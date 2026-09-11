#!/bin/sh
# dns-guard: keep the machine resolving when the DoH proxy stops answering.
#
# THE PROBLEM
# -----------
# System DNS points at 127.0.0.1:53 (local.doh-proxy). socks-guard already
# covers the SOCKS half of this setup, where a stranded setting makes the
# machine look offline. The DNS half had no equivalent, and it is strictly
# worse: stranded SOCKS breaks proxy-aware apps, dead DNS breaks everything.
#
# The failure is not "the daemon died" -- launchd's KeepAlive handles that, and
# a port-liveness check would pass anyway. The failure is that the proxy is
# LISTENING BUT NOT ANSWERING: a link flap trips both upstream circuit
# breakers, in-flight queries pile up against MAX_INFLIGHT, clients retry, and
# the retries sustain the collapse long after the link comes back. Observed
# 2026-08-22: a few-second ISP blip produced minutes of total DNS failure that
# only cleared when the resolver was switched off 127.0.0.1 by hand.
#
# WHAT THIS DOES
# --------------
# Probes for a real ANSWER (not just a listener) every INTERVAL seconds. After
# FAIL_THRESHOLD consecutive failures it:
#   1. switches every enabled service to plaintext fallback resolvers, so the
#      machine resolves again within ~30s instead of waiting for a human, and
#   2. kickstarts local.doh-proxy, which drops the wedged connection pool,
#      tripped breakers and query backlog that it cannot escape on its own.
# When the proxy answers again for OK_THRESHOLD consecutive probes, DNS is put
# back to 127.0.0.1 so the DoH path (and its sinkhole immunity) is restored
# without intervention.
#
# The fallback is PLAINTEXT and therefore sinkhole-vulnerable -- this ISP
# poisons at its own resolver (a blocked name -> the block page, via the router).
# That is an accepted, logged, temporary trade: degraded DNS beats no DNS, and
# it self-reverts. It is deliberately never left in place silently.
#
# Runs as root: unlike the SOCKS keys, -setdnsservers requires it.

set -u

PROBE_PORT=53
PROBE_ADDR=127.0.0.1
FAIL_THRESHOLD=3          # ~30s of failure before we touch the resolver
OK_THRESHOLD=2            # consecutive good probes before restoring DoH
FALLBACK="1.1.1.1 1.0.0.1 9.9.9.9"
PRIMARY=127.0.0.1

STATE_DIR=/Library/Application\ Support/dns-guard
LOG=/var/log/dns-guard.log

NETWORKSETUP=/usr/sbin/networksetup
DIG=/usr/bin/dig
LAUNCHCTL=/bin/launchctl
DSCACHEUTIL=/usr/bin/dscacheutil
KILLALL=/usr/bin/killall
SED=/usr/bin/sed

MODE="interval"
[ "${1:-}" = "--boot" ] && MODE="boot"

mkdir -p "$STATE_DIR" 2>/dev/null || true
FAILS_F="$STATE_DIR/fails"
OKS_F="$STATE_DIR/oks"
OVER_F="$STATE_DIR/failed_over"

log() {
    echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') [$MODE] $1" >> "$LOG"
}

counter_get() { [ -f "$1" ] && cat "$1" 2>/dev/null || echo 0; }
counter_set() { echo "$2" > "$1" 2>/dev/null || true; }

# Every ENABLED network service. networksetup prefixes disabled ones with '*'
# and prints a header line we drop. Same sweep as socks-guard: which service is
# primary depends on whether a dock or ethernet adapter is plugged in.
services() {
    "$NETWORKSETUP" -listallnetworkservices 2>/dev/null \
        | "$SED" -e '1d' -e '/^\*/d'
}

# A real resolution, not a port check. A random label forces a cache miss so
# this exercises the full upstream path -- a wedged proxy with a warm cache
# would otherwise look healthy. NXDOMAIN counts as success: it proves the
# upstream answered. Only a timeout or SERVFAIL is a failure.
probe() {
    label="p$$$(/bin/date '+%s')"
    out="$("$DIG" +time=3 +tries=1 +noall +comments \
           "@$PROBE_ADDR" "$label.example.com" A 2>/dev/null)" || return 1
    case "$out" in
        *"status: NOERROR"*|*"status: NXDOMAIN"*) return 0 ;;
        *) return 1 ;;
    esac
}

flush() {
    "$DSCACHEUTIL" -flushcache 2>/dev/null || true
    "$KILLALL" -HUP mDNSResponder 2>/dev/null || true
}

fail_over() {
    services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        cur="$("$NETWORKSETUP" -getdnsservers "$svc" 2>/dev/null | head -1)"
        # Only take over a service we own -- never stomp a resolver the user
        # or a VPN deliberately set to something else.
        [ "$cur" = "$PRIMARY" ] || continue
        # shellcheck disable=SC2086
        "$NETWORKSETUP" -setdnsservers "$svc" $FALLBACK
        log "FAILOVER '$svc': $PRIMARY -> $FALLBACK (proxy listening but not answering)"
    done
    flush
    counter_set "$OVER_F" 1
    log "kickstarting local.doh-proxy to clear wedged pool/breakers/backlog"
    "$LAUNCHCTL" kickstart -k system/local.doh-proxy 2>/dev/null || true
}

# macOS reports a service with no explicit resolver as a human sentence --
# "There aren't any DNS Servers set on Wi-Fi." -- meaning it is using whatever
# DHCP handed it, which here is the ISP resolver that poisons. That is a THIRD
# state, and this guard originally knew only two: PRIMARY and FALLBACK. A
# service sitting unset was skipped by fail_over (not PRIMARY, so "not ours")
# AND by restore (not FALLBACK, so "nothing to put back"), so the guard went
# permanently silent while every blocked domain resolved through the sinkhole.
# Observed 2026-08-25: DNS unset on all three services, failed_over=0, no log
# line since 18:11, a blocked name -> the block page while the DoH proxy sat
# healthy and unused.
#
# Unset counts as ours to claim. It is not a resolver anyone deliberately
# chose -- it is the default macOS reverts to after a network reset -- and on
# this machine it is precisely the dangerous state. An explicitly-set foreign
# resolver (a VPN's, say) matches neither branch below and is still left alone,
# which is the "never stomp someone else's resolver" rule fail_over intended.
is_unset() {
    case "$1" in
        *"aren't any DNS Servers set"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Pin every service we own back to the DoH proxy. Covers both "coming back from
# fallback" and "found sitting unset": the corrective write is identical, only
# the reason differs. Idempotent -- a service already on PRIMARY is untouched,
# so this is safe to run on every healthy pass.
claim_primary() {
    reason="$1"
    services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        cur="$("$NETWORKSETUP" -getdnsservers "$svc" 2>/dev/null | head -1)"
        [ "$cur" = "$PRIMARY" ] && continue
        if is_unset "$cur"; then
            what="unset"
        else
            case " $FALLBACK " in
                *" $cur "*) what="fallback" ;;
                *) continue ;;
            esac
        fi
        "$NETWORKSETUP" -setdnsservers "$svc" "$PRIMARY"
        log "CLAIM '$svc': $what -> $PRIMARY ($reason)"
    done
    flush
}

restore() {
    claim_primary "DoH answering again"
    counter_set "$OVER_F" 0
}

# ---------------------------------------------------------------------------

over="$(counter_get "$OVER_F")"

if probe; then
    counter_set "$FAILS_F" 0
    if [ "$over" = 1 ]; then
        oks=$(( $(counter_get "$OKS_F") + 1 ))
        counter_set "$OKS_F" "$oks"
        if [ "$oks" -ge "$OK_THRESHOLD" ]; then
            counter_set "$OKS_F" 0
            restore
        fi
    else
        # Standing reconcile. The probe just proved the proxy answers, so any
        # service NOT pointed at it has drifted -- a network reset, a dock
        # replug, an OS update -- and is silently resolving through the ISP
        # sinkhole. Claiming it here is what makes the guard self-healing for
        # states it did not create itself, rather than only undoing its own
        # failovers. Costs one -getdnsservers per service per interval.
        claim_primary "drifted while proxy healthy"
    fi
    exit 0
fi

counter_set "$OKS_F" 0

# Already on fallback: nothing more to switch. Stay quiet -- the probe above
# keeps watching 127.0.0.1 so recovery is still detected.
[ "$over" = 1 ] && exit 0

fails=$(( $(counter_get "$FAILS_F") + 1 ))
counter_set "$FAILS_F" "$fails"

if [ "$fails" -ge "$FAIL_THRESHOLD" ]; then
    counter_set "$FAILS_F" 0
    log "$fails consecutive failed probes against $PROBE_ADDR:$PROBE_PORT"
    fail_over
fi

exit 0
