#!/bin/sh
# dns-guard: keep the machine resolving if veyld stops answering.
#
# Every INTERVAL (launchd) it asks 127.0.0.1 for a random name. After
# FAIL_THRESHOLD failures it points every service we own at plaintext FALLBACK
# resolvers and restarts veyld; after OK_THRESHOLD successes it points them
# back. While healthy, it also reclaims services that drifted to DHCP DNS,
# which here is the resolver that sinkholes. Runs as root.

set -u

PROBE_ADDR=127.0.0.1
FAIL_THRESHOLD=3
OK_THRESHOLD=2
FALLBACK="1.1.1.1 1.0.0.1 9.9.9.9"
PRIMARY=127.0.0.1

STATE_DIR="/Library/Application Support/dns-guard"
LOG=/var/log/dns-guard.log

NETWORKSETUP=/usr/sbin/networksetup
DIG=/usr/bin/dig

mkdir -p "$STATE_DIR" 2>/dev/null || true
FAILS_F="$STATE_DIR/fails"
OKS_F="$STATE_DIR/oks"
OVER_F="$STATE_DIR/failed_over"

log() { echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"; }
counter_get() { [ -f "$1" ] && cat "$1" 2>/dev/null || echo 0; }
counter_set() { echo "$2" > "$1" 2>/dev/null || true; }

services() { "$NETWORKSETUP" -listallnetworkservices 2>/dev/null | /usr/bin/sed -e '1d' -e '/^\*/d'; }

# A cache miss, so the upstream path is exercised. NXDOMAIN counts as success.
probe() {
    out="$("$DIG" +time=3 +tries=1 +noall +comments "@$PROBE_ADDR" "p$$$(/bin/date '+%s').example.com" A 2>/dev/null)" || return 1
    case "$out" in
        *"status: NOERROR"*|*"status: NXDOMAIN"*) return 0 ;;
        *) return 1 ;;
    esac
}

flush() {
    /usr/bin/dscacheutil -flushcache 2>/dev/null || true
    /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
}

fail_over() {
    services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        # Only services we own; never a resolver someone else set (a VPN's).
        [ "$("$NETWORKSETUP" -getdnsservers "$svc" 2>/dev/null | head -1)" = "$PRIMARY" ] || continue
        # shellcheck disable=SC2086
        "$NETWORKSETUP" -setdnsservers "$svc" $FALLBACK
        log "FAILOVER '$svc': $PRIMARY -> $FALLBACK"
    done
    flush
    counter_set "$OVER_F" 1
    log "restarting local.veyld"
    /bin/launchctl kickstart -k system/local.veyld 2>/dev/null || true
}

# Point services that are on FALLBACK or unset (DHCP) back at PRIMARY.
claim_primary() {
    reason="$1"
    services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        cur="$("$NETWORKSETUP" -getdnsservers "$svc" 2>/dev/null | head -1)"
        [ "$cur" = "$PRIMARY" ] && continue
        case "$cur" in
            *"aren't any DNS Servers set"*) what="unset" ;;
            *) case " $FALLBACK " in *" $cur "*) what="fallback" ;; *) continue ;; esac ;;
        esac
        "$NETWORKSETUP" -setdnsservers "$svc" "$PRIMARY"
        log "CLAIM '$svc': $what -> $PRIMARY ($reason)"
    done
    flush
}

over="$(counter_get "$OVER_F")"

if probe; then
    counter_set "$FAILS_F" 0
    if [ "$over" = 1 ]; then
        oks=$(( $(counter_get "$OKS_F") + 1 ))
        counter_set "$OKS_F" "$oks"
        if [ "$oks" -ge "$OK_THRESHOLD" ]; then
            counter_set "$OKS_F" 0
            claim_primary "veyld answering again"
            counter_set "$OVER_F" 0
        fi
    else
        claim_primary "drifted while veyld healthy"
    fi
    exit 0
fi

counter_set "$OKS_F" 0
[ "$over" = 1 ] && exit 0

fails=$(( $(counter_get "$FAILS_F") + 1 ))
counter_set "$FAILS_F" "$fails"
if [ "$fails" -ge "$FAIL_THRESHOLD" ]; then
    counter_set "$FAILS_F" 0
    log "$fails failed probes against $PROBE_ADDR"
    fail_over
fi
