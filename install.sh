#!/usr/bin/env bash
# Build and install veyl. Run as your own account; it calls sudo itself.
#
#   ./install.sh              install or update
#   ./install.sh --uninstall  remove everything

set -euo pipefail

# --- configuration ----------------------------------------------------------

LISTEN=127.0.0.1
SOCKS_PORT=1080   # system SOCKS setting
HTTP_PORT=1085    # HTTPS_PROXY; both ports speak SOCKS and CONNECT

# Hosts never to desync (with subdomains).
DIRECT_HOSTS=()

# Desync strategies in order; empty uses veyld's defaults.
STRATEGIES=()

NO_PROXY_LIST="localhost,.localhost,.local,.test,.internal,.lan,.home.arpa,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"

# Merged into each service's proxy bypass list when SOCKS is turned on.
BYPASS=("*.local" "169.254/16" "10/8" "172.16/12" "192.168/16" "*.test" "*.localhost" "localhost" "127.0.0.1" "::1")

# --- paths ------------------------------------------------------------------

LIBEXEC=/usr/local/libexec/veyl
BINDIR=/usr/local/bin
DAEMONS=/Library/LaunchDaemons
AGENTS="$HOME/Library/LaunchAgents"
STATE=/Users/Shared/.veyl-enabled
LOG=/var/log/veyld.log

SYSTEM_LABELS=(local.veyld local.dns-guard local.veyl-proxy)
AGENT_LABEL=local.veyl-env

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
uid=$(id -u)

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
note() { printf '    %s\n' "$1"; }
die()  { printf '\n\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# bootout returns before the job is gone, and bootstrapping over it fails.
wait_gone() { # wait_gone <sudo|""> <domain/label>
  local i
  for i in $(seq 1 50); do
    if [ -n "$1" ]; then sudo launchctl print "$2" >/dev/null 2>&1 || return 0
    else launchctl print "$2" >/dev/null 2>&1 || return 0; fi
    sleep 0.2
  done
  return 1
}

unload_system() { sudo launchctl bootout "system/$1" 2>/dev/null || true; wait_gone sudo "system/$1" || note "warning: $1 is still loaded"; }
unload_agent()  { launchctl bootout "gui/$uid/$1" 2>/dev/null || true; wait_gone "" "gui/$uid/$1" || note "warning: $1 is still loaded"; }

services() { /usr/sbin/networksetup -listallnetworkservices 2>/dev/null | sed -e 1d -e '/^\*/d'; }

# --- uninstall --------------------------------------------------------------

if [ "${1:-}" = "--uninstall" ]; then
  say "Removing veyl"
  sudo -v
  unload_agent "$AGENT_LABEL"; rm -f "$AGENTS/$AGENT_LABEL.plist"
  for v in HTTPS_PROXY https_proxy NO_PROXY no_proxy; do launchctl unsetenv "$v" || true; done
  services | while IFS= read -r svc; do
    sudo /usr/sbin/networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
  done
  for l in "${SYSTEM_LABELS[@]}"; do unload_system "$l"; sudo rm -f "$DAEMONS/$l.plist"; done
  services | while IFS= read -r svc; do
    if [ "$(/usr/sbin/networksetup -getdnsservers "$svc" 2>/dev/null | head -1)" = 127.0.0.1 ]; then
      sudo /usr/sbin/networksetup -setdnsservers "$svc" Empty
      note "DNS for $svc back to DHCP"
    fi
  done
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null || true
  sudo rm -rf "$LIBEXEC" "$BINDIR/veyl"
  note "Done."
  exit 0
fi

[ "$(uname -s)" = Darwin ] || die "macOS only."
[ "$uid" -ne 0 ] || die "Run as your own account, not with sudo."

CARGO=$(command -v cargo || true)
[ -n "$CARGO" ] || [ ! -x "$HOME/.cargo/bin/cargo" ] || CARGO="$HOME/.cargo/bin/cargo"
[ -n "$CARGO" ] || die "cargo is missing; install Rust from https://rustup.rs"

# --- build ------------------------------------------------------------------

say "Building veyld"
(cd "$here/daemon" && "$CARGO" build --release --locked) || die "veyld build failed"
VEYLD_BIN="$here/daemon/target/release/veyld"
note "$("$VEYLD_BIN" version)"

sudo -v || die "This account has to be an administrator."

# --- files ------------------------------------------------------------------

say "Installing into $LIBEXEC"
sudo install -d -m 755 "$LIBEXEC"
sudo install -m 755 "$VEYLD_BIN" "$LIBEXEC/veyld.new"
sudo mv -f "$LIBEXEC/veyld.new" "$LIBEXEC/veyld"
sudo install -m 755 "$here/src/dns-guard.sh" "$LIBEXEC/dns-guard"

sudo tee "$LIBEXEC/veyl-proxy-toggle" >/dev/null <<TOGGLE
#!/bin/bash
set -f # bypass entries contain '*'
NS=/usr/sbin/networksetup
want=0
if [ -r $STATE ]; then
  case "\$(cat $STATE)" in
    1 | on | true | yes) want=1 ;;
  esac
fi
bypass=($(printf '%q ' "${BYPASS[@]}"))
\$NS -listallnetworkservices 2>/dev/null | /usr/bin/sed -e 1d -e '/^\*/d' | while IFS= read -r svc; do
  info=\$(\$NS -getsocksfirewallproxy "\$svc" 2>/dev/null) || continue
  cur=\$(/usr/bin/awk '/^Enabled:/ { print \$2 }' <<<"\$info")
  server=\$(/usr/bin/awk '/^Server:/ { print \$2 }' <<<"\$info")
  port=\$(/usr/bin/awk '/^Port:/ { print \$2 }' <<<"\$info")
  if [ "\$want" = 1 ]; then
    if [ "\$server" != $LISTEN ] || [ "\$port" != $SOCKS_PORT ]; then
      \$NS -setsocksfirewallproxy "\$svc" $LISTEN $SOCKS_PORT # also enables it
      cur=Yes
    fi
    [ "\$cur" = Yes ] || \$NS -setsocksfirewallproxystate "\$svc" on
    have=\$(\$NS -getproxybypassdomains "\$svc" 2>/dev/null | /usr/bin/grep -v "There aren't any")
    missing=0
    for b in "\${bypass[@]}"; do /usr/bin/grep -qxF -- "\$b" <<<"\$have" || missing=1; done
    if [ "\$missing" = 1 ]; then
      \$NS -setproxybypassdomains "\$svc" \$( { printf '%s\n' "\$have"; printf '%s\n' "\${bypass[@]}"; } | /usr/bin/awk 'NF && !seen[\$0]++')
    fi
  elif [ "\$cur" = Yes ]; then
    \$NS -setsocksfirewallproxystate "\$svc" off
  fi
done
TOGGLE
sudo chmod 755 "$LIBEXEC/veyl-proxy-toggle"

sudo tee "$BINDIR/veyl" >/dev/null <<CLI
#!/bin/bash
state=$STATE
read_state() { cat "\$state" 2>/dev/null || echo 0; }

case "\${1:-status}" in
  on) echo 1 > "\$state" ;;
  off) echo 0 > "\$state" ;;
  toggle) if [ "\$(read_state)" = 1 ]; then echo 0 > "\$state"; else echo 1 > "\$state"; fi ;;
  status) ;;
  stats) exec /usr/bin/curl -sf --noproxy '*' -m 3 http://$LISTEN:$HTTP_PORT/status ;;
  *) echo "usage: veyl [on|off|toggle|status|stats]" >&2; exit 2 ;;
esac

if [ "\$(read_state)" = 1 ]; then want=on; else want=off; fi
echo "veyl: \$want"
/usr/sbin/networksetup -listallnetworkservices 2>/dev/null | /usr/bin/sed -e 1d -e '/^\*/d' | while IFS= read -r svc; do
  printf '  %-26s SOCKS %-4s DNS %s\n' "\$svc" \\
    "\$(/usr/sbin/networksetup -getsocksfirewallproxy "\$svc" 2>/dev/null | /usr/bin/awk '/^Enabled:/ { print \$2 }')" \\
    "\$(/usr/sbin/networksetup -getdnsservers "\$svc" 2>/dev/null | head -1 | sed 's/^There.*/(DHCP)/')"
done
if /usr/bin/curl -sf --noproxy '*' -m 2 -o /dev/null http://$LISTEN:$HTTP_PORT/status; then
  echo "  veyld answering"
else
  echo "  veyld NOT answering on $LISTEN:$HTTP_PORT"
fi
CLI
sudo chmod 755 "$BINDIR/veyl"

[ -e "$STATE" ] || { sudo touch "$STATE"; sudo chmod 666 "$STATE"; }
sudo touch "$LOG"; sudo chown nobody:nobody "$LOG"; sudo chmod 644 "$LOG"

# --- launchd ----------------------------------------------------------------

say "Writing launchd jobs"

plist_open() { printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n'; }
plist_close() { printf '</dict>\n</plist>\n'; }
kv_str()  { printf '\t<key>%s</key>\n\t<string>%s</string>\n' "$1" "$2"; }
kv_bool() { printf '\t<key>%s</key>\n\t<%s/>\n' "$1" "$2"; }
kv_int()  { printf '\t<key>%s</key>\n\t<integer>%s</integer>\n' "$1" "$2"; }
kv_args() { printf '\t<key>ProgramArguments</key>\n\t<array>\n'; for a in "$@"; do printf '\t\t<string>%s</string>\n' "$a"; done; printf '\t</array>\n'; }
sock() { # sock <stream|dgram> <port>
  printf '\t\t\t<dict>\n\t\t\t\t<key>SockNodeName</key><string>%s</string>\n\t\t\t\t<key>SockServiceName</key><string>%s</string>\n\t\t\t\t<key>SockType</key><string>%s</string>\n\t\t\t\t<key>SockFamily</key><string>IPv4</string>\n\t\t\t</dict>\n' "$LISTEN" "$2" "$1"
}

veyld_args=("$LIBEXEC/veyld" serve)
if [ ${#DIRECT_HOSTS[@]} -gt 0 ]; then veyld_args+=(--direct "$(IFS=,; echo "${DIRECT_HOSTS[*]}")"); fi
for s in "${STRATEGIES[@]}"; do veyld_args+=(--strategy "$s"); done

{
  plist_open
  kv_str  Label local.veyld
  kv_args "${veyld_args[@]}"
  # launchd owns the sockets, so veyld needs no root and restarts refuse nothing.
  printf '\t<key>Sockets</key>\n\t<dict>\n'
  printf '\t\t<key>dns-udp</key>\n\t\t<array>\n'; sock dgram 53; printf '\t\t</array>\n'
  printf '\t\t<key>dns-tcp</key>\n\t\t<array>\n'; sock stream 53; printf '\t\t</array>\n'
  printf '\t\t<key>proxy</key>\n\t\t<array>\n'; sock stream "$SOCKS_PORT"; sock stream "$HTTP_PORT"; printf '\t\t</array>\n'
  printf '\t</dict>\n'
  kv_str  UserName nobody
  kv_str  GroupName nobody
  kv_bool RunAtLoad true
  kv_bool KeepAlive true
  kv_int  ThrottleInterval 1
  kv_str  ProcessType Interactive # Background is deprioritised under load
  kv_str  StandardOutPath "$LOG"
  kv_str  StandardErrorPath "$LOG"
  plist_close
} | sudo tee "$DAEMONS/local.veyld.plist" >/dev/null

{
  plist_open
  kv_str  Label local.dns-guard
  kv_args "$LIBEXEC/dns-guard"
  kv_bool RunAtLoad true
  kv_int  StartInterval 10
  kv_str  ProcessType Background
  kv_str  StandardErrorPath /var/log/dns-guard.err.log
  plist_close
} | sudo tee "$DAEMONS/local.dns-guard.plist" >/dev/null

{
  plist_open
  kv_str  Label local.veyl-proxy
  kv_args "$LIBEXEC/veyl-proxy-toggle"
  kv_bool RunAtLoad true
  kv_int  StartInterval 60
  kv_str  ProcessType Background
  printf '\t<key>WatchPaths</key>\n\t<array>\n\t\t<string>%s</string>\n\t</array>\n' "$STATE"
  kv_str  StandardErrorPath /var/log/veyl-proxy.log
  plist_close
} | sudo tee "$DAEMONS/local.veyl-proxy.plist" >/dev/null

mkdir -p "$AGENTS"
{
  plist_open
  kv_str  Label "$AGENT_LABEL"
  kv_args "$LIBEXEC/veyld" env-agent --state "$STATE" --url "http://$LISTEN:$HTTP_PORT" --no-proxy "$NO_PROXY_LIST"
  kv_bool RunAtLoad true
  kv_bool KeepAlive true
  kv_str  ProcessType Background
  kv_str  StandardErrorPath "$HOME/Library/Logs/veyl-env.log"
  plist_close
} > "$AGENTS/$AGENT_LABEL.plist"

for f in "${SYSTEM_LABELS[@]}"; do
  sudo plutil -lint "$DAEMONS/$f.plist" >/dev/null || die "$f.plist is malformed"
  sudo chown root:wheel "$DAEMONS/$f.plist"
  sudo chmod 644 "$DAEMONS/$f.plist"
done
plutil -lint "$AGENTS/$AGENT_LABEL.plist" >/dev/null || die "$AGENT_LABEL.plist is malformed"

# --- load -------------------------------------------------------------------

say "Loading"
for l in "${SYSTEM_LABELS[@]}"; do
  unload_system "$l"
  sudo launchctl bootstrap system "$DAEMONS/$l.plist" || die "could not load $l"
  note "loaded $l"
done
unload_agent "$AGENT_LABEL"
launchctl bootstrap "gui/$uid" "$AGENTS/$AGENT_LABEL.plist" || die "could not load $AGENT_LABEL"
note "loaded $AGENT_LABEL"

# --- verify -----------------------------------------------------------------

say "Checking"
for _ in $(seq 1 25); do
  /usr/bin/dig @127.0.0.1 +time=2 +tries=1 +short example.com A 2>/dev/null | grep -q . && break
  sleep 0.2
done
if /usr/bin/dig @127.0.0.1 +time=3 +tries=1 +short example.com A | grep -q .; then note "DNS answers"; else note "warning: DNS is not answering; see $LOG"; fi
if /usr/bin/curl -sf --noproxy '*' -m 5 -o /dev/null "http://$LISTEN:$HTTP_PORT/status"; then note "proxy answers"; else note "warning: proxy is not answering; see $LOG"; fi

say "Done"
note "veyl on | off | toggle | status | stats"
