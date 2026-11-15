#!/usr/bin/env bash
# Smoke test on spare ports (DNS :10053, proxy :11080/:11085), leaving any
# running install alone:  daemon/tests/smoke.sh [path/to/veyld]

set -u
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VEYLD=${1:-$here/../target/release/veyld}
[ -x "$VEYLD" ] || { echo "build first: (cd daemon && cargo build --release)"; exit 2; }
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy NO_PROXY no_proxy

log=$(mktemp -t veyld-smoke)
"$VEYLD" serve --dns 127.0.0.1:10053 --proxy 127.0.0.1:11080 --proxy 127.0.0.1:11085 >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null' EXIT
for _ in $(seq 1 50); do grep -q ready "$log" && break; kill -0 $pid 2>/dev/null || break; sleep 0.2; done
if ! kill -0 $pid 2>/dev/null || ! grep -q ready "$log"; then
  echo "veyld did not start:"; sed 's/^/  /' "$log"; exit 1
fi

pass=0 fail=0
check() { # check <name> <command...>
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else printf '  FAIL  %s\n' "$name"; fail=$((fail + 1)); fi
}

echo "veyld smoke test ($("$VEYLD" version))"
check "DNS over UDP resolves"  sh -c 'dig @127.0.0.1 -p 10053 +short +time=5 example.com A | grep -q .'
check "DNS over TCP resolves"  sh -c 'dig @127.0.0.1 -p 10053 +tcp +short +time=5 example.com A | grep -q .'
check "NXDOMAIN is passed on"  sh -c 'dig @127.0.0.1 -p 10053 +time=5 nx-$RANDOM-$RANDOM.invalid | grep -q NXDOMAIN'
check "cached answer is instant" sh -c "[ \"\$(dig @127.0.0.1 -p 10053 +time=5 example.com A | awk '/Query time/ { print \$4 }')\" -le 2 ]"
check "SOCKS5 to an open site"   sh -c '[ "$(curl -s -o /dev/null -m 15 -w "%{http_code}" --socks5-hostname 127.0.0.1:11080 https://www.google.com/generate_204)" = 204 ]'
check "CONNECT to an open site"  sh -c '[ "$(curl -s -o /dev/null -m 15 -w "%{http_code}" --proxy http://127.0.0.1:11085 https://www.google.com/generate_204)" = 204 ]'
check "SOCKS4a works"            sh -c '[ "$(curl -s -o /dev/null -m 15 -w "%{http_code}" --socks4a 127.0.0.1:11080 https://www.google.com/generate_204)" = 204 ]'
check "status page"              sh -c 'curl -sf -m 5 http://127.0.0.1:11085/status | grep -q "^dns"'

direct=$(curl -s -o /dev/null -m 10 -w '%{http_code}' https://discord.com/)
via=$(curl -s -o /dev/null -m 15 -w '%{http_code}' --proxy http://127.0.0.1:11085 https://discord.com/)
if [ "$direct" = 000 ]; then
  check "blocked discord.com gets through" [ "$via" != 000 ]
else
  printf '  skip  discord.com is not blocked on this network (direct %s, proxied %s)\n' "$direct" "$via"
fi

echo "$pass passed, $fail failed"
grep -E "needs|unreachable|fatal" "$log" | sed 's/^/  log: /'
rm -f "$log"
[ "$fail" = 0 ]
