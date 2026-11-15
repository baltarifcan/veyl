# veyl

DNS and DPI bypass for macOS, for networks that sinkhole DNS at the resolver
and reset TLS connections by SNI. One native daemon, `veyld` (Rust, in
`daemon/`), handles both.

## How it works

**DNS.** `veyld` answers on `127.0.0.1:53` and resolves over DNS-over-HTTPS
(HTTP/2) to Cloudflare and Google by IP. Answers are cached, refreshed before
they expire, and served stale while refreshing. A slow upstream is hedged
with another provider. If DoH is unreachable, plaintext resolvers are used
without caching. Local names (`.lan`, `.home.arpa`, the DHCP search domain,
private reverse zones) go to the network's own resolver.

**DPI.** `veyld` is a SOCKS5/SOCKS4/HTTP CONNECT proxy on `127.0.0.1:1080` and
`:1085`. Each connection is tried plainly first. If the DPI interferes (reset,
close, or no ServerHello), it is retried with the next desync strategy, and
what works is remembered per hostname:

```
proxy: discord.com needs split:1 (none: reset)
```

| strategy | effect |
|---|---|
| `split:N` | first N bytes in their own TCP segment |
| `tlsrec:sni+1` | ClientHello split into two TLS records at the SNI |
| `oob:N` | an extra urgent byte the server strips |
| `disorder:N` | first N bytes sent with TTL 1, arriving last |

## Install

```sh
./install.sh             # needs Rust (https://rustup.rs); calls sudo itself
./install.sh --uninstall
```

Ports, hosts never to desync, the strategy list and `NO_PROXY` are the
constants at the top of `install.sh`.

| launchd job | role |
|---|---|
| `local.veyld` | the daemon; runs as `nobody` on launchd-held sockets |
| `local.dns-guard` | switches to plaintext DNS if veyld stops answering, and reclaims services that drift to DHCP DNS |
| `local.veyl-proxy` | applies the on/off flag to every network service's SOCKS setting |
| `local.veyl-env` (user) | publishes `HTTPS_PROXY` while veyl is on, for CLI tools and apps that ignore the SOCKS setting |

## Use

```sh
veyl              # status
veyl on | off | toggle
veyl stats        # resolver and proxy counters, learned strategies
```

On: system SOCKS and `HTTPS_PROXY` point at veyld. Off: neither does. DNS goes
through veyld either way. `extras/veyl.5s.sh` is a SwiftBar toggle.

## Debugging

```sh
tail -f /var/log/veyld.log /var/log/dns-guard.log
daemon/tests/smoke.sh     # end-to-end test on spare ports
cd daemon && cargo test
```

A test instance with every connection logged:

```sh
daemon/target/release/veyld serve --dns 127.0.0.1:10053 \
  --proxy 127.0.0.1:11080 --proxy 127.0.0.1:11085 --verbose
```

Panic button: `veyl off; sudo networksetup -setdnsservers Wi-Fi Empty`.

## Credits

The desync techniques come from [byedpi](https://github.com/hufrea/byedpi)
(MIT, © 2024 hufrea). MIT licensed.
