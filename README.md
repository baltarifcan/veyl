# veyl

DPI and DNS bypass, packaged as a nix-darwin module and a home-manager
module. For networks that block by SNI and sinkhole DNS at the resolver.

Two independent problems, deliberately kept separate:

1. **DNS is sinkholed.** Blocked domains resolve to the ISP's block page, so a
   name fails before any TLS is attempted. Fixed by resolving over HTTPS.
2. **TLS is reset by SNI.** Even with a correct IP, the DPI sends an RST when it
   sees a blocked SNI in the ClientHello. Fixed by desyncing the handshake.

You need both. Fixing only DNS gets you a correct IP and a reset connection.

## There are no lists to maintain

ciadpi runs in auto-detect mode (`-A`). Parameters before the first `-A` are the
first attempt, and there are none — so **every connection is tried undesynced**,
and a desync is applied only to connections the DPI actually kills:

```
slack.com    group=0                                     (untouched, stops there)
discord.com  group=0 -> recv: Connection reset by peer
             group=1 -> split: pos=0-2, m: DESYNC_OOB    (auto-fixed)
```

Blocked sites start working by themselves; unblocked sites are never touched.
This replaces a hostlist that had to be maintained in *both* directions: add
what was blocked, and exclude whatever the bypass broke.

`strategies` is a cascade of four different mechanisms rather than one, because
this DPI adapts and clamps a single strategy within minutes. When one stops
working the next is tried automatically.

## Install

```nix
# flake.nix
{
  inputs.veyl.url = "github:baltarifcan/veyl";

  outputs = { nix-darwin, home-manager, veyl, ... }: {
    darwinConfigurations.mac = nix-darwin.lib.darwinSystem {
      modules = [
        veyl.darwinModules.default
        {
          networking.knownNetworkServices = [ "Wi-Fi" ];
          services.veyl.enable = true;
        }
        home-manager.darwinModules.home-manager
        {
          home-manager.users.baltarifcan = {
            imports = [ veyl.homeManagerModules.default ];
            services.veyl.enable = true;   # connect-bridge only
          };
        }
      ];
    };
  };
}
```

`networking.knownNetworkServices` is required — the SOCKS and DNS settings are
per network service, and which one is primary depends on whether a dock is
plugged in.

## What runs where

| | Component | Why there |
|---|---|---|
| **nix-darwin** | `ciadpi` (`local.ciadpi`) | SOCKS5 on 127.0.0.1:1080. System-wide setting, so a system daemon. |
| | `doh-proxy` (`local.doh-proxy`) | Binds :53, must be root. Dials Cloudflare by IP with SNI `cloudflare-dns.com`, so it needs no DNS to bootstrap. |
| | `dns-guard` (`local.dns-guard`) | Fails over to plaintext resolvers when the DoH proxy is listening but not answering, and reverts itself. |
| | SOCKS + DNS settings | `networksetup`, root, per network service. |
| **home-manager** | `connect-bridge` (`local.connect-bridge`) | Publishes `HTTPS_PROXY` with `launchctl setenv`, which is per-user and does not survive a reboot. |
| **Homebrew** | *SwiftBar, optionally* | Only to render the menu-bar toggle. Nothing depends on it. |

Labels are stable on purpose, so existing logs and habits still apply.

## Toggling

The bypass is on or off according to a one-byte flag file, applied by a root
daemon (`local.veyl-proxy`) that watches it. ciadpi itself keeps running
either way — it is bound to loopback and nothing reaches it while the SOCKS
setting is off — so the setting can never outlive its listener.

```sh
veyl            # status
veyl on
veyl off
veyl toggle
```

No sudo: the flag file is the only thing you write, and the daemon owns the
privileged half. `extras/veyl.5s.sh` is a SwiftBar plugin that does the same
thing from the menu bar, if you want the click back.

Set `services.veyl.proxy.mode` to `always` to pin it on, or `manual` to have
the module not touch the setting at all.

There is no hostlist and no exclusion list on disk. The one remaining escape
hatch, `services.veyl.directHosts`, is empty by default and lives in your Nix
config rather than a dotfile — auto-detect means an unblocked host is never
desynced, so there is normally nothing to exempt.

## Debugging

```sh
sudo launchctl print system/local.ciadpi | head -20      # is it loaded, what args
tail -f /var/log/ciadpi.log /var/log/dns-guard.log
dig @127.0.0.1 example.com +short                        # DoH proxy answering?
networksetup -getsocksfirewallproxy "Wi-Fi"
```

Test a strategy without disturbing the running proxy — note the alternate port,
and stop it by PID:

```sh
ciadpi -i 127.0.0.1 -p 10800 -c 8192 -A torst,ssl_err,redirect -o 2 &
curl -s -o /dev/null -w '%{http_code}\n' --socks5-hostname 127.0.0.1:10800 https://discord.com/
```

Add `-x 1` to see which group each connection lands in — that is how you tell a
DPI block from a local problem.

**A site that "just got blocked" is often not blocked.** At `maxConnections`,
ciadpi answers new connections with a TCP reset while established ones keep
working, which is indistinguishable from the DPI. Compare a direct request
against one through the proxy before believing it.

**Panic button:**

```sh
sudo networksetup -setsocksfirewallproxystate "Wi-Fi" off
```

## Deliberately not here

- **The transparent PF/tpws design.** It funnels every outbound 443 through one
  process, so every failure is machine-wide and presents as "the internet is
  broken". It also wedges on recent macOS.
- **The menu-bar app.** It had to own ciadpi's lifecycle to toggle anything,
  which is why the setting could outlive the listener, and its arguments lived
  in `defaults` rather than in this config — which is how `-c` and `-i` went
  missing. The toggle survives it; the app does not.
- **The boot-reset and SOCKS guard agents.** They existed because ciadpi was
  started by an app rather than launchd, so shutting down while connected left
  the SOCKS setting pointing at a dead port and the machine looked offline. A
  `KeepAlive` daemon makes that state impossible.
- **A per-IP strategy cache (`-u`).** It would apply a cached desync to any
  domain sharing a CDN address with a blocked one.

## Credits

The desync engine is [byedpi](https://github.com/hufrea/byedpi) by hufrea, MIT
licensed (© 2024 hufrea). It is fetched and built from source by `pkgs/byedpi.nix`
rather than vendored here.

`doh-proxy`, `dns-guard` and `connect-bridge` are original, as is everything
under `modules/` and `pkgs/`. This repo is MIT licensed.
