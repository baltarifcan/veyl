{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.veyl;
  scripts = pkgs.callPackage ../pkgs/scripts.nix { };

  splitArgs = s: lib.filter (x: x != "") (lib.splitString " " s);

  # Parameters BEFORE the first -A are the first attempt. There are none, so
  # every connection is tried clean and a desync is applied only to connections
  # the DPI actually kills. This is what removes the hostlist.
  ciadpiArgs =
    [
      "-i"
      cfg.listenAddress
      "-p"
      (toString cfg.port)
      "-c"
      (toString cfg.maxConnections)
    ]
    ++ lib.concatMap (s: [ "-A" cfg.detect ] ++ splitArgs s) cfg.strategies;

  services = lib.escapeShellArgs cfg.proxy.networkServices;

  # Applies the flag file to the system SOCKS setting. Only writes on an actual
  # change: rewriting network config on a timer churns SystemConfiguration and
  # can disturb live connections.
  toggleScript = pkgs.writeShellScript "veyl-proxy-toggle" ''
    want=0
    if [ -r ${cfg.proxy.stateFile} ]; then
      case "$(cat ${cfg.proxy.stateFile})" in
        1 | on | true | yes) want=1 ;;
      esac
    fi

    for svc in ${services}; do
      cur=$(/usr/sbin/networksetup -getsocksfirewallproxy "$svc" 2>/dev/null \
            | /usr/bin/awk '/^Enabled:/ { print $2 }')
      if [ "$want" = 1 ] && [ "$cur" != "Yes" ]; then
        /usr/sbin/networksetup -setsocksfirewallproxystate "$svc" on
      elif [ "$want" = 0 ] && [ "$cur" = "Yes" ]; then
        /usr/sbin/networksetup -setsocksfirewallproxystate "$svc" off
      fi
    done
  '';

  veylCtl = pkgs.writeShellScriptBin "veyl" ''
    state=${cfg.proxy.stateFile}
    read_state() { cat "$state" 2>/dev/null || echo 0; }

    case "''${1:-status}" in
      on) echo 1 > "$state" ;;
      off) echo 0 > "$state" ;;
      toggle) if [ "$(read_state)" = 1 ]; then echo 0 > "$state"; else echo 1 > "$state"; fi ;;
      status) ;;
      *)
        echo "usage: veyl [on|off|toggle|status]" >&2
        exit 2
        ;;
    esac

    if [ "$(read_state)" = 1 ]; then want=on; else want=off; fi
    echo "veyl: $want (applied by local.veyl-proxy within a moment)"
    for svc in ${services}; do
      printf '  %-26s SOCKS %s\n' "$svc" \
        "$(/usr/sbin/networksetup -getsocksfirewallproxy "$svc" 2>/dev/null \
           | /usr/bin/awk '/^Enabled:/ { print $2 }')"
    done
  '';
in
{
  options.services.veyl = {
    enable = lib.mkEnableOption "the ciadpi DPI bypass proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../pkgs/byedpi.nix { };
      defaultText = lib.literalExpression "byedpi";
      description = "The byedpi package providing ciadpi.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Bind address. ciadpi's own default is 0.0.0.0, which publishes an open
        SOCKS5 relay to every device on the LAN. Do not widen this casually.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 1080;
      description = "SOCKS5 port.";
    };

    maxConnections = lib.mkOption {
      type = lib.types.int;
      default = 8192;
      description = ''
        Concurrent connection cap. ciadpi's default of 512 is shared by the
        whole machine once the system SOCKS proxy is on, and at the cap it
        answers new connections with a TCP reset while established ones keep
        working. That is indistinguishable from the DPI blocking a site, so it
        presents as "another domain to add" rather than as proxy saturation.
      '';
    };

    detect = lib.mkOption {
      type = lib.types.str;
      default = "torst,ssl_err,redirect";
      description = "Signals that make ciadpi retry with the next strategy.";
    };

    strategies = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "-o 2"
        "-s 2 -o 2"
        "-s 2"
        "-o 3"
      ];
      description = ''
        Desync strategies, tried in order, each as one -A group. Deliberately
        several *different* mechanisms: this ISP's DPI adapts and clamps a
        single strategy within minutes, and a cascade re-converges by itself
        instead of needing a manual sweep.

        Verified working 2026-09-11; -d 2, -q 2 and -s 1+s were verified not to
        work and are omitted on purpose.
      '';
    };

    proxy = {
      mode = lib.mkOption {
        type = lib.types.enum [
          "toggle"
          "always"
          "manual"
        ];
        default = "toggle";
        description = ''
          How the system SOCKS setting is managed.

          - `toggle`: a root daemon follows `stateFile` and the `veyl` command
            flips it. Needs no sudo and no menu-bar app. ciadpi keeps running
            either way, so the setting can never outlive its listener -- which
            is the failure the old install needed two guard agents for.
          - `always`: turned on at activation and left on.
          - `manual`: never touched. Use if something else owns the setting.
        '';
      };

      stateFile = lib.mkOption {
        type = lib.types.str;
        default = "/Users/Shared/.veyl-enabled";
        description = ''
          Toggle state for `mode = "toggle"`: 1 is on, anything else is off.
          Created mode 0666 at activation so it can be flipped without sudo. The
          daemon reads nothing from it but that boolean.
        '';
      };

      networkServices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = config.networking.knownNetworkServices;
        defaultText = lib.literalExpression "config.networking.knownNetworkServices";
        description = "Network services to configure. The setting is per service, not global.";
      };

      bypassDomains = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "*.local"
          "169.254/16"
          "*.test"
          "*.localhost"
          "localhost"
          "127.0.0.1"
          "::1"
        ];
        description = "Hosts that must never enter the proxy, including local dev suffixes.";
      };
    };

    dns = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Run the DoH proxy on 127.0.0.1:53. Needed independently of the desync:
          this ISP also sinkholes DNS, so a blocked name resolves to its block
          page before any TLS is attempted.
        '';
      };

      guard = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Run dns-guard. The failure it covers is not "the daemon died" --
          KeepAlive handles that -- but "listening and not answering", which no
          port check detects and which takes the whole machine's DNS with it.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.strategies != [ ];
        message = "services.veyl.strategies is empty: ciadpi would never desync anything.";
      }
      {
        assertion = (cfg.proxy.mode != "manual") -> cfg.proxy.networkServices != [ ];
        message = ''
          services.veyl.proxy.mode is not "manual" but no network services are
          listed.
          Set networking.knownNetworkServices (e.g. [ "Wi-Fi" ]) or
          services.veyl.proxy.networkServices.
        '';
      }
    ];

    environment.systemPackages = [ cfg.package ] ++ lib.optional (cfg.proxy.mode == "toggle") veylCtl;

    # Labels are set explicitly rather than derived from launchd.labelPrefix:
    # dns-guard kickstarts local.doh-proxy by name, and keeping the labels
    # stable means existing logs and muscle memory still apply.
    launchd.daemons.ciadpi.serviceConfig = {
      Label = "local.ciadpi";
      ProgramArguments = [ (lib.getExe cfg.package) ] ++ ciadpiArgs;
      RunAtLoad = true;
      KeepAlive = true;
      ProcessType = "Background";
      StandardOutPath = "/var/log/ciadpi.log";
      StandardErrorPath = "/var/log/ciadpi.log";
    };

    launchd.daemons.doh-proxy = lib.mkIf cfg.dns.enable {
      serviceConfig = {
        Label = "local.doh-proxy";
        ProgramArguments = [ "${scripts.doh-proxy}/bin/doh-proxy" ];
        RunAtLoad = true;
        KeepAlive = true;
        ProcessType = "Background";
        StandardOutPath = "/var/log/doh-proxy.log";
        StandardErrorPath = "/var/log/doh-proxy.log";
      };
    };

    launchd.daemons.dns-guard = lib.mkIf (cfg.dns.enable && cfg.dns.guard) {
      serviceConfig = {
        Label = "local.dns-guard";
        ProgramArguments = [ "${scripts.dns-guard}/bin/dns-guard" ];
        RunAtLoad = true;
        StartInterval = 10;
        ProcessType = "Background";
        StandardErrorPath = "/var/log/dns-guard.err.log";
      };
    };

    launchd.daemons.veyl-proxy = lib.mkIf (cfg.proxy.mode == "toggle") {
      serviceConfig = {
        Label = "local.veyl-proxy";
        ProgramArguments = [ "${toggleScript}" ];
        RunAtLoad = true;
        WatchPaths = [ cfg.proxy.stateFile ];
        StartInterval = 60; # safety net if a WatchPaths event is ever missed
        ProcessType = "Background";
        StandardErrorPath = "/var/log/veyl-proxy.log";
      };
    };

    # The DoH proxy must be answering before anything is pointed at it, or you
    # have no DNS and no way to look up how to fix it. nix-darwin writes the
    # resolver with networksetup during activation, and launchd has the daemon
    # up by then; dns-guard covers it afterwards.
    networking.dns = lib.mkIf cfg.dns.enable [ "127.0.0.1" ];

    # Note this only ever points the setting at ciadpi and sets the bypass list.
    # Whether it is *on* is mode-dependent, and in toggle mode belongs to the
    # daemon above -- so a rebuild never silently re-enables a proxy you turned
    # off.
    system.activationScripts.postActivation.text = lib.mkIf (cfg.proxy.mode != "manual") (
      ''
        echo "configuring SOCKS proxy for veyl..." >&2
        for svc in ${services}; do
          /usr/sbin/networksetup -setsocksfirewallproxy \
            "$svc" ${cfg.listenAddress} ${toString cfg.port} || true
          /usr/sbin/networksetup -setproxybypassdomains \
            "$svc" ${lib.escapeShellArgs cfg.proxy.bypassDomains} || true
        done
      ''
      + lib.optionalString (cfg.proxy.mode == "always") ''
        for svc in ${services}; do
          /usr/sbin/networksetup -setsocksfirewallproxystate "$svc" on || true
        done
      ''
      + lib.optionalString (cfg.proxy.mode == "toggle") ''
        if [ ! -e ${cfg.proxy.stateFile} ]; then
          echo 1 > ${cfg.proxy.stateFile}
        fi
        chmod 0666 ${cfg.proxy.stateFile} || true
      ''
    );
  };
}
