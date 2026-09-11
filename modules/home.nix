{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.veyl;
  scripts = pkgs.callPackage ../pkgs/scripts.nix { };

  noProxy = lib.concatStringsSep "," cfg.noProxy;

  directFileArg = lib.optionalString (cfg.directHosts != [ ]) (
    " --direct-file ${pkgs.writeText "veyl-direct" (lib.concatMapStrings (h: h + "\n") cfg.directHosts)}"
  );

  # This has to publish HTTPS_PROXY with `launchctl setenv`, which is per-user
  # and does not survive a reboot -- hence a wrapper on RunAtLoad, and hence
  # this half living in home-manager rather than in the system module.
  wrapper = pkgs.writeShellScript "connect-bridge-wrapper" ''
    /bin/launchctl setenv HTTPS_PROXY "http://127.0.0.1:${toString cfg.port}"
    /bin/launchctl setenv https_proxy "http://127.0.0.1:${toString cfg.port}"
    /bin/launchctl setenv NO_PROXY "${noProxy}"
    /bin/launchctl setenv no_proxy "${noProxy}"

    exec ${scripts.connect-bridge}/bin/connect-bridge --port ${toString cfg.port}${directFileArg}
  '';
in
{
  options.services.veyl = {
    enable = lib.mkEnableOption ''
      connect-bridge, an HTTP CONNECT front-end for clients that honour
      HTTPS_PROXY but cannot speak SOCKS. Discord's updater is the reason it
      exists: it is Rust/reqwest, built without SOCKS support, and reqwest's
      macOS system-proxy lookup never reads the SOCKS key -- so the Chromium
      half of Discord works while the updater goes out raw and gets reset
    '';

    port = lib.mkOption {
      type = lib.types.port;
      default = 1085;
      description = "Port the bridge listens on, published as HTTPS_PROXY.";
    };

    directHosts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "dl2.discordapp.net" ];
      description = ''
        Hosts this bridge must always dial direct, never through ciadpi.

        Normally empty, and there is no file on disk unless you set it. It used
        to be a hand-maintained list because the old hostlist desynced anything
        matching it -- `dl2.discordapp.net` serves update payloads that are not
        blocked but time out through an OOB desync, and it matched
        `discordapp.net`. Auto-detect removed that whole class of problem: an
        unblocked host is never desynced, so it never needs exempting.

        It survives only as an escape hatch for a host that genuinely looks
        blocked -- one that resets connections for its own reasons -- and that a
        desync would then break. Note it covers only traffic through this
        bridge; the system SOCKS path does not consult it.
      '';
    };

    noProxy = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "localhost"
        ".localhost"
        ".test"
        "127.0.0.1"
        "::1"
      ];
      description = ''
        Published as NO_PROXY. Must exclude loopback and any local dev suffixes,
        or `curl https://myapp.test` tunnels local traffic into ciadpi.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    launchd.agents.connect-bridge = {
      enable = true;
      config = {
        Label = "local.connect-bridge";
        ProgramArguments = [ "${wrapper}" ];
        RunAtLoad = true;
        KeepAlive = true;
        ProcessType = "Background";
        StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/connect-bridge.log";
      };
    };
  };
}
