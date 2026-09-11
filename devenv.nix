{ pkgs, ... }:

{
  packages = with pkgs; [
    python3
    shellcheck
    nixfmt
  ];

  # The daemons are stdlib-only on purpose, so the whole test suite is a syntax
  # gate plus shellcheck. Anything beyond that needs a real macOS host.
  enterTest = ''
    python3 -m py_compile pkgs/src/doh-proxy.py pkgs/src/connect-bridge.py
    shellcheck --shell=sh pkgs/src/dns-guard.sh
  '';
}
