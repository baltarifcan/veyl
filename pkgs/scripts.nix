{
  runCommand,
  python3,
}:

# The three helper daemons, carried over unchanged from the hand-rolled install.
# They are stdlib-only by design, so packaging is just pinning the interpreter:
# no /usr/bin/env lookup, no dependency on Xcode's python3 stub being present.
let
  pythonBin =
    name: src:
    runCommand name { } ''
      mkdir -p $out/bin
      sed '1s|^#!.*|#!${python3}/bin/python3|' ${src} > $out/bin/${name}
      chmod +x $out/bin/${name}
    '';
in
{
  doh-proxy = pythonBin "doh-proxy" ./src/doh-proxy.py;
  connect-bridge = pythonBin "connect-bridge" ./src/connect-bridge.py;

  # dns-guard calls every macOS tool it needs by absolute path already, so it
  # needs no PATH and no interpreter rewrite -- only /bin/sh, which is always
  # there. Installed verbatim.
  dns-guard = runCommand "dns-guard" { } ''
    mkdir -p $out/bin
    install -m 755 ${./src/dns-guard.sh} $out/bin/dns-guard
  '';
}
