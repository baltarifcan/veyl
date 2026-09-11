{
  description = "DPI and DNS bypass, as nix-darwin and home-manager modules";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        byedpi = pkgs.callPackage ./pkgs/byedpi.nix { };
        default = byedpi;
      });

      # The modules resolve their own packages with callPackage, so importing
      # them does not require `self` to be threaded through the consumer's
      # config. See README for which half owns what.
      darwinModules.default = ./modules/darwin.nix;
      homeManagerModules.default = ./modules/home.nix;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            python3
            shellcheck
            nixfmt
          ];
        };
      });

      checks = forAllSystems (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) byedpi;

        scripts = pkgs.runCommand "veyl-script-checks" { nativeBuildInputs = [ pkgs.python3 pkgs.shellcheck ]; } ''
          python3 -m py_compile ${./pkgs/src/doh-proxy.py} ${./pkgs/src/connect-bridge.py}
          shellcheck --shell=sh ${./pkgs/src/dns-guard.sh}
          touch $out
        '';
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
