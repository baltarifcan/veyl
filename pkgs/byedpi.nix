{
  lib,
  stdenv,
  fetchFromGitHub,
}:

# ciadpi, the SOCKS5 proxy that does the desync. Built from source rather than
# vendored as a prebuilt binary -- the installer this replaced shipped a blob,
# which is the one thing that could not be reproduced from this repo.
stdenv.mkDerivation (finalAttrs: {
  pname = "byedpi";
  version = "0.17.3";

  src = fetchFromGitHub {
    owner = "hufrea";
    repo = "byedpi";
    rev = "v${finalAttrs.version}";
    hash = "sha256-dDUmCIWy4uHIBmbonrpkrBnurYHfZAdz/jd3l0228Ec=";
  };

  # Plain C99, no dependencies. The Makefile's install target honours PREFIX.
  makeFlags = [
    "CC=${stdenv.cc.targetPrefix}cc"
    "PREFIX=${placeholder "out"}"
  ];

  enableParallelBuilding = true;

  meta = {
    description = "DPI circumvention proxy (ciadpi)";
    homepage = "https://github.com/hufrea/byedpi";
    license = lib.licenses.mit; # verified against upstream LICENSE, (c) 2024 hufrea
    mainProgram = "ciadpi";
    platforms = lib.platforms.unix;
  };
})
