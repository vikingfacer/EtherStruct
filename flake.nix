{
  description = "zig replayer flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let leg = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = leg.mkShell {
          nativeBuildInputs = [ leg.zig leg.libpcap ];
          packages = [ leg.pkg-config leg.zls leg.glow ];
        };
        packages.default = leg.stdenv.mkDerivation {
          name = "replayer";
          src = self;
          buildInputs = [ leg.zig leg.libpcap ];
          buildPhase =
            "export XDG_CACHE_HOME=$(mktemp -d); mkdir $out; zig build --prefix $out ";
        };
      });
}
