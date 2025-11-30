{
  description = "zig cappy development enviroment ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig.url = "github:mitchellh/zig-overlay";
    zls-overlay.url = "github:zigtools/zls/0.15.0";
    # Used for shell.nix
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    let
      overlays = [
        # Other overlays
        (final: prev: { zigpkgs = inputs.zig.packages.${prev.system}; })
      ];
      # Our supported systems are the same supported systems as the Zig binaries
      systems = builtins.attrNames inputs.zig.packages;
    in flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs { inherit overlays system; };
        zig = pkgs.zigpkgs.${"0.15.1"};
        zls = inputs.zls-overlay.packages.${system}.zls.overrideAttrs
          (old: { nativeBuildInputs = [ zig ]; });
      in rec {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ pkgs.libpcap zls zig ];
        };

        # For compatibility with older versions of the `nix` binary
        devShell = self.devShells.${system}.default;
      });
}

