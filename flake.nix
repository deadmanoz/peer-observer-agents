{
  description = "AI agents for peer-observer Bitcoin P2P network monitoring";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          peer-observer-agent = pkgs.rustPlatform.buildRustPackage {
            pname = "peer-observer-agent";
            version = "0.5.1";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];
          };

          default = self.packages.${system}.peer-observer-agent;
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.peer-observer-agent ];
            packages = with pkgs; [
              rustc
              cargo
              clippy
              rustfmt
              rust-analyzer
              just
            ];
          };
        }
      );

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          rustToolchain = [ pkgs.rustc pkgs.cargo pkgs.clippy pkgs.rustfmt ];
          buildDeps = [ pkgs.pkg-config pkgs.openssl ];
        in
        {
          package = self.packages.${system}.peer-observer-agent;

          fmt = pkgs.runCommand "fmt-check" {
            nativeBuildInputs = rustToolchain;
            src = ./.;
          } ''
            cd $src
            cargo fmt --check
            touch $out
          '';

          clippy = pkgs.runCommand "clippy-check" {
            nativeBuildInputs = rustToolchain ++ buildDeps;
            src = ./.;
          } ''
            export CARGO_HOME=$(mktemp -d)
            cp -r $src/* .
            cargo clippy --all-targets --all-features -- -D warnings
            touch $out
          '';

          test = pkgs.runCommand "test-check" {
            nativeBuildInputs = rustToolchain ++ buildDeps;
            src = ./.;
          } ''
            export CARGO_HOME=$(mktemp -d)
            cp -r $src/* .
            cargo test
            touch $out
          '';
        }
      );
    };
}
