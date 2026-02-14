{
  description = "Kern development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };

          clangFormat = pkgs.runCommand "clang-format-18" { } ''
            mkdir -p $out/bin
            ln -s ${pkgs.lib.getBin pkgs.llvmPackages_18.clang-unwrapped}/bin/clang-format $out/bin/clang-format
          '';

          # Build the shell with clang everywhere: it is the native toolchain
          # on Darwin, and it keeps the host compiler the same on both
          # platforms so .clang-tidy / .clangd see one set of builtin headers.
          mkShell = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; };
        in
        {
          default = mkShell {
            name = "kern-dev-shell";

            buildInputs = [
              # clang-format, clang-tidy and clangd, for scripts/format.sh
              # and the checked-in .clang-tidy / .clangd configs.
              pkgs.clang-tools
              pkgs.cmake
              pkgs.gnumake
              pkgs.just
              # nproc, used by the simulator recipes, is GNU-only.
              pkgs.coreutils
              pkgs.zlib
              pkgs.mbedtls
              pkgs.SDL2
              pkgs.pkg-config
            ];

            shellHook = ''
              export PATH="${clangFormat}/bin:$PATH"
              echo "Kern host-tools shell ready"
              echo "  clang:      $(clang --version | head -1)"
              echo "  format:     $(clang-format --version)"
              echo "  cmake:      $(cmake --version | head -1)"
              echo "  make:       $(make --version | head -1)"
              echo "  just:       $(just --version)"
              echo "  firmware:   install ESP-IDF v6.1 separately"
            '';
          };
        });
    };
  }
