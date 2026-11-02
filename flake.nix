{
  description = "Kern development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # mirrexagon/nixpkgs-esp-dev#135 (ESP-IDF v6.1) plus a libpython3.14 fix for Linux.
    nixpkgs-esp-dev = {
      url = "github:Sammyalhashe/nixpkgs-esp-dev/b574e8e501dfa691814c87d4151043eb991d2be9";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-esp-dev,
    }:
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
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ nixpkgs-esp-dev.overlays.default ];

            # The Python library ecdsa is marked as insecure, but we need it for esptool.
            # See https://github.com/mirrexagon/nixpkgs-esp-dev/issues/109
            config.permittedInsecurePackages = [
              "python3.13-ecdsa-0.19.1"
              "python3.13-ecdsa-0.19.2"
            ];
          };

          # LLVM 21 is the major ESP-IDF 6.1 ships as esp-clang and the one
          # scripts/format.sh requires: clang-format's defaults drift between
          # majors, so every host has to run the same one.
          llvm = pkgs.llvmPackages_21;

          # Build the shell with clang everywhere: it is the native toolchain
          # on Darwin, and it keeps the host compiler the same on both
          # platforms so .clang-tidy / .clangd see one set of builtin headers.
          mkShell = pkgs.mkShell.override { stdenv = llvm.stdenv; };
        in
        {
          default = mkShell {
            name = "kern-dev-shell";

            buildInputs = [
              # clang-format, clang-tidy and clangd, for scripts/format.sh
              # and the checked-in .clang-tidy / .clangd configs.
              llvm.clang-tools
              pkgs.cmake
              pkgs.gnumake
              pkgs.just
              # The simulator fetches LVGL with FetchContent, which runs git.
              pkgs.git
              # nproc, used by the simulator recipes, is GNU-only.
              pkgs.coreutils
              pkgs.zlib
              pkgs.mbedtls
              pkgs.SDL2
              pkgs.pkg-config
              # ESP-IDF v6.1 with its toolchains and Python env (incl. esp-idf-sbom).
              pkgs.esp-idf-full
            ];

            shellHook = ''
              echo "Kern host-tools shell ready"
              echo "  clang:      $(clang --version | head -1)"
              echo "  format:     $(clang-format --version)"
              echo "  cmake:      $(cmake --version | head -1)"
              echo "  make:       $(make --version | head -1)"
              echo "  just:       $(just --version)"
              echo "  firmware:   ESP-IDF $(cat "$IDF_PATH/version.txt")"
            '';
          };
        }
      );
    };
}
