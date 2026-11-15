export IDF_PATH := env_var_or_default("IDF_PATH", env_var("HOME") + "/esp/esp-idf")
export IDF_PATH_FORCE := "1"

# Board parameter: "wave_4b" (default), "wave_35", "wave_5", "wave_43", "crowpanel", "wave_7b", or "p4_pico"
# Usage: just build wave_35, just flash wave_4b, just build wave_5, just build wave_7b
# Each board builds into its own build_<board>/ directory, so switching
# boards is instant (no clean required) and per-board builds stay incremental.
# Append _v3 to a board (just build wave_43_v3) for ESP32-P4 chip revision
# v3.x: IDF cannot build one image for both v1.x and v3.x silicon.

boards := "wave_4b wave_35 wave_5 wave_43 crowpanel wave_7b p4_pico"

_check_board board:
    #!/usr/bin/env sh
    case " {{boards}} " in *" {{trim_end_match(board, "_v3")}} "*) ;; *) echo "error: unknown board '{{board}}' (valid: {{boards}}, each optionally suffixed _v3)" >&2; exit 1;; esac

_defaults board:
    @echo "sdkconfig.defaults;sdkconfig.defaults.{{trim_end_match(board, "_v3")}}{{ if board =~ '_v3$' { ";sdkconfig.rev3" } else { "" } }}"

build board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    # Without this a failed build still exits 0: the recipe would carry on to the
    # cp below, which succeeds because cmake writes compile_commands.json at
    # configure time, and just reports the recipe's last exit status.
    set -e
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}})" build
    cp ./build_{{board}}/compile_commands.json ./compile_commands.json

flash board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}})" flash

# The sdkconfig is regenerated every time so overlay edits always land.
# Release log and panic settings (sdkconfig.release overlay) with a plain bootloader, in build_release_<board>/.
# scripts/release.sh builds with build-secure.
build-release board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    set -e
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    rm -f build_release_{{board}}/sdkconfig
    idf.py -B build_release_{{board}} -D SDKCONFIG=build_release_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}});sdkconfig.release" build

flash-release board="wave_4b": (build-release board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_release_{{board}} -D SDKCONFIG=build_release_{{board}}/sdkconfig flash

# Lockable release image (sdkconfig.release + sdkconfig.secure, published key digests) in build_secure_<board>/.
# The build signs with dev_signing_key.pem; the files to sign with the release keys are
# kern-unsigned.bin (key 0) and bootloader/bootloader-unsigned.bin (keys 0, 1 and 2).
build-secure board="wave_4b" target="build": (_check_board board)
    #!/usr/bin/env sh
    set -e
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    rm -f build_secure_{{board}}/sdkconfig
    idf.py -B build_secure_{{board}} -D SDKCONFIG=build_secure_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}});sdkconfig.release;sdkconfig.secure" {{target}}

# Build every board's secure bootloader and stage one unsigned image per variant in release/bootloader-<N>/
# for scripts/freeze_bootloader.sh, which signs them with the three release keys on the air-gapped PC.
bootloader-stage:
    ./scripts/bootloader_stage.sh

# Verify a signed release/bootloader-<N>/ folder and copy it into kern_secure_boot/bootloaders/
bootloader-import dir:
    ./scripts/bootloader_import.sh {{dir}}

# Secure boot dry run: a sdkconfig.secure build with virtual eFuses (sdkconfig.sbtest), so the
# Settings lockdown burns a RAM copy that is gone after the restart. Signed with test keys:
# dev_signing_key.pem signs the app, it and two throwaway keys sign the bootloader, and their
# digests replace the release ones. Run on a board that already has a PIN.
sbtest-build board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    set -e
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    dir=build_sbtest_{{board}}
    mkdir -p $dir/keys $dir/digests
    [ -f dev_signing_key.pem ] || python -m espsecure generate-signing-key --version 2 --scheme rsa3072 dev_signing_key.pem
    cp dev_signing_key.pem $dir/keys/key0.pem
    for n in 1 2; do
        [ -f $dir/keys/key$n.pem ] || python -m espsecure generate-signing-key --version 2 --scheme rsa3072 $dir/keys/key$n.pem
    done
    for n in 0 1 2; do
        python -m espsecure digest-sbv2-public-key --keyfile $dir/keys/key$n.pem -o $dir/digests/kern-sb-digest$n.bin
    done
    rm -f $dir/sdkconfig
    idf.py -B $dir -D SDKCONFIG=$dir/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}});sdkconfig.secure;sdkconfig.sbtest" -D KERN_SB_DIGEST_DIR=$PWD/$dir/digests build
    python -m espsecure sign-data --version 2 --keyfile $dir/keys/key1.pem --append-signatures -o $dir/bootloader-2sig.bin $dir/bootloader/bootloader.bin
    python -m espsecure sign-data --version 2 --keyfile $dir/keys/key2.pem --append-signatures -o $dir/bootloader-sbtest.bin $dir/bootloader-2sig.bin

# idf.py leaves the bootloader out when secure boot is configured, so esptool writes it.
# `just flash <board>` puts the normal firmware back.
sbtest-flash board="wave_4b": (sbtest-build board)
    #!/usr/bin/env sh
    set -e
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    dir=build_sbtest_{{board}}
    idf.py -B $dir -D SDKCONFIG=$dir/sdkconfig flash
    python -m esptool --chip esp32p4 write-flash 0x2000 $dir/bootloader-sbtest.bin

monitor board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig monitor

# Build with the PBKDF2 accelerator and its on-device check, then watch it run
pbkdf2-check board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_pbkdf2_{{board}} -D SDKCONFIG=build_pbkdf2_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}});sdkconfig.pbkdf2check" flash monitor

# Build with QR scanner pipeline timing, then watch it run
scan-prof board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_scanprof_{{board}} -D SDKCONFIG=build_scanprof_{{board}}/sdkconfig -D "SDKCONFIG_DEFAULTS=$(just _defaults {{board}});sdkconfig.scanprof" flash monitor

format:
    ./scripts/format.sh

test:
    ./scripts/test.sh

# Core host tests built with ASan and UBSan, libwally included
test-asan:
    make -C main/core/test clean
    make -C main/core/test SANITIZE=1 run
    make -C main/core/test clean

# Fuzz the glue around libwally (ASan and UBSan, coverage-blind driver)
fuzz iterations="20000":
    make -C main/core/test clean
    make -C main/core/test SANITIZE=1 FUZZ_ITERATIONS={{iterations}} fuzz
    make -C main/core/test clean

clean:
    rm -fRd build build_wave_4b build_wave_35 build_wave_5 build_wave_43 build_crowpanel build_wave_7b build_p4_pico
    rm -fRd build_*_v3
    rm -fRd build_pbkdf2_*
    rm -fRd build_scanprof_*
    rm -fRd build_release_*
    rm -fRd build_sbtest_*
    rm -fRd build_secure_*
    rm -f sdkconfig
    rm -fRd compile_commands.json
    rm -fRd .cache/
    rm -rf simulator/build
    make -C components/bbqr/test clean
    make -C components/secure_memory/test clean
    make -C components/bip138 clean
    make -C main/qr/test clean
    rm -rf components/k_quirc/test/build
    make -C main/core/test clean

# Stages branding and any locally built firmware into site/ the same way the
# deploy-site job in .github/workflows/test-all-builds.yml does, so what you see
# on localhost is what gets deployed. Boards you have not built are simply
# absent: the flasher still renders, but its CI-build mode cannot fetch them.
# Serve on localhost only -- Web Serial needs a secure context, which
# http://localhost provides but a LAN IP does not.
# Serve the landing page + web flasher locally, as GitHub Pages does
site port="8000":
    #!/usr/bin/env sh
    set -e
    rm -rf site/branding site/flash/firmware
    cp -r branding site/branding
    for b in {{boards}} $(printf '%s_v3 ' {{boards}}); do
        [ -f "build_$b/flasher_args.json" ] || continue
        stage="site/flash/firmware/$b"
        mkdir -p "$stage"
        cp "build_$b"/bootloader/bootloader.bin "$stage"/
        cp "build_$b"/partition_table/partition-table.bin "$stage"/
        cp "build_$b"/flasher_args.json "$stage"/
        cp "build_$b"/*.bin "$stage"/ 2>/dev/null || true
        cp "build_$b"/flash_args "$stage"/ 2>/dev/null || true
        echo "staged firmware: $b"
    done
    echo "Serving http://localhost:{{port}}/"
    python3 -m http.server {{port}} -d site

# Simulator board resolution mapping
# wave_4b: 720x720, wave_35: 320x480, wave_5: 720x1280, wave_43: 480x800, crowpanel: 1024x600, wave_7b: 1024x600, p4_pico: 720x1280
_sim_h_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 320;; wave_5) echo 720;; wave_43) echo 480;; crowpanel) echo 1024;; wave_7b) echo 1024;; p4_pico) echo 720;; *) echo 720;; esac

_sim_v_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 480;; wave_5) echo 1280;; wave_43) echo 800;; crowpanel) echo 600;; wave_7b) echo 600;; p4_pico) echo 1280;; *) echo 720;; esac

# Build the desktop simulator
sim-build board="wave_4b": (_check_board board)
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug \
        -DSIM_BOARD={{board}} \
        -DSIM_LCD_H_RES=$(just _sim_h_res {{board}}) \
        -DSIM_LCD_V_RES=$(just _sim_v_res {{board}}) \
        && cmake --build build -- -j$(nproc)

# Run simulator storage and sensitive-data lifecycle regressions
sim-test board="wave_4b": (sim-build board)
    ctest --test-dir simulator/build --output-on-failure

# Run the desktop simulator with webcam
# SDL env vars: software renderer for compatibility with ssh -X
sim board="wave_4b": (sim-build-webcam board)
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator --webcam

# Run the desktop simulator without camera
sim-no-cam board="wave_4b": (sim-build board)
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator

# Clean simulator build artifacts
sim-clean:
    rm -rf simulator/build

# Reset simulator to factory state (wipes all persistent data)
sim-reset:
    rm -rf simulator/sim_data

# Run simulator with a QR image (software renderer for ssh -X)
sim-qr IMAGE board="wave_4b": (sim-build board)
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator --qr-image {{IMAGE}}

# Build simulator with webcam support (V4L2)
sim-build-webcam board="wave_4b": (_check_board board)
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DSIM_WEBCAM=ON \
        -DSIM_BOARD={{board}} \
        -DSIM_LCD_H_RES=$(just _sim_h_res {{board}}) \
        -DSIM_LCD_V_RES=$(just _sim_v_res {{board}}) \
        && cmake --build build -- -j$(nproc)

# update subrepo dependencies
dep:
    git submodule update --init --recursive
