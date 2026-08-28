export IDF_PATH := env_var("HOME") + "/esp/esp-idf"
export IDF_PATH_FORCE := "1"

# Board parameter: "wave_4b" (default), "wave_35", "wave_5", "wave_43", "crowpanel", or "wave_7b"
# Usage: just build wave_35, just flash wave_4b, just build wave_5, just build wave_7b
# Each board builds into its own build_<board>/ directory, so switching
# boards is instant (no clean required) and per-board builds stay incremental.

boards := "wave_4b wave_35 wave_5 wave_43 crowpanel wave_7b"

_check_board board:
    #!/usr/bin/env sh
    case " {{boards}} " in *" {{board}} "*) ;; *) echo "error: unknown board '{{board}}' (valid: {{boards}})" >&2; exit 1;; esac

build board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.{{board}}' build
    cp ./build_{{board}}/compile_commands.json ./compile_commands.json

flash board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.{{board}}' flash

monitor board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig monitor

# Build with the PBKDF2 accelerator and its on-device check, then watch it run
pbkdf2-check board="wave_4b": (_check_board board)
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_pbkdf2_{{board}} -D SDKCONFIG=build_pbkdf2_{{board}}/sdkconfig -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.{{board}};sdkconfig.pbkdf2check' flash monitor

format:
    ./scripts/format.sh

test:
    ./scripts/test.sh

clean:
    rm -fRd build build_wave_4b build_wave_35 build_wave_5 build_wave_43 build_crowpanel build_wave_7b
    rm -fRd build_pbkdf2_*
    rm -f sdkconfig
    rm -fRd compile_commands.json
    rm -fRd .cache/
    rm -rf simulator/build
    make -C components/bbqr/test clean
    make -C main/qr/test clean
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
    for b in {{boards}}; do
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
# wave_4b: 720x720, wave_35: 320x480, wave_5: 720x1280, wave_43: 480x800, crowpanel: 1024x600, wave_7b: 1024x600
_sim_h_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 320;; wave_5) echo 720;; wave_43) echo 480;; crowpanel) echo 1024;; wave_7b) echo 1024;; *) echo 720;; esac

_sim_v_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 480;; wave_5) echo 1280;; wave_43) echo 800;; crowpanel) echo 600;; wave_7b) echo 600;; *) echo 720;; esac

# Build the desktop simulator
sim-build board="wave_4b": (_check_board board)
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug \
        -DSIM_BOARD={{board}} \
        -DSIM_LCD_H_RES=$(just _sim_h_res {{board}}) \
        -DSIM_LCD_V_RES=$(just _sim_v_res {{board}}) \
        && cmake --build build -- -j$(nproc)

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
