export IDF_PATH := env_var("HOME") + "/esp/esp-idf"
export IDF_PATH_FORCE := "1"

# Board parameter: "wave_4b" (default), "wave_35", or "wave_5"
# Usage: just build wave_35, just flash wave_4b, just build wave_5
# Each board builds into its own build_<board>/ directory, so switching
# boards is instant (no clean required) and per-board builds stay incremental.

build board="wave_4b":
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.{{board}}' build
    cp ./build_{{board}}/compile_commands.json ./compile_commands.json

flash board="wave_4b":
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.{{board}}' flash

monitor board="wave_4b":
    #!/usr/bin/env sh
    command -v idf.py >/dev/null || . $IDF_PATH/export.sh
    idf.py -B build_{{board}} -D SDKCONFIG=build_{{board}}/sdkconfig monitor

format:
    ./scripts/format.sh

test:
    ./scripts/test.sh

clean:
    rm -fRd build build_wave_4b build_wave_35 build_wave_5
    rm -f sdkconfig
    rm -fRd compile_commands.json
    rm -fRd .cache/
    rm -rf simulator/build
    make -C components/bbqr/test clean
    make -C main/core/test clean

# Simulator board resolution mapping
# wave_4b: 720x720, wave_35: 320x480, wave_5: 720x1280
_sim_h_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 320;; wave_5) echo 720;; *) echo 720;; esac

_sim_v_res board:
    #!/usr/bin/env sh
    case "{{board}}" in wave_35) echo 480;; wave_5) echo 1280;; *) echo 720;; esac

# Build the desktop simulator
sim-build board="wave_4b":
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug \
        -DSIM_BOARD={{board}} \
        -DSIM_LCD_H_RES=$(just _sim_h_res {{board}}) \
        -DSIM_LCD_V_RES=$(just _sim_v_res {{board}}) \
        && cmake --build build -- -j$(nproc)

# Run the desktop simulator
# SDL env vars: software renderer for compatibility with ssh -X
sim board="wave_4b": (sim-build board)
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
sim-build-webcam board="wave_4b":
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DSIM_WEBCAM=ON \
        -DSIM_BOARD={{board}} \
        -DSIM_LCD_H_RES=$(just _sim_h_res {{board}}) \
        -DSIM_LCD_V_RES=$(just _sim_v_res {{board}}) \
        && cmake --build build -- -j$(nproc)

# Run simulator with webcam (builds with V4L2 support)
sim-webcam board="wave_4b": (sim-build-webcam board)
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator --webcam

# update subrepo dependencies
dep:
    git submodule update --init --recursive
