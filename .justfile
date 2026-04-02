export IDF_PATH := env_var("HOME") + "/esp/esp-idf"
export IDF_PATH_FORCE := "1"

build:
    . $IDF_PATH/export.sh && idf.py build
    cp ./build/compile_commands.json ./compile_commands.json

flash:
    . $IDF_PATH/export.sh && idf.py flash

format:
    ./format.sh

test:
    ./test.sh

clean:
    rm -fRd build/
    rm -fRd compile_commands.json
    rm -fRd .cache/
    rm -rf simulator/build
    make -C components/bbqr/test clean
    make -C main/core/test clean

# Build the desktop simulator
sim-build:
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug && cmake --build build -- -j$(nproc)

# Run the desktop simulator
# SDL env vars: software renderer for compatibility with ssh -X
sim *ARGS: sim-build
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator {{ARGS}}

# Clean simulator build artifacts
sim-clean:
    rm -rf simulator/build

# Reset simulator to factory state (wipes all persistent data)
sim-reset:
    rm -rf simulator/sim_data

# Run simulator with a QR image (software renderer for ssh -X)
sim-qr IMAGE: sim-build
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator --qr-image {{IMAGE}}

# Build simulator with webcam support (V4L2)
sim-build-webcam:
    cd simulator && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DSIM_WEBCAM=ON && cmake --build build -- -j$(nproc)

# Run simulator with webcam (builds with V4L2 support)
sim-webcam *ARGS: sim-build-webcam
    SDL_VIDEODRIVER=x11 SDL_RENDER_DRIVER=software ./simulator/build/kern_simulator --webcam {{ARGS}}
