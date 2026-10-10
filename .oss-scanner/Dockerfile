# Build image for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The scanner clones the repository without submodules, builds this file with the
# checkout as the context (network available), then audits the finished image with
# no network. Everything the audit may need is built or fetched here.
#
# Same base image as CI (.github/workflows/*.yml). It ships ESP-IDF v6.1, the
# esp32p4 toolchain, cmake, ninja and python; host tests and the simulator also
# need the system packages below.
FROM espressif/idf:v6.1
# export.sh needs bash, the default /bin/sh is dash
SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      zlib1g-dev libmbedtls-dev libsdl2-dev gdb \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# libwally-core, cUR, k_quirc and bip138 are submodules (libwally nests secp256k1)
RUN git config --global --add safe.directory '*' \
    && git submodule update --init --recursive

# Host tests: core (PSBT, descriptors, KEF, PIN, BIP32, BIP322, firmware update
# pre-flight), QR parsers, BBQr, deflate, secure memory, bip138, k_quirc.
# Failures do not abort the build; the binaries stay in place for the audit.
RUN . "$IDF_PATH/export.sh" >/dev/null \
    && (bash scripts/test.sh || echo "WARNING: host tests reported failures")

# Desktop simulator: the real core, QR and page code as a native x86-64 debug
# binary with ESP-IDF stubs. Its ctest targets are lifecycle regressions.
RUN . "$IDF_PATH/export.sh" >/dev/null \
    && cmake -S simulator -B simulator/build -DCMAKE_BUILD_TYPE=Debug \
         -DSIM_BOARD=wave_4b -DSIM_LCD_H_RES=720 -DSIM_LCD_V_RES=720 \
    && cmake --build simulator/build -j"$(nproc)" \
    && (ctest --test-dir simulator/build --output-on-failure \
        || echo "WARNING: simulator tests reported failures")

# Firmware, as the maintainers build it (just build wave_4b). Pulls the managed
# components from the Espressif registry, so it needs the network.
RUN . "$IDF_PATH/export.sh" >/dev/null \
    && idf.py -B build_wave_4b -D SDKCONFIG=build_wave_4b/sdkconfig \
         -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_4b' build \
    && cp build_wave_4b/compile_commands.json compile_commands.json

# Interactive shells get idf.py and the toolchain on PATH; non-interactive ones
# must source $IDF_PATH/export.sh themselves.
RUN echo '. "$IDF_PATH/export.sh" >/dev/null 2>&1' >> /etc/bash.bashrc
