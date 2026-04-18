#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICES="wave_4b wave_35 wave_5"
VERSION=$(cat "$REPO_ROOT/version.txt" | tr -d '[:space:]')

if [ -z "$VERSION" ]; then
    echo "Error: version.txt is empty"
    exit 1
fi

RELEASE_DIR="$REPO_ROOT/release/v${VERSION}"

echo "Building Kern v${VERSION} release for: ${DEVICES}"
echo "Output: ${RELEASE_DIR}"
echo

# Source ESP-IDF
source ~/esp/esp-idf/export.sh

mkdir -p "$RELEASE_DIR"

cd "$REPO_ROOT"

for DEVICE in $DEVICES; do
    echo "========================================"
    echo "Building for ${DEVICE}..."
    echo "========================================"

    # Remove sdkconfig so it regenerates for this device
    rm -f "$REPO_ROOT/sdkconfig"

    # Build
    idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.${DEVICE}" build

    BUILD_DIR="$REPO_ROOT/build"
    DEVICE_DIR="$RELEASE_DIR/${DEVICE}"
    mkdir -p "$DEVICE_DIR"

    # Copy individual binaries
    cp "$BUILD_DIR/bootloader/bootloader.bin" "$DEVICE_DIR/"
    cp "$BUILD_DIR/partition_table/partition-table.bin" "$DEVICE_DIR/"
    cp "$BUILD_DIR/kern.bin" "$DEVICE_DIR/firmware.bin"

    # Create merged binary
    esptool --chip esp32p4 merge-bin \
        --flash-mode dio \
        --flash-freq 80m \
        --flash-size 16MB \
        -o "$DEVICE_DIR/kern-v${VERSION}.bin" \
        0x2000  "$BUILD_DIR/bootloader/bootloader.bin" \
        0x8000  "$BUILD_DIR/partition_table/partition-table.bin" \
        0xf000  "$BUILD_DIR/ota_data_initial.bin" \
        0x20000 "$BUILD_DIR/kern.bin"

    # Create zip
    ZIP_NAME="kern-${DEVICE}-v${VERSION}.zip"
    (cd "$DEVICE_DIR" && zip "$RELEASE_DIR/$ZIP_NAME" \
        bootloader.bin \
        partition-table.bin \
        firmware.bin \
        "kern-v${VERSION}.bin")

    # Clean up loose files
    rm -rf "$DEVICE_DIR"

    echo "${DEVICE} done: ${ZIP_NAME}"
    echo
done

echo "========================================"
echo "Release v${VERSION} complete!"
echo "Files in ${RELEASE_DIR}:"
ls -lh "$RELEASE_DIR"
