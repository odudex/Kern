#!/bin/bash
# Kern release signing + packaging — runs on the AIR-GAPPED signing PC.
#
# For each device staged by release.sh, this script:
#   1. signs the app image with the Secure Boot v2 RSA-3072 primary key (key0)
#      and verifies the signature
#   2. regenerates the single-file Intel HEX embedding the SIGNED app (sparse:
#      flashing it preserves the NVS and SPIFFS partitions)
#   3. packs the publishable zip (self-describing via flasher_args.json so the
#      web flasher's custom-ZIP mode flashes the signed app)
# and finally writes SHA256SUMS over the zips.
#
# Usage (from inside the release folder on the SD card):
#
#   bash sign_release.sh /path/to/kern-sb-key0.pem [release-dir]
#
# release-dir defaults to the directory this script sits in.
#
# Requirements on the signing PC: bash, python3, sha256sum, and the esptool
# pip package (provides both espsecure and esptool; install offline with
# pip install esptool). python3 -m fallbacks are used if the CLIs are not on
# PATH.
#
# Input per device:  <device>/{bootloader,partition-table,ota_data_initial,
#                    firmware}.bin
# Output per device: <device>/firmware-signed.bin   (also the SD-update file)
#                    <device>/kern-v<ver>.hex       (serial install, signed app)
#                    kern-<device>-v<ver>.zip       (publishable bundle)
# Plus:              SHA256SUMS                     (over the zips)
#
# The private key never touches the release folder; only signatures do.

set -e

KEYFILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="${2:-$SCRIPT_DIR}"

if [ -z "$KEYFILE" ] || [ ! -f "$KEYFILE" ]; then
    echo "Usage: $0 <signing-key.pem> [release-dir]" >&2
    echo "Error: signing key not found: '$KEYFILE'" >&2
    exit 1
fi

if [ -f "$RELEASE_DIR/VERSION" ]; then
    VERSION="$(tr -d '[:space:]' < "$RELEASE_DIR/VERSION")"
else
    VERSION="$(basename "$RELEASE_DIR" | sed 's/^v//')"
fi

if command -v espsecure >/dev/null 2>&1; then
    ESPSECURE="espsecure"
elif python3 -c "import espsecure" >/dev/null 2>&1; then
    ESPSECURE="python3 -m espsecure"
else
    echo "Error: espsecure not found. Install esptool (pip install esptool)." >&2
    exit 1
fi

if command -v esptool >/dev/null 2>&1; then
    ESPTOOL="esptool"
elif python3 -c "import esptool" >/dev/null 2>&1; then
    ESPTOOL="python3 -m esptool"
else
    echo "Error: esptool not found. Install esptool (pip install esptool)." >&2
    exit 1
fi

FOUND=0
ZIPS=()

for UNSIGNED in "$RELEASE_DIR"/*/firmware.bin; do
    [ -f "$UNSIGNED" ] || continue
    FOUND=1
    DEVICE_DIR="$(dirname "$UNSIGNED")"
    DEVICE="$(basename "$DEVICE_DIR")"
    SIGNED="$DEVICE_DIR/firmware-signed.bin"
    HEX="$DEVICE_DIR/kern-v${VERSION}.hex"
    ZIP_NAME="kern-${DEVICE}-v${VERSION}.zip"

    echo "── ${DEVICE}: signing ──"
    $ESPSECURE sign-data --version 2 --keyfile "$KEYFILE" \
        --output "$SIGNED" "$UNSIGNED"
    $ESPSECURE verify-signature --version 2 --keyfile "$KEYFILE" "$SIGNED"

    echo "── ${DEVICE}: single-file image (signed app, NVS-preserving) ──"
    $ESPTOOL --chip esp32p4 merge-bin \
        --format hex \
        -o "$HEX" \
        0x2000  "$DEVICE_DIR/bootloader.bin" \
        0x8000  "$DEVICE_DIR/partition-table.bin" \
        0x1e000 "$DEVICE_DIR/ota_data_initial.bin" \
        0x20000 "$SIGNED"

    # flasher_args.json lets the web flasher's custom-ZIP mode find the signed
    # app; offsets must match the merge-bin layout above
    cat > "$DEVICE_DIR/flasher_args.json" <<EOF
{
    "flash_files": {
        "0x2000": "bootloader.bin",
        "0x8000": "partition-table.bin",
        "0x1e000": "ota_data_initial.bin",
        "0x20000": "firmware-signed.bin"
    }
}
EOF

    echo "── ${DEVICE}: packing ${ZIP_NAME} ──"
    python3 - "$RELEASE_DIR/$ZIP_NAME" "$DEVICE_DIR" "kern-v${VERSION}.hex" <<'EOF'
import sys, zipfile, os
zip_path, device_dir, hex_name = sys.argv[1:4]
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for name in ("bootloader.bin", "partition-table.bin",
                 "ota_data_initial.bin", "firmware-signed.bin",
                 "flasher_args.json", hex_name):
        z.write(os.path.join(device_dir, name), name)
EOF

    ZIPS+=("$ZIP_NAME")
    echo
done

if [ "$FOUND" = 0 ]; then
    echo "Error: no <device>/firmware.bin found under $RELEASE_DIR" >&2
    exit 1
fi

(
    cd "$RELEASE_DIR"
    sha256sum "${ZIPS[@]}" > SHA256SUMS
    echo "SHA256SUMS:"
    cat SHA256SUMS
)

echo
echo "Done. Publishable artifacts: kern-<device>-v${VERSION}.zip + SHA256SUMS"
echo "SD-update file per device: <device>/firmware-signed.bin (also inside the zip)"
echo "Optionally GPG-sign the checksums: gpg --detach-sign --armor SHA256SUMS"
