#!/bin/bash
# Prints the bootloader variant a build belongs to, from its generated
# sdkconfig: chip revision range (v1 / v3) and flash mode (qio / dio). Boards
# of one variant share one frozen bootloader (docs/secure-boot.md, section 4a).
#
# Usage: bootloader_variant.sh <build-dir>/sdkconfig

set -e

CONFIG="$1"
if [ ! -f "$CONFIG" ]; then
    echo "Usage: $0 <sdkconfig>" >&2
    exit 1
fi

if grep -q '^CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y' "$CONFIG"; then REV=v1; else REV=v3; fi
if grep -q '^CONFIG_ESPTOOLPY_FLASHMODE_QIO=y' "$CONFIG"; then
    MODE=qio
elif grep -q '^CONFIG_ESPTOOLPY_FLASHMODE_DIO=y' "$CONFIG"; then
    MODE=dio
else
    echo "Error: $CONFIG uses a flash mode with no bootloader variant" >&2
    exit 1
fi
echo "$REV-$MODE"
