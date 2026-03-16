#!/bin/bash

# Script to run clang-format on all .c and .h files in project source directories
# Covers main/ and first-party components (excludes libwally-core)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DIRS=(
    "$SCRIPT_DIR/main"
    "$SCRIPT_DIR/components/bbqr"
    "$SCRIPT_DIR/components/cUR"
    "$SCRIPT_DIR/components/k_quirc"
    "$SCRIPT_DIR/components/sd_card"
    "$SCRIPT_DIR/components/video"
    "$SCRIPT_DIR/components/waveshare_bsp"
)

echo "Running clang-format on project source files..."

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Warning: $dir not found, skipping"
        continue
    fi
    find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -not -path "*/build/*" -exec clang-format -i {} \;
done

echo "Formatting complete!"
