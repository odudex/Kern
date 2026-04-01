#!/bin/bash

# Script to run clang-format on all .c and .h files in project source directories
# Covers main/ and first-party components (excludes libwally-core)

set -e

# Usage: ./format.sh [--check]
#   --check   Dry-run mode: exit 1 if any file needs formatting (for CI)

CHECK_MODE=false
if [ "${1:-}" = "--check" ]; then
    CHECK_MODE=true
fi

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

if $CHECK_MODE; then
    echo "Checking clang-format on project source files..."
    FORMAT_ARGS="--dry-run -Werror"
else
    echo "Running clang-format on project source files..."
    FORMAT_ARGS="-i"
fi

FAILED=false

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Warning: $dir not found, skipping"
        continue
    fi
    while IFS= read -r -d '' file; do
        if ! clang-format $FORMAT_ARGS "$file"; then
            FAILED=true
        fi
    done < <(find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -not -path "*/build/*" -print0)
done

if $CHECK_MODE && $FAILED; then
    echo "Format check failed!"
    exit 1
elif $CHECK_MODE; then
    echo "Format check passed!"
else
    echo "Formatting complete!"
fi
