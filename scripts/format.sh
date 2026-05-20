#!/bin/bash

# Script to run clang-format on all .c and .h files in project source directories
# Covers main/ and first-party components (excludes libwally-core)

set -e

# Usage: ./scripts/format.sh [--check]
#   --check   Dry-run mode: exit 1 if any file needs formatting (for CI)

CHECK_MODE=false
if [ "${1:-}" = "--check" ]; then
    CHECK_MODE=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd))"

DIRS=(
    "$REPO_ROOT/main"
    "$REPO_ROOT/components/bbqr"
    "$REPO_ROOT/components/cUR"
    "$REPO_ROOT/components/k_quirc"
    "$REPO_ROOT/components/sd_card"
    "$REPO_ROOT/components/video"
    "$REPO_ROOT/components/wave_4b"
    "$REPO_ROOT/components/wave_35"
    "$REPO_ROOT/components/wave_43"
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
    done < <(find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -not -path "*/build/*" \
        -not -name "stb_image.h" \
        -print0)
done

if $CHECK_MODE && $FAILED; then
    echo "Format check failed!"
    exit 1
elif $CHECK_MODE; then
    echo "Format check passed!"
else
    echo "Formatting complete!"
fi
