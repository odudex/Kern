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

# clang-format's defaults drift between majors, so every host and CI must run
# the same one. 21 is the major ESP-IDF v6.1 ships as esp-clang.
CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"
REQUIRED_MAJOR=21
if ! command -v "$CLANG_FORMAT" >/dev/null 2>&1; then
    echo "error: $CLANG_FORMAT not found" >&2
    exit 1
fi
VERSION_LINE="$("$CLANG_FORMAT" --version)"
MAJOR="$(sed -n 's/.*clang-format version \([0-9]*\).*/\1/p' <<< "$VERSION_LINE")"
if [ "$MAJOR" != "$REQUIRED_MAJOR" ]; then
    echo "error: clang-format $REQUIRED_MAJOR required, found: $VERSION_LINE" >&2
    echo "  ESP-IDF: \$IDF_PATH/tools/idf_tools.py install esp-clang, then re-source export.sh" >&2
    echo "  pip:     pip install 'clang-format==$REQUIRED_MAJOR.1.*'" >&2
    echo "  Nix:     nix develop" >&2
    echo "  or set CLANG_FORMAT=/path/to/clang-format" >&2
    exit 1
fi

DIRS=(
    "$REPO_ROOT/main"
    "$REPO_ROOT/components/secure_memory"
    "$REPO_ROOT/components/bbqr"
    "$REPO_ROOT/components/bsp_common"
    "$REPO_ROOT/components/cUR"
    "$REPO_ROOT/components/deflate_codec"
    "$REPO_ROOT/components/k_quirc"
    "$REPO_ROOT/components/mbedtls_compat"
    "$REPO_ROOT/components/sd_card"
    "$REPO_ROOT/components/video"
    "$REPO_ROOT/components/wave_4b"
    "$REPO_ROOT/components/wave_35"
    "$REPO_ROOT/components/wave_43"
    "$REPO_ROOT/components/wave_5"
    "$REPO_ROOT/components/crowpanel"
    "$REPO_ROOT/components/wave_7b"
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
        if ! "$CLANG_FORMAT" $FORMAT_ARGS "$file"; then
            FAILED=true
        fi
    done < <(find "$dir" -type f \( -name "*.c" -o -name "*.h" \) -not -path "*/build/*" \
        -not -name "stb_image.h" \
        -print0)
done

for file in "$REPO_ROOT/components/libwally-core/kern_wally.c" \
            "$REPO_ROOT/components/libwally-core/kern_wally.h"; do
    if ! "$CLANG_FORMAT" $FORMAT_ARGS "$file"; then
        FAILED=true
    fi
done

if $CHECK_MODE && $FAILED; then
    echo "Format check failed!"
    exit 1
elif $CHECK_MODE; then
    echo "Format check passed!"
else
    echo "Formatting complete!"
fi
