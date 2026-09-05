#!/bin/bash

# Run all project tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd))"

echo "Running deflate_codec tests..."
make -C "$REPO_ROOT/components/deflate_codec/test" run

echo "Running bbqr tests..."
make -C "$REPO_ROOT/components/bbqr/test" run

echo "Running QR parser tests..."
make -C "$REPO_ROOT/main/qr/test" run

echo "Running core tests..."
make -C "$REPO_ROOT/main/core/test" run

echo "Running k_quirc tests..."
K_QUIRC_TEST_DIR="$REPO_ROOT/components/k_quirc/test"
cmake -S "$K_QUIRC_TEST_DIR" -B "$K_QUIRC_TEST_DIR/build" -DK_QUIRC_SANITIZE=OFF
cmake --build "$K_QUIRC_TEST_DIR/build" --parallel
ctest --test-dir "$K_QUIRC_TEST_DIR/build" --output-on-failure

echo "All tests passed!"
