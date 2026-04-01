#!/bin/bash

# Run all project tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Running bbqr tests..."
make -C "$SCRIPT_DIR/components/bbqr/test" run

echo "All tests passed!"
