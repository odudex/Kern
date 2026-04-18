#!/bin/bash

# Run all project tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Running bbqr tests..."
make -C "$REPO_ROOT/components/bbqr/test" run

echo "Running core tests..."
make -C "$REPO_ROOT/main/core/test" run

echo "All tests passed!"
