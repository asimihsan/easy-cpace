#!/usr/bin/env bash

# Script to run ASan tests on macOS with leak suppressions

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
pushd "$ROOT_DIR" > /dev/null
trap 'popd > /dev/null' EXIT

# Set up environment for LeakSanitizer
export LSAN_OPTIONS="suppressions=./sanitizer_reports/macos_leak_suppressions.txt"

# Build with ASan and UBSan
just build-asan-ubsan

# Run tests with suppressions applied
cd build-asan-ubsan && mise x -- ctest -V

printf "\nSanitizer tests complete."
