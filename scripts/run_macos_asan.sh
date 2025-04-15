#!/bin/sh
# Script to run ASan tests on macOS with leak suppressions

# Set up environment for LeakSanitizer
export LSAN_OPTIONS="suppressions=$(dirname "$0")/../sanitizer_reports/macos_leak_suppressions.txt"

# Build with ASan and UBSan
just build-asan-ubsan

# Run tests with suppressions applied
cd build-asan-ubsan && ctest -V

echo "\nSanitizer tests complete."