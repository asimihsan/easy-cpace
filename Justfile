default:
  @just --list

setup:
    #!/usr/bin/env bash
    set -euo pipefail

    mise trust
    mise install
    mise x -- uv venv
    mise x -- uv sync

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "Installing clang tools on Linux..."
        sudo apt-get update
        sudo apt-get install -y clang-format clang-tidy
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "Installing clang tools on macOS..."
        brew install llvm
        echo "LLVM tools installed at: $(brew --prefix llvm)/bin"
        echo "Add this to your PATH if not already included"
    else
        echo "Unsupported platform for automatic clang tools installation"
        echo "Please install clang-format and clang-tidy manually"
    fi

build:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON --debug-output -S . -B build -G Ninja
    mise x -- cmake --build build

build-debug-logging:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON --debug-output -S . -B build -G Ninja -DCPACE_ENABLE_DEBUG_LOGGING=ON
    mise x -- cmake --build build

# Build fuzz targets (requires Clang)
build-fuzz:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]];
    then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi
    
    # Ensure Clang is available
    if ! command -v clang &> /dev/null; then
        echo "⛔ Error: clang compiler is required for fuzzing but not found."
        echo "Please install Clang or ensure it's in your PATH."
        exit 1
    fi
    
    # Configure and build with fuzzing enabled
    # Note: Fuzzer flags include ASan/UBSan by default in fuzz/CMakeLists.txt
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON \
        -S . -B build-fuzz -G Ninja \
        -DCPACE_BUILD_FUZZERS=ON \
        -DCMAKE_C_COMPILER=clang
    mise x -- cmake --build build-fuzz

# --- Sanitizer Builds ---
build-asan:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build-asan -G Ninja -DCPACE_ENABLE_ASAN=ON
    mise x -- cmake --build build-asan

build-ubsan:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build-ubsan -G Ninja -DCPACE_ENABLE_UBSAN=ON
    mise x -- cmake --build build-ubsan

build-tsan:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build-tsan -G Ninja -DCPACE_ENABLE_TSAN=ON
    mise x -- cmake --build build-tsan

build-msan:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Make sure we are using clang for MSan
    if ! command -v clang &> /dev/null; then
        echo "Error: clang is required for MSan but not found in PATH"
        exit 1
    fi
    
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build-msan -G Ninja -DCPACE_ENABLE_MSAN=ON -DCMAKE_C_COMPILER=clang
    mise x -- cmake --build build-msan

# Combined sanitizer build (ASan + UBSan is a common combination)
build-asan-ubsan:
    mise x -- cmake -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build-asan-ubsan -G Ninja -DCPACE_ENABLE_ASAN=ON -DCPACE_ENABLE_UBSAN=ON
    mise x -- cmake --build build-asan-ubsan

test:
    cd build && mise x -- ctest -V

# --- Sanitizer Tests ---
test-asan:
    cd build-asan && mise x -- ctest -V

test-ubsan:
    cd build-ubsan && mise x -- ctest -V

test-tsan:
    cd build-tsan && mise x -- ctest -V

test-msan:
    cd build-msan && mise x -- ctest -V

test-asan-ubsan:
    cd build-asan-ubsan && mise x -- ctest -V

run-basic-exchange:
    mise x -- ./build/examples/basic_exchange

run-benchmark:
    mise x -- hyperfine --warmup 3 \
        ./build/examples/benchmark

run-benchmark-asan:
    ASAN_OPTIONS=detect_leaks=1 mise x -- ./build-asan/examples/benchmark

run-benchmark-ubsan:
    mise x -- ./build-ubsan/examples/benchmark

run-benchmark-asan-ubsan:
    ASAN_OPTIONS=detect_leaks=1 mise x -- ./build-asan-ubsan/examples/benchmark

# Run a specific fuzzer target
# Usage: just run-fuzzer <fuzzer_name> [fuzzer_args...]
# Example: just run-fuzzer fuzz_protocol_inputs
run-fuzzer fuzzer_name +fuzzer_args='':
    #!/usr/bin/env bash
    set -euo pipefail

    FUZZER_EXE="./build-fuzz/fuzz/{{fuzzer_name}}"
    CORPUS_DIR="./corpus/{{fuzzer_name}}"
    CRASH_DIR="./crashes/{{fuzzer_name}}"

    if [ ! -f "$FUZZER_EXE" ]; then
        echo "⛔ Error: Fuzzer executable '$FUZZER_EXE' not found."
        echo "Run 'just build-fuzz' first."
        exit 1
    fi

    # Create directories if they don't exist
    mkdir -p "$CORPUS_DIR"
    mkdir -p "$CRASH_DIR"

    echo "🚀 Starting fuzzer '{{fuzzer_name}}'..."
    echo "   Corpus: $CORPUS_DIR"
    echo "   Crashes: $CRASH_DIR"
    echo "   Args: {{fuzzer_args}}"

    # Run the fuzzer. Pass corpus dir first, then optional seeds/args.
    # Use -artifact_prefix to store crashes in a dedicated directory.
    "$FUZZER_EXE" "$CORPUS_DIR" -artifact_prefix="$CRASH_DIR/" {{fuzzer_args}}

# Run the main protocol input fuzzer
fuzz: build-fuzz
    @just run-fuzzer fuzz_protocol_inputs

lint-fix:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]];
    then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    # Check if clang-format and clang-tidy are installed
    if ! command -v clang-format &> /dev/null; then
        echo "⛔ Error: clang-format is not installed or not in PATH"
        echo "Run 'just setup' to install required tools"
        exit 1
    fi

    if ! command -v clang-tidy &> /dev/null; then
        echo "⛔ Error: clang-tidy is not installed or not in PATH"
        echo "Run 'just setup' to install required tools"
        exit 1
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    # Make sure compile commands exist
    if [ ! -f "build/compile_commands.json" ]; then
        echo "Generating compile_commands.json first..."
        mise x -- cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build -G Ninja
    fi

    mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -i {}
    # Include paths for Unity are needed for clang-tidy
    UNITY_INCLUDE="${PWD}/build/_deps/unity-src/src"
    UNITY_HELPERS_INCLUDE="${PWD}/build/tests"
    # Also explicitly include Monocypher headers
    MONOCYPHER_INCLUDE="${PWD}/build/_deps/monocypher-src/src"
    MONOCYPHER_OPTIONAL_INCLUDE="${PWD}/build/_deps/monocypher-src/src/optional"
    # Include path for easy_cpace.h
    PROJECT_INCLUDE="${PWD}/include"
    # Run clang-tidy with all include paths
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # On macOS, add system includes path
        SDK_PATH=$(xcrun --show-sdk-path)
        fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -fix -fix-errors -p=build {} -- -std=c99 -I${PROJECT_INCLUDE} -isystem${UNITY_INCLUDE} -isystem${UNITY_HELPERS_INCLUDE} -isystem${MONOCYPHER_INCLUDE} -isystem${MONOCYPHER_OPTIONAL_INCLUDE} -isystem${SDK_PATH}/usr/include
    else
        # Regular path for other platforms
        fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -fix -fix-errors -p=build {} -- -std=c99 -I${PROJECT_INCLUDE} -isystem${UNITY_INCLUDE} -isystem${UNITY_HELPERS_INCLUDE} -isystem${MONOCYPHER_INCLUDE} -isystem${MONOCYPHER_OPTIONAL_INCLUDE}
    fi

lint:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]];
    then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    # Check if clang-format and clang-tidy are installed
    if ! command -v clang-format &> /dev/null; then
        echo "⛔ Error: clang-format is not installed or not in PATH"
        echo "Run 'just setup' to install required tools"
        exit 1
    fi

    if ! command -v clang-tidy &> /dev/null; then
        echo "⛔ Error: clang-tidy is not installed or not in PATH"
        echo "Run 'just setup' to install required tools"
        exit 1
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    # Make sure compile commands exist
    if [ ! -f "build/compile_commands.json" ]; then
        echo "Generating compile_commands.json first..."
        mise x -- cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build -G Ninja
    fi

    output=$(mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -n -Werror {} 2>&1) || \
    (echo "⛔ Formatting issues found:"; echo "$output"; exit 1)
    echo "✅ All files correctly formatted."

    # Include paths for Unity are needed for clang-tidy
    UNITY_INCLUDE="${PWD}/build/_deps/unity-src/src"
    UNITY_HELPERS_INCLUDE="${PWD}/build/tests"
    # Also explicitly include Monocypher headers
    MONOCYPHER_INCLUDE="${PWD}/build/_deps/monocypher-src/src"
    MONOCYPHER_OPTIONAL_INCLUDE="${PWD}/build/_deps/monocypher-src/src/optional"
    # Include path for easy_cpace.h
    PROJECT_INCLUDE="${PWD}/include"
    # Run clang-tidy with all include paths
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # On macOS, add system includes path
        SDK_PATH=$(xcrun --show-sdk-path)
        output=$(fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -p=build {} -- -std=c99 -I${PROJECT_INCLUDE} -isystem${UNITY_INCLUDE} -isystem${UNITY_HELPERS_INCLUDE} -isystem${MONOCYPHER_INCLUDE} -isystem${MONOCYPHER_OPTIONAL_INCLUDE} -isystem${SDK_PATH}/usr/include 2>&1) || \
        (echo "⛔ Linting issues found:"; echo "$output"; exit 1)
    else
        # Regular path for other platforms
        output=$(fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -p=build {} -- -std=c99 -I${PROJECT_INCLUDE} -isystem${UNITY_INCLUDE} -isystem${UNITY_HELPERS_INCLUDE} -isystem${MONOCYPHER_INCLUDE} -isystem${MONOCYPHER_OPTIONAL_INCLUDE} 2>&1) || \
        (echo "⛔ Linting issues found:"; echo "$output"; exit 1)
    fi

# Format a specific file
format-file file:
    clang-format -i "{{file}}"

clean:
    rm -rf build build-asan build-ubsan build-tsan build-msan build-asan-ubsan build-fuzz
    rm -rf corpus crashes
    rm -rf cmake-build-debug

clean-build-test: clean build test

copyright:
    mise x -- bash -c 'fd -e c -e h -e py | xargs addlicense -f copyright.tmpl -c "Asim Ihsan" -v -s'

copyright-check:
    mise x -- bash -c 'fd -e c -e h -e py | xargs addlicense -f copyright.tmpl -c "Asim Ihsan" -v -s -check'

# --- Combined Sanitizer Workflow Targets ---
# Build and test with ASan
asan: build-asan test-asan

# Build and test with UBSan
ubsan: build-ubsan test-ubsan

# Build and test with ASan + UBSan (common combination)
asan-ubsan: build-asan-ubsan test-asan-ubsan

# Build and test with TSan
tsan: build-tsan test-tsan

# Build and test with MSan
msan: build-msan test-msan

# Run all CI checks (build, test, lint, benchmark)
ci: clean build lint test run-benchmark

# Run CI with sanitizers (ASan + UBSan)
ci-sanitizers: lint build-asan-ubsan test-asan-ubsan run-benchmark

ci-sanitizers-mac: clean build lint test macos-asan-test run-benchmark

# Run all sanitizers and generate reports
sanitizers:
    ./scripts/run_sanitizers.sh

# Run specific sanitizers
sanitizers-asan:
    ./scripts/run_sanitizers.sh --asan

sanitizers-ubsan:
    ./scripts/run_sanitizers.sh --ubsan

sanitizers-tsan:
    ./scripts/run_sanitizers.sh --tsan

sanitizers-msan:
    ./scripts/run_sanitizers.sh --msan

# Run sanitizers with verbose output
sanitizers-verbose:
    ./scripts/run_sanitizers.sh --verbose
    
# macOS-specific sanitizer test with suppression for libobjc/Darwin framework leaks
# This is required because on macOS, the Objective-C runtime and Darwin frameworks
# have expected memory leaks that are not actual leaks in the application code
macos-asan-test:
    ./scripts/run_macos_asan.sh
