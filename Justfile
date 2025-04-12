build:
    mise x -- cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON --debug-output -S . -B build -G Ninja
    mise x -- cmake --build build

lint-fix:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]]; then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    # Make sure compile commands exist
    if [ ! -f "build/compile_commands.json" ]; then
        echo "Generating compile_commands.json first..."
        mise x -- cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build -G Ninja
    fi

    mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -i {}
    # Get OpenSSL include path from helper script
    OPENSSL_INCLUDE="$(./scripts/find_openssl.sh)"
    fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -fix -fix-errors -p=build {} -- -std=c99 -isystem${OPENSSL_INCLUDE}

lint:
    #!/usr/bin/env bash

    set -euo pipefail

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

    # Get OpenSSL include path from helper script
    OPENSSL_INCLUDE="$(./scripts/find_openssl.sh)"
    output=$(fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -p=build {} -- -std=c99 -isystem${OPENSSL_INCLUDE} 2>&1) || \
    (echo "⛔ Linting issues found:"; echo "$output"; exit 1)

# Format a specific file
format-file file:
    clang-format -i "{{file}}"

clean:
    rm -rf build
    rm -rf cmake-build-debug
