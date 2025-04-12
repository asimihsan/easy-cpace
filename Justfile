build:
    mise x -- cmake -DCMAKE_VERBOSE_MAKEFILE=ON --debug-output -S . -B build -G Ninja
    mise x -- cmake --build build

lint-fix:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]]; then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -i {}
    fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy -fix {} -- -std=c99

lint:
    #!/usr/bin/env bash

    set -euo pipefail

    if [[ "$OSTYPE" == "darwin"* ]]; then
        export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    fi

    output=$(mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -n -Werror {} 2>&1) || \
    (echo "⛔ Formatting issues found:"; echo "$output"; exit 1)
    echo "✅ All files correctly formatted."

    output=$(fd -e c -e h -E "build/" -E "third_party/" . -x clang-tidy {} -- -std=c99 2>&1) || \
    (echo "⛔ Linting issues found:"; echo "$output"; exit 1)

# Format a specific file
format-file file:
    clang-format -i "{{file}}"

clean:
    rm -rf build
    rm -rf cmake-build-debug
