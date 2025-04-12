build:
    mise x -- cmake -B build -S .

lint-fix:
    mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -i {}

lint:
    #!/usr/bin/env bash
    set -eu
    output=$(mise x -- fd -e c -e h -E "build/" -E "third_party/" . -x clang-format -n -Werror {} 2>&1) || \
    (echo "⛔ Formatting issues found:"; echo "$output"; exit 1)
    echo "✅ All files correctly formatted."

# Format a specific file
format-file file:
    clang-format -i "{{file}}"
