#!/usr/bin/env bash
# Helper script to find OpenSSL include path in a cross-platform manner

set -euo pipefail

find_openssl_include_path() {
    # Try to find OpenSSL include path with various platform-specific methods
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew > /dev/null; then
        # macOS with Homebrew
        OPENSSL_INCLUDE="$(brew --prefix openssl@3)/include"
    elif command -v pkg-config > /dev/null && pkg-config --exists openssl; then
        # Use pkg-config (common on Linux)
        OPENSSL_INCLUDE="$(pkg-config --cflags-only-I openssl | sed 's/-I//')"
    elif [ -d "/usr/include/openssl" ]; then
        # Standard system location on many Linux distros
        OPENSSL_INCLUDE="/usr/include"
    else
        # Fallback
        OPENSSL_INCLUDE="/usr/local/include"
    fi
    
    echo "$OPENSSL_INCLUDE"
}

# Output the path when script is executed
find_openssl_include_path