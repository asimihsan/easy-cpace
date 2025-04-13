# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test Commands
- `just build` - Build project with CMake and Ninja
- `just clean` - Remove build artifacts
- `just test` - Build and run all tests
- For a specific test: build with `-DCPACE_BUILD_TESTS=ON` flag, then run `ctest -R <test_name> -V` for verbose output
- `cmake -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build && cmake --build build` - Alternative direct build

## Debugging Commands
- `just test-verbose` - Run tests with verbose output
- Create debug prints in C code with `printf("DEBUG: %s %zu\n", var, size)` and `fflush(stdout)`
- Use hexdump helpers for binary data:
```c
// Helper for debugging binary data
static void hexdump(const char* prefix, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", prefix, len);
    for(size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
    fflush(stdout);
}
```

## Lint Commands
- `just lint` - Check code formatting and run clang-tidy
- `just lint-fix` - Fix formatting and linting issues automatically
- `just format-file <file>` - Format a specific file

## Python Helpers
- Python scripts can be created using `hashlib` for independent hash verification:
```python
import hashlib
# Example SHA-512 hash verification
data_bytes = bytes.fromhex("hex_string_here")
hash_obj = hashlib.sha512()
hash_obj.update(data_bytes)
print(f"SHA-512: {hash_obj.hexdigest()}")
```

## Code Style Guidelines
- C99 standard with LLVM style, 120 char line limit, 4-space indent
- Functions: `lowercase_with_underscores`
- Constants/Macros: `UPPERCASE_WITH_UNDERSCORES`
- Types: `lowercase_with_underscores_t` for typedef'd structs
- Doxygen comments for API functions with `@brief`, `@param`, `@return`
- Return error codes (`cpace_error_t`), positive for success
- Secure coding practices: constant-time implementations, buffer size checking, memory zeroing
- This is a C implementation for a cryptographic protocol. Hence methods needs to always be clearly documented in typical idiomatic way for C code, and always describe safety like memory, threading, etc.