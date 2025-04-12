# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test Commands
- `just build` - Build project with CMake and Ninja
- `just clean` - Remove build artifacts
- For a specific test: build with `-DCPACE_BUILD_TESTS=ON` flag, then run `ctest -R <test_name>`
- `cmake -DCMAKE_VERBOSE_MAKEFILE=ON -S . -B build && cmake --build build` - Alternative direct build

## Lint Commands
- `just lint` - Check code formatting and run clang-tidy
- `just lint-fix` - Fix formatting and linting issues automatically
- `just format-file <file>` - Format a specific file

## Code Style Guidelines
- C99 standard with LLVM style, 120 char line limit, 4-space indent
- Functions: `lowercase_with_underscores`
- Constants/Macros: `UPPERCASE_WITH_UNDERSCORES`
- Types: `lowercase_with_underscores_t` for typedef'd structs
- Doxygen comments for API functions with `@brief`, `@param`, `@return`
- Return error codes (`cpace_error_t`), positive for success
- Secure coding practices: constant-time implementations, buffer size checking, memory zeroing
- This is a C implementation for a cryptographic protocol. Hence methods needs to always be clearly documented in typical idiomatic way for C code, and always describe safety like memory, threading, etc.