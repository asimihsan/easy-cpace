# Sanitizers in EasyCPace

This document describes how to use sanitizers with the EasyCPace project to detect memory errors, undefined behavior, race conditions, and other runtime issues.

## Available Sanitizers

EasyCPace supports the following sanitizers:

1. **AddressSanitizer (ASan)** - Detects memory errors such as:
   - Use-after-free
   - Heap/stack/global buffer overflow
   - Use-after-return
   - Memory leaks

2. **UndefinedBehaviorSanitizer (UBSan)** - Detects undefined behavior such as:
   - Signed integer overflow
   - Null pointer dereferences
   - Misaligned memory accesses
   - Array bounds violations

3. **ThreadSanitizer (TSan)** - Detects race conditions and deadlocks in multi-threaded code.

4. **MemorySanitizer (MSan)** - Detects uninitialized memory reads (requires Clang).

5. **LeakSanitizer (LSan)** - Detects memory leaks (included in ASan, but can be used standalone on Linux).

## Using Sanitizers

### Quick Start

The easiest way to run the sanitizers is to use the provided `just` targets:

```bash
# Run all sanitizers and generate reports
just sanitizers

# Run only AddressSanitizer
just sanitizers-asan

# Run only UndefinedBehaviorSanitizer
just sanitizers-ubsan

# Run only ThreadSanitizer
just sanitizers-tsan

# Run sanitizers with verbose output
just sanitizers-verbose
```

### Building with Sanitizers

You can also build the project with specific sanitizers:

```bash
# Build with AddressSanitizer
just build-asan

# Build with UndefinedBehaviorSanitizer
just build-ubsan

# Build with ThreadSanitizer
just build-tsan

# Build with MemorySanitizer (requires Clang)
just build-msan

# Build with both AddressSanitizer and UndefinedBehaviorSanitizer
just build-asan-ubsan
```

### Running Tests with Sanitizers

After building with sanitizers, you can run the tests:

```bash
# Run tests with AddressSanitizer
just test-asan

# Run tests with UndefinedBehaviorSanitizer
just test-ubsan

# Run tests with ThreadSanitizer
just test-tsan

# Run tests with MemorySanitizer
just test-msan

# Run tests with both AddressSanitizer and UndefinedBehaviorSanitizer
just test-asan-ubsan
```

### Running Benchmarks with Sanitizers

```bash
# Run benchmark with AddressSanitizer
just run-benchmark-asan

# Run benchmark with UndefinedBehaviorSanitizer
just run-benchmark-ubsan

# Run benchmark with both AddressSanitizer and UndefinedBehaviorSanitizer
just run-benchmark-asan-ubsan
```

### Combined Workflow Targets

The following targets build and test in a single command:

```bash
# Build and test with ASan
just asan

# Build and test with UBSan
just ubsan

# Build and test with ASan + UBSan
just asan-ubsan

# Build and test with TSan
just tsan

# Build and test with MSan
just msan

# Run all CI checks with sanitizers
just ci-sanitizers
```

## Advanced Usage

### Manual CMake Configuration

You can also manually configure CMake with sanitizer options:

```bash
# Configure with AddressSanitizer
cmake -S . -B build-custom -DCPACE_ENABLE_ASAN=ON

# Configure with multiple sanitizers
cmake -S . -B build-custom -DCPACE_ENABLE_ASAN=ON -DCPACE_ENABLE_UBSAN=ON

# Build the configured project
cmake --build build-custom
```

### Sanitizer Runtime Options

You can control sanitizer behavior at runtime using environment variables:

```bash
# AddressSanitizer options
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./build-asan/tests/test_runner

# UndefinedBehaviorSanitizer options
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./build-ubsan/tests/test_runner

# ThreadSanitizer options
TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 ./build-tsan/tests/test_runner

# MemorySanitizer options
MSAN_OPTIONS=halt_on_error=1 ./build-msan/tests/test_runner
```

## Sanitizer Reports

When using the `sanitizers` target, reports are saved in the `sanitizer_reports` directory. These reports contain detailed information about any issues detected by the sanitizers.

## Compatibility Notes

1. **ASan, MSan, and TSan are mutually exclusive** - You cannot use them together in the same build.
2. **UBSan can be combined** with any other sanitizer.
3. **MSan requires Clang** - GCC does not fully support MemorySanitizer.
4. **LSan as a standalone tool** is only available on Linux.
5. **Platform compatibility** - All sanitizers work on Linux. On macOS, ASan, UBSan, and TSan are well-supported, but MSan may have limitations.

## Troubleshooting

### Common Issues

1. **False positives in third-party code** - Sometimes sanitizers can report issues in dependencies. You can use suppression files or focus on issues in your own code.

2. **Missing symbolization** - If you see raw addresses instead of source locations, make sure you have debugging symbols enabled and tools like `llvm-symbolizer` are in your PATH.

3. **MSan false positives** - MemorySanitizer requires that all code, including system libraries, is instrumented. If you see many false positives, you might need a custom-built instrumented stdlib.

### Environment Setup

Ensure your environment is correctly set up:

- Make sure you have a recent compiler version (GCC 7+ or Clang 6+)
- For MSan on macOS, you'll need Clang from Homebrew or LLVM's website
- The debug symbols are needed for good error reports (`-g` flag, enabled by default)