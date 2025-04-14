#!/usr/bin/env bash
# Script to run sanitizer tests and generate reports

set -euo pipefail

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
RESET='\033[0m'

# Default settings
RUN_ASAN=true
RUN_UBSAN=true
RUN_TSAN=true
RUN_MSAN=false  # Default to false as MSan requires special setup
CONTINUE_ON_ERROR=false
VERBOSE=false
SKIP_BUILD=false
TEST_ONLY=false

# Directory to save reports
REPORT_DIR="sanitizer_reports"

# Function to display usage
usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -h, --help           Show this help message"
  echo "  -a, --asan           Run only AddressSanitizer"
  echo "  -u, --ubsan          Run only UndefinedBehaviorSanitizer"
  echo "  -t, --tsan           Run only ThreadSanitizer"
  echo "  -m, --msan           Run only MemorySanitizer (requires Clang)"
  echo "  -c, --continue       Continue running tests even if one fails"
  echo "  -v, --verbose        Show verbose output"
  echo "  -s, --skip-build     Skip the build step, use existing binaries"
  echo "  -T, --test-only      Run only the test step, skip examples and benchmarks"
  echo ""
  echo "By default, the script runs ASan, UBSan, and TSan (if no specific sanitizers are selected)."
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage
      exit 0
      ;;
    -a|--asan)
      RUN_ASAN=true
      RUN_UBSAN=false
      RUN_TSAN=false
      RUN_MSAN=false
      shift
      ;;
    -u|--ubsan)
      RUN_ASAN=false
      RUN_UBSAN=true
      RUN_TSAN=false
      RUN_MSAN=false
      shift
      ;;
    -t|--tsan)
      RUN_ASAN=false
      RUN_UBSAN=false
      RUN_TSAN=true
      RUN_MSAN=false
      shift
      ;;
    -m|--msan)
      RUN_ASAN=false
      RUN_UBSAN=false
      RUN_TSAN=false
      RUN_MSAN=true
      shift
      ;;
    -c|--continue)
      CONTINUE_ON_ERROR=true
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -s|--skip-build)
      SKIP_BUILD=true
      shift
      ;;
    -T|--test-only)
      TEST_ONLY=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# Create report directory
mkdir -p "$REPORT_DIR"

# Function to run a sanitizer test
run_sanitizer() {
  local name=$1
  local build_dir=$2
  local build_cmd=$3
  local test_cmd=$4
  local example_cmd=$5
  local options=$6
  local report_file="${REPORT_DIR}/${name}_report.txt"
  
  echo -e "${BLUE}============================================================${RESET}"
  echo -e "${BLUE}Running ${name}${RESET}"
  echo -e "${BLUE}============================================================${RESET}"
  
  # Build step
  if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}Building with ${name}...${RESET}"
    if $VERBOSE; then
      eval "$build_cmd"
    else
      eval "$build_cmd" > /dev/null
    fi
  fi
  
  # Test step
  echo -e "${YELLOW}Running tests with ${name}...${RESET}"
  {
    echo "============================================================"
    echo "${name} Test Results"
    echo "============================================================"
    echo "Date: $(date)"
    echo "Build command: $build_cmd"
    echo "Test command: $test_cmd"
    echo "Options: $options"
    echo "============================================================"
    echo ""
  } > "$report_file"
  
  set +e
  if $VERBOSE; then
    eval "$options $test_cmd" | tee -a "$report_file"
    TEST_RESULT=${PIPESTATUS[0]}
  else
    eval "$options $test_cmd" >> "$report_file" 2>&1
    TEST_RESULT=$?
  fi
  set -e
  
  # Run example and benchmark unless test_only is set
  if [ "$TEST_ONLY" = false ] && [ -n "$example_cmd" ]; then
    echo -e "${YELLOW}Running examples with ${name}...${RESET}"
    {
      echo ""
      echo "============================================================"
      echo "${name} Example Results"
      echo "============================================================"
      echo ""
    } >> "$report_file"
    
    set +e
    if $VERBOSE; then
      eval "$options $example_cmd" | tee -a "$report_file"
      EXAMPLE_RESULT=${PIPESTATUS[0]}
    else
      eval "$options $example_cmd" >> "$report_file" 2>&1
      EXAMPLE_RESULT=$?
    fi
    set -e
  else
    EXAMPLE_RESULT=0
  fi
  
  # Report result
  if [ $TEST_RESULT -eq 0 ] && [ $EXAMPLE_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ ${name} tests and examples passed${RESET}"
    {
      echo ""
      echo "============================================================"
      echo "RESULT: PASS - No issues detected"
      echo "============================================================"
    } >> "$report_file"
    return 0
  else
    echo -e "${RED}✗ ${name} detected issues - see ${report_file} for details${RESET}"
    {
      echo ""
      echo "============================================================"
      echo "RESULT: FAIL - Issues detected"
      echo "============================================================"
    } >> "$report_file"
    
    if [ "$CONTINUE_ON_ERROR" = false ]; then
      echo "Exiting due to errors. Use --continue to run all tests despite errors."
      exit 1
    fi
    return 1
  fi
}

# Run configured sanitizers
FAILURES=0

# ASan
if $RUN_ASAN; then
  run_sanitizer "AddressSanitizer" "build-asan" \
    "just build-asan" \
    "cd build-asan && ctest -V" \
    "just run-benchmark-asan" \
    "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1" || ((FAILURES++))
fi

# UBSan
if $RUN_UBSAN; then
  run_sanitizer "UndefinedBehaviorSanitizer" "build-ubsan" \
    "just build-ubsan" \
    "cd build-ubsan && ctest -V" \
    "just run-benchmark-ubsan" \
    "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1" || ((FAILURES++))
fi

# TSan
if $RUN_TSAN; then
  run_sanitizer "ThreadSanitizer" "build-tsan" \
    "just build-tsan" \
    "cd build-tsan && ctest -V" \
    "" \
    "TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1" || ((FAILURES++))
fi

# MSan
if $RUN_MSAN; then
  which clang > /dev/null 2>&1 || { echo "Error: clang is required for MSan but not found"; exit 1; }
  
  run_sanitizer "MemorySanitizer" "build-msan" \
    "just build-msan" \
    "cd build-msan && ctest -V" \
    "" \
    "MSAN_OPTIONS=halt_on_error=1" || ((FAILURES++))
fi

# Final summary
echo -e "${BLUE}============================================================${RESET}"
if [ $FAILURES -eq 0 ]; then
  echo -e "${GREEN}All sanitizer tests completed successfully!${RESET}"
else
  echo -e "${RED}$FAILURES sanitizer tests reported issues.${RESET}"
  echo -e "${YELLOW}Check the reports in the ${REPORT_DIR} directory.${RESET}"
fi
echo -e "${BLUE}============================================================${RESET}"

exit $FAILURES