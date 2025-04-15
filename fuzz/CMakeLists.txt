cmake_minimum_required(VERSION 3.15)

# Only proceed if fuzzers are enabled (already checked in root, but good practice)
# and Clang is the compiler (checked in root)
if(NOT CPACE_BUILD_FUZZERS OR NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    return()
endif()

message(STATUS "Configuring Fuzz Targets...")

# Helper function to define a fuzzer target
# Usage: add_cpace_fuzzer(target_name harness_source1.c [harness_source2.c ...])
function(add_cpace_fuzzer TARGET_NAME)
    # --- Argument Parsing ---
    set(HARNESS_SOURCES ${ARGN})
    if(NOT HARNESS_SOURCES)
        message(FATAL_ERROR "add_cpace_fuzzer requires at least one source file for target ${TARGET_NAME}")
    endif()

    message(STATUS "  Adding fuzzer: ${TARGET_NAME}")

    # --- Define Executable ---
    add_executable(${TARGET_NAME} ${HARNESS_SOURCES})

    # --- Compiler & Linker Flags ---
    # Combine fuzzer, ASan, and UBSan flags. This is the standard way.
    # -fsanitize=fuzzer implicitly includes address and undefined behavior sanitizers
    # when supported by the compiler (like modern Clang).
    set(FUZZER_FLAGS "-g" "-fsanitize=fuzzer")

    # Add flags specific to the fuzzer target
    target_compile_options(${TARGET_NAME} PRIVATE ${FUZZER_FLAGS})
    target_link_options(${TARGET_NAME} PRIVATE ${FUZZER_FLAGS})

    # --- Link Core Library ---
    # Link against the core cpace library.
    target_link_libraries(${TARGET_NAME} PRIVATE easy_cpace) # Alias to easy_cpace_core

    # --- Include Directories ---
    # Ensure the harness can find the public API and potentially internal headers
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include  # Public API (easy_cpace.h)
        ${CMAKE_SOURCE_DIR}/src      # Internal headers (e.g., common/utils.h)
    )

    # --- Optional: Debug Logging Definition ---
    # Propagate debug logging to fuzzer if enabled globally
    if(CPACE_ENABLE_DEBUG_LOGGING)
        target_compile_definitions(${TARGET_NAME} PRIVATE CPACE_DEBUG_LOG)
    endif()

    # --- Installation (Optional) ---
    # install(TARGETS ${TARGET_NAME} DESTINATION bin/fuzzers)

endfunction()

# --- Define Your Fuzz Targets ---
add_cpace_fuzzer(fuzz_protocol_inputs
    fuzz_protocol_inputs.c
)

# Add other fuzz targets here as needed...
# add_cpace_fuzzer(fuzz_another_component another_harness.c)
