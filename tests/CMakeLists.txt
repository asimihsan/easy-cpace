# tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

# --- Unity Test Framework ---
# Add Unity source file (assuming it's in vendor/unity/src relative to this CMakeLists.txt)
# Check if the source file exists first.
if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/unity/src/unity.c")
    message(FATAL_ERROR "Unity source not found in tests/vendor/unity/src. "
            "Please ensure the submodule is initialized: git submodule update --init --recursive")
endif ()

add_library(unity STATIC
        vendor/unity/src/unity.c
        # Add fixture support if you plan to use it later:
        # vendor/unity/src/unity_fixture.c
)
target_include_directories(unity PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/unity/src>
        # For unity_fixture.h if used:
        # $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/unity/src>
)


# needed if you have a local unity_config.h
# target_compile_definitions(unity PUBLIC UNITY_INCLUDE_CONFIG_H)

# --- Test Runner Executable ---
add_executable(cpace_test_runner
        test_runner.c       # Main test runner entry point
        test_cpace_api.c    # Test cases for the public API and flow
        test_cpace_vectors.c # Test cases for RFC vectors
)

# Link the test runner against our library and Unity
target_link_libraries(cpace_test_runner PRIVATE
        easy_cpace_core # Link against the actual core library target
        unity
)

# Include directories needed by tests (e.g., to see easy_cpace.h)
# The easy_cpace_core target should propagate its public include dirs,
# but we might need project source include if tests need internal headers.
target_include_directories(cpace_test_runner PRIVATE
        # Access to easy_cpace.h (should be inherited via linking easy_cpace_core)
        # ${CMAKE_SOURCE_DIR}/include
        # Access to internal headers if needed (e.g., test helpers might need crypto_provider.h)
        # ${CMAKE_SOURCE_DIR}/src

        # Explicitly add Unity includes here in case propagation fails
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor/unity/src
)


# --- Register with CTest ---
# Add the test runner executable to CTest
add_test(NAME EasyCPaceTests COMMAND cpace_test_runner)

message(STATUS "Unity tests configured. Run with 'ctest' or 'just test'.")

# Optional: Add a custom target to run tests via 'make test' or 'ninja test'
# This depends on enable_testing() being called in the root CMakeLists.txt (which it is).
# The command 'ctest' will already work in the build directory.
