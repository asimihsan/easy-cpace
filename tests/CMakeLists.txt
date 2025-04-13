# tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.14) # Ensure modern CMake for FetchContent

# --- Unity Test Framework using FetchContent ---
include(FetchContent)

# Define the Unity repository and version to use
FetchContent_Declare(
  unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG        v2.6.0  # Use a specific, stable version
)

# Make Unity available - need to handle it manually as it doesn't have a CMakeLists.txt
FetchContent_GetProperties(unity)
if(NOT unity_POPULATED)
  FetchContent_Populate(unity)
  
  # Create a library target for Unity
  add_library(unity STATIC
    ${unity_SOURCE_DIR}/src/unity.c
  )
  
  target_include_directories(unity PUBLIC
    ${unity_SOURCE_DIR}/src
  )
endif()

# Add helper function for defining tests
function(add_unity_test TEST_NAME)
  # Parse arguments
  cmake_parse_arguments(TEST "" "SUITE" "SOURCES;LINK_LIBS" ${ARGN})
  
  set(RUNNER_TARGET "test_${TEST_NAME}")
  set(TEST_LABEL "${TEST_SUITE}")
  
  # Define the executable
  add_executable(${RUNNER_TARGET} ${TEST_SOURCES})
  
  # Link common dependencies
  target_link_libraries(${RUNNER_TARGET} PRIVATE
    unity
    ${TEST_LINK_LIBS}
  )
  
  # Ensure include paths are set
  target_include_directories(${RUNNER_TARGET} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src     # For internal headers if needed
  )
  
  # Register with CTest
  add_test(NAME ${TEST_NAME} COMMAND ${RUNNER_TARGET})
  set_property(TEST ${TEST_NAME} PROPERTY LABELS "${TEST_LABEL}")
endfunction()

# --- Test helper for running a test with setup/teardown ---
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/unity_test_helpers.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/unity_test_helpers.h
  @ONLY
)

# --- Define API Tests ---
add_unity_test(cpace_api
  SUITE "API"
  SOURCES
    test_api_runner.c
    test_cpace_api.c
  LINK_LIBS
    easy_cpace_core
)

target_include_directories(test_cpace_api PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}  # For generated unity_test_helpers.h
)

# --- Define Vector Tests ---
add_unity_test(cpace_vectors
  SUITE "Vectors"
  SOURCES
    test_vectors_runner.c
    test_cpace_vectors.c
  LINK_LIBS
    easy_cpace_core
)

target_include_directories(test_cpace_vectors PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}  # For generated unity_test_helpers.h
)

message(STATUS "Unity tests configured. Run with 'ctest' or 'just test'.")
