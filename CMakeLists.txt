cmake_minimum_required(VERSION 3.27) # Increased version to cover policies

project(EasyCPace LANGUAGES C VERSION 0.1.0)

# Policies CMP0159, CMP0126, CMP0082 are implicitly NEW with version 3.27
# Explicitly set CMP0156 just in case minimum_required isn't fully propagating
cmake_policy(SET CMP0156 NEW)

# --- Standard Project Setup ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# --- Options ---
option(CPACE_BUILD_TESTS "Build unit tests using Unity" ON)
option(CPACE_BUILD_EXAMPLES "Build example programs" ON)
option(CPACE_ENABLE_DEBUG_LOGGING "Enable debug printf statements" OFF) # Debug logging option

message(STATUS "Build configuration:")
message(STATUS "  Build Tests:    ${CPACE_BUILD_TESTS}")
message(STATUS "  Build Examples: ${CPACE_BUILD_EXAMPLES}")
message(STATUS "  Backend:        Monocypher")

if(NOT CPACE_USE_OPENSSL AND NOT CPACE_USE_MBEDTLS)
    message(FATAL_ERROR "At least one backend (OpenSSL or MbedTLS) must be enabled.")
endif()

# --- Fetch Dependencies ---
include(FetchContent)

# Ensure CMake knows CMAKE_SYSTEM_NAME for backend logic
if(NOT CMAKE_SYSTEM_NAME)
    message(FATAL_ERROR "CMAKE_SYSTEM_NAME is not defined. Cannot determine OS for RNG.")
endif()
message(STATUS "Detected System: ${CMAKE_SYSTEM_NAME}")

# Monocypher (Example - add option later if creating backend)
FetchContent_Declare(
  monocypher
  GIT_REPOSITORY https://github.com/LoupVaillant/Monocypher.git
  GIT_TAG        4.0.2 # Use the specific tag requested
)
FetchContent_MakeAvailable(monocypher)

# Create a library target for Monocypher
# This makes it easier to link against if a backend is created.
# We compile the C file directly into this static library.
add_library(monocypher_lib STATIC
    ${monocypher_SOURCE_DIR}/src/monocypher.c
    ${monocypher_SOURCE_DIR}/src/monocypher.h
)
# Ensure consumers of monocypher_lib can find the header
target_include_directories(monocypher_lib PUBLIC
    ${monocypher_SOURCE_DIR}/src
)
# Optional: Add Ed25519 support if needed by a potential backend
# target_sources(monocypher_lib PRIVATE
#     ${monocypher_SOURCE_DIR}/src/optional/monocypher-ed25519.c
#     ${monocypher_SOURCE_DIR}/src/optional/monocypher-ed25519.h
# )


# --- Add Source Directory ---
# This will build the library (core + selected backends)
add_subdirectory(src)

# --- Add Tests ---
if(CPACE_BUILD_TESTS)
    # We're using FetchContent in tests/CMakeLists.txt to download Unity
    enable_testing()
    add_subdirectory(tests)
endif()

# --- Add Examples ---
if(CPACE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# --- Installation Rules (Basic Example) ---
include(GNUInstallDirs)
install(TARGETS easy_cpace_core # Install the actual core library target, not the alias
    EXPORT EasyCPaceTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}

    # For shared libs on Windows
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES include/easy_cpace.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Generate and install CMake package configuration files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/EasyCPaceConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)
export(EXPORT EasyCPaceTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/EasyCPaceTargets.cmake"
    NAMESPACE EasyCPace::
)
configure_package_config_file(
    # Use the source file location directly
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EasyCPaceConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/EasyCPaceConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/EasyCPace"
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/EasyCPaceConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/EasyCPaceConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/EasyCPace"
)
install(EXPORT EasyCPaceTargets
    FILE EasyCPaceTargets.cmake
    NAMESPACE EasyCPace::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/EasyCPace"
)
