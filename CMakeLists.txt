cmake_minimum_required(VERSION 3.10)

project(EasyCPace LANGUAGES C VERSION 0.1.0)

# --- Standard Project Setup ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# --- Options ---
option(CPACE_BUILD_TESTS "Build unit tests using Unity" ON)
option(CPACE_BUILD_EXAMPLES "Build example programs" ON)
option(CPACE_USE_OPENSSL "Enable OpenSSL backend" ON)  # Default ON for now
option(CPACE_USE_MBEDTLS "Enable MbedTLS backend" ON) # Default ON for now

message(STATUS "Build configuration:")
message(STATUS "  Build Tests:    ${CPACE_BUILD_TESTS}")
message(STATUS "  Build Examples: ${CPACE_BUILD_EXAMPLES}")
message(STATUS "  Use OpenSSL:    ${CPACE_USE_OPENSSL}")
message(STATUS "  Use MbedTLS:    ${CPACE_USE_MBEDTLS}")

if(NOT CPACE_USE_OPENSSL AND NOT CPACE_USE_MBEDTLS)
    message(FATAL_ERROR "At least one backend (OpenSSL or MbedTLS) must be enabled.")
endif()

# --- Add Source Directory ---
# This will build the library (core + selected backends)
add_subdirectory(src)

# --- Add Public Include Directory ---
# Make include/easy_cpace.h available to users and examples/tests
target_include_directories(easy_cpace_core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include> # For installation
)

# --- Add Tests ---
if(CPACE_BUILD_TESTS)
    # Check if Unity is available (e.g., via submodule)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/vendor/unity/src/unity.c")
         message(WARNING "Unity test framework not found in tests/vendor/unity. Tests will be skipped. "
                         "Initialize submodules: git submodule update --init --recursive")
         set(CPACE_BUILD_TESTS OFF) # Disable tests if Unity not found
    else()
        enable_testing()
        add_subdirectory(tests)
    endif()
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
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # For shared libs on Windows
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
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
    "cmake/EasyCPaceConfig.cmake.in"
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

# Create cmake/EasyCPaceConfig.cmake.in (Needed for installation)
# Note: The actual file content is created separately using a SEARCH/REPLACE block
# This ensures the file exists for configure_package_config_file
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/cmake")
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EasyCPaceConfig.cmake.in")
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EasyCPaceConfig.cmake.in" "") # Create dummy if not exists
endif()
