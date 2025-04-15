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

# --- Sanitizer Options ---
option(CPACE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(CPACE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(CPACE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(CPACE_ENABLE_MSAN "Enable MemorySanitizer (Clang only)" OFF)
option(CPACE_ENABLE_LSAN "Enable LeakSanitizer standalone (Linux only)" OFF)

message(STATUS "Build configuration:")
message(STATUS "  Build Tests:    ${CPACE_BUILD_TESTS}")
message(STATUS "  Build Examples: ${CPACE_BUILD_EXAMPLES}")
message(STATUS "  Backend:        Monocypher")
message(STATUS "  ASan:           ${CPACE_ENABLE_ASAN}")
message(STATUS "  UBSan:          ${CPACE_ENABLE_UBSAN}")
message(STATUS "  TSan:           ${CPACE_ENABLE_TSAN}")
message(STATUS "  MSan:           ${CPACE_ENABLE_MSAN}")
message(STATUS "  LSan:           ${CPACE_ENABLE_LSAN}")

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
# Ensure consumers of monocypher_lib can find the headers within the build tree
target_include_directories(monocypher_lib PUBLIC
    $<BUILD_INTERFACE:${monocypher_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${monocypher_SOURCE_DIR}/src/optional>
)
# Add Ed25519 support needed by the Monocypher backend for SHA512
target_sources(monocypher_lib PRIVATE
    ${monocypher_SOURCE_DIR}/src/optional/monocypher-ed25519.c
    ${monocypher_SOURCE_DIR}/src/optional/monocypher-ed25519.h
)


# --- Sanitizer Configuration ---
set(SANITIZER_FLAGS "")
set(SANITIZER_ENABLED FALSE)
set(SANITIZER_INCOMPATIBLE_FLAGS FALSE)

# Common options for sanitizer builds
list(APPEND SANITIZER_FLAGS "-g" "-fno-omit-frame-pointer")

if(CPACE_ENABLE_ASAN)
    if(SANITIZER_INCOMPATIBLE_FLAGS)
        message(FATAL_ERROR "ASan cannot be enabled with TSan or MSan")
    endif()
    message(STATUS "Configuring AddressSanitizer")
    list(APPEND SANITIZER_FLAGS "-fsanitize=address")
    
    # Add suppression file for macOS
    if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/sanitizer_reports")
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/sanitizer_reports/macos_leak_suppressions.txt")
            file(WRITE "${CMAKE_SOURCE_DIR}/sanitizer_reports/macos_leak_suppressions.txt"
                "# Suppress macOS Objective-C runtime leaks that are false positives\n"
                "leak:*libobjc.A.dylib*\n"
                "leak:*libsystem_malloc.dylib*\n"
                "leak:*libdispatch.dylib*\n"
                "leak:*CoreFoundation*\n"
                "leak:*Foundation*\n"
            )
        endif()
        message(STATUS "Using leak suppressions for macOS")
        set(ENV{LSAN_OPTIONS} "suppressions=${CMAKE_SOURCE_DIR}/sanitizer_reports/macos_leak_suppressions.txt")
    endif()
    
    set(SANITIZER_ENABLED TRUE)
    set(SANITIZER_INCOMPATIBLE_FLAGS TRUE)
endif()

if(CPACE_ENABLE_UBSAN)
    message(STATUS "Configuring UndefinedBehaviorSanitizer")
    list(APPEND SANITIZER_FLAGS "-fsanitize=undefined")
    set(SANITIZER_ENABLED TRUE)
endif()

if(CPACE_ENABLE_TSAN)
    if(SANITIZER_INCOMPATIBLE_FLAGS)
        message(FATAL_ERROR "TSan cannot be enabled with ASan or MSan")
    endif()
    message(STATUS "Configuring ThreadSanitizer")
    list(APPEND SANITIZER_FLAGS "-fsanitize=thread")
    set(SANITIZER_ENABLED TRUE)
    set(SANITIZER_INCOMPATIBLE_FLAGS TRUE)
endif()

if(CPACE_ENABLE_MSAN)
    if(SANITIZER_INCOMPATIBLE_FLAGS)
        message(FATAL_ERROR "MSan cannot be enabled with ASan or TSan")
    endif()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "MSan requires Clang compiler")
    endif()
    message(STATUS "Configuring MemorySanitizer")
    list(APPEND SANITIZER_FLAGS "-fsanitize=memory")
    list(APPEND SANITIZER_FLAGS "-fsanitize-memory-track-origins=2")
    set(SANITIZER_ENABLED TRUE)
    set(SANITIZER_INCOMPATIBLE_FLAGS TRUE)
endif()

if(CPACE_ENABLE_LSAN)
    if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
        message(FATAL_ERROR "Standalone LeakSanitizer is only available on Linux")
    endif()
    if(CPACE_ENABLE_ASAN)
        message(WARNING "LeakSanitizer is already included in ASan, ignoring CPACE_ENABLE_LSAN")
    else()
        message(STATUS "Configuring LeakSanitizer")
        list(APPEND SANITIZER_FLAGS "-fsanitize=leak")
        set(SANITIZER_ENABLED TRUE)
    endif()
endif()

if(SANITIZER_ENABLED)
    message(STATUS "Adding sanitizer flags: ${SANITIZER_FLAGS}")
    add_compile_options(${SANITIZER_FLAGS})
    add_link_options(${SANITIZER_FLAGS})
endif()

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
install(TARGETS easy_cpace_core monocypher_lib # Install the core library and its dependency
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
