cmake_minimum_required(VERSION 3.10)

# Define the object library for the Monocypher backend
add_library(cpace_backend_monocypher OBJECT
        monocypher_backend.c
)

# Public include directories needed by the backend implementation
target_include_directories(cpace_backend_monocypher PUBLIC
        # Allow backend to see interfaces and common utils
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
        # Allow backend to see the public API header
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        # Allow backend to see the Monocypher headers (via the interface target)
        # The monocypher_lib target should propagate its include directory.
        # If not, uncomment the line below after checking the monocypher target definition.
        # $<TARGET_PROPERTY:monocypher_lib,INTERFACE_INCLUDE_DIRECTORIES>
)

# Link the backend object library against Monocypher
# This isn't strictly necessary for OBJECT libraries but clarifies dependency
target_link_libraries(cpace_backend_monocypher INTERFACE monocypher_lib)

# Add compile definition for debug logging if enabled globally
if(CPACE_ENABLE_DEBUG_LOGGING)
    target_compile_definitions(cpace_backend_monocypher PRIVATE CPACE_DEBUG_LOG)
endif()

# Platform-specific RNG source (Example for POSIX/Windows)
# Add more specific checks if needed (e.g., __linux__, __APPLE__, _WIN32)
if(UNIX OR APPLE)
    message(STATUS "Monocypher backend: Using POSIX RNG (/dev/urandom)")
    # No extra source file needed, handled within monocypher_backend.c via #ifdef
elseif(WIN32)
    message(STATUS "Monocypher backend: Using Windows RNG (BCryptGenRandom)")
    # No extra source file needed, handled within monocypher_backend.c via #ifdef
    # Link against bcrypt.lib if using BCryptGenRandom
    target_link_libraries(cpace_backend_monocypher INTERFACE bcrypt) # Link bcrypt to consumers
else()
    message(WARNING "Monocypher backend: No specific OS RNG implementation found for
${CMAKE_SYSTEM_NAME}. Random number generation will fail.")
    # Define a placeholder or error macro if desired
    target_compile_definitions(cpace_backend_monocypher PRIVATE CPACE_NO_OS_RNG)
endif()
