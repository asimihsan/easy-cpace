cmake_minimum_required(VERSION 3.10) # Add if not already present

# --- Find Dependencies (Conditionally) ---
# Find dependencies at this level to ensure targets are available in this scope
if(CPACE_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    message(STATUS "Found OpenSSL in src scope for linking")
endif()

# MbedTLS dependency is still found within its backend subdirectory
# but we should move that here too for consistency

# Example for MbedTLS if it were needed here (it's not currently, find is moved):
# if(CPACE_USE_MBEDTLS)
#    find_package(MbedTLS REQUIRED COMPONENTS crypto psa)
# endif()

# Placeholder for MbedTLS message if find_package were here
if(CPACE_USE_MBEDTLS)
    # We still need to find MbedTLS if the backend is enabled,
    # but we'll do it inside its own CMakeLists.txt for consistency.
    # message(STATUS "MbedTLS will be sought in its backend directory.")
    # For now, just ensure the message reflects reality if MbedTLS is enabled:
    message(STATUS "MbedTLS found in src scope for linking.")
endif()

# --- Common Utilities ---
add_library(cpace_common OBJECT
    common/utils.c
)
target_include_directories(cpace_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # Allow utils to see crypto_iface
)
# Enable debug logging for this component if requested globally
if(CPACE_ENABLE_DEBUG_LOGGING)
    target_compile_definitions(cpace_common PRIVATE CPACE_DEBUG_LOG)
endif()

# --- Core Protocol Logic ---
add_library(cpace_protocol_logic OBJECT
    cpace_core/cpace_core.c
    cpace_core/cpace_core.h
)
target_include_directories(cpace_protocol_logic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # See crypto_iface, common
)

# --- API Implementation ---
add_library(cpace_api_impl OBJECT
    cpace_api/cpace_api.c
    # The backend source is compiled in its own object library target
    # crypto_backend_monocypher/monocypher_backend.c # REMOVED
)
target_include_directories(cpace_api_impl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # See cpace_core, crypto_iface
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include> # See easy_cpace.h
)

# --- Include Monocypher Backend ---
add_subdirectory(crypto_backend_monocypher)

# --- Final Library Target ---
# Create the final static library from all the object files.
add_library(easy_cpace_core STATIC
    $<TARGET_OBJECTS:cpace_api_impl>
    $<TARGET_OBJECTS:cpace_protocol_logic>
    $<TARGET_OBJECTS:cpace_common>
    $<TARGET_OBJECTS:cpace_backend_monocypher>
)

# Link Monocypher library (fetched in root CMakeLists.txt)
# Using PUBLIC ensures consumers of easy_cpace_core also link Monocypher
target_link_libraries(easy_cpace_core PUBLIC monocypher_lib)

# Public include directories for the final library
target_include_directories(easy_cpace_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    # Propagate includes from components if needed.
    # Linking PUBLIC OpenSSL::Crypto should automatically add its include dirs
    # for consumers of easy_cpace_core. Add explicitly only if necessary:
    # $<INSTALL_INTERFACE:include> # Handled by install(TARGETS ... INCLUDES)
    # $<BUILD_INTERFACE:${OpenSSL_INCLUDE_DIR}> # Usually not needed
)

# Add compile definition for debug logging if enabled
if(CPACE_ENABLE_DEBUG_LOGGING)
    target_compile_definitions(easy_cpace_core PUBLIC CPACE_DEBUG_LOG)
    message(STATUS "Debug logging enabled for easy_cpace_core")
endif()

# Alias remains the same
add_library(easy_cpace ALIAS easy_cpace_core)
