
# --- Common Utilities ---
add_library(cpace_common OBJECT # Changed to OBJECT
    common/utils.c
)
target_include_directories(cpace_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # Allow utils to see crypto_iface
)

# --- Core Protocol Logic ---
add_library(cpace_protocol_logic OBJECT # Changed to OBJECT
    cpace_core/cpace_core.c
)
target_include_directories(cpace_protocol_logic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # See crypto_iface, common
)
# No target_link_libraries needed between OBJECT libraries here

# --- API Implementation ---
add_library(cpace_api_impl OBJECT # Changed to OBJECT
    cpace_api/cpace_api.c
)
target_include_directories(cpace_api_impl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> # See cpace_core, crypto_iface
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include> # See easy_cpace.h
)
# No target_link_libraries needed between OBJECT libraries here


# --- Include Backends Based on Options ---
set(CPACE_BACKEND_OBJECTS "") # List of backend OBJECT library targets

if(CPACE_USE_OPENSSL)
    add_subdirectory(crypto_backend_openssl)
    list(APPEND CPACE_BACKEND_OBJECTS $<TARGET_OBJECTS:cpace_backend_openssl>)
endif()

if(CPACE_USE_MBEDTLS)
    add_subdirectory(crypto_backend_mbedtls)
    list(APPEND CPACE_BACKEND_OBJECTS $<TARGET_OBJECTS:cpace_backend_mbedtls>)
endif()

# --- Final Library Target ---
# Create the final static library from all the object files.
add_library(easy_cpace_core STATIC
    $<TARGET_OBJECTS:cpace_api_impl>
    $<TARGET_OBJECTS:cpace_protocol_logic>
    $<TARGET_OBJECTS:cpace_common>
    ${CPACE_BACKEND_OBJECTS}
)

# Link external dependencies (like OpenSSL, MbedTLS) to the final static library
# These dependencies were previously linked to the backend static libs,
# but now need to be linked to the final library that uses their object files.
if(CPACE_USE_OPENSSL)
    target_link_libraries(easy_cpace_core PUBLIC OpenSSL::Crypto)
endif()
if(CPACE_USE_MBEDTLS)
    # Adjust MbedTLS target names if necessary
    target_link_libraries(easy_cpace_core PUBLIC MbedTLS::mbedcrypto MbedTLS::mbedtls)
endif()

# Public include directories for the final library
target_include_directories(easy_cpace_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    # Add component include dirs if they weren't propagated correctly, though PUBLIC on OBJECT libs should handle it.
)

# Alias remains the same
add_library(easy_cpace ALIAS easy_cpace_core)
