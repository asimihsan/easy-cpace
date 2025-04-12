cmake_minimum_required(VERSION 3.10)

add_library(cpace_backend_mbedtls OBJECT # Changed to OBJECT
    mbedtls_backend.c
    # mbedtls_elligator2.c # Add later when implemented
)

target_include_directories(cpace_backend_mbedtls PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../..> # Access include/ and src/crypto_iface
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>   # Access src/common
    # Add Mbed TLS include dirs if find_package doesn't handle it automatically
    # $<BUILD_INTERFACE:${MbedTLS_INCLUDE_DIRS}>
)

# Link Mbed TLS libraries
# The exact target names might vary depending on how Mbed TLS is built/packaged.
# Common names are mbedcrypto, mbedtls, mbedx509. PSA might be integrated or separate.
# Adjust these based on your Mbed TLS installation or find_package results.
# Link MbedTLS libraries to the final easy_cpace_core target in parent scope, not here.

# Ensure this backend links against common utilities if needed directly
# Usually handled by including object files in the final target
