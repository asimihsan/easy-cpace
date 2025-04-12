cmake_minimum_required(VERSION 3.10)

find_package(OpenSSL REQUIRED)

add_library(cpace_backend_openssl OBJECT # Changed to OBJECT
    openssl_backend.c
    # openssl_elligator2.c # Add later when implemented
)

target_include_directories(cpace_backend_openssl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../..> # Access include/ and src/crypto_iface
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>   # Access src/common
)

# Link OpenSSL::Crypto to the final easy_cpace_core target in parent scope, not here.

# Ensure this backend links against common utilities if needed directly
# Usually handled by including object files in the final target
