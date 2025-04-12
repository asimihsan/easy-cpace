cmake_minimum_required(VERSION 3.10)

add_library(cpace_backend_openssl OBJECT
    openssl_backend.c
    # openssl_elligator2.c # Add later when implemented
)

target_include_directories(cpace_backend_openssl PUBLIC
    # Provides access to src/common, src/crypto_iface etc.
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    # Provides access to include/easy_cpace.h (if needed by backend impl)
    # $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>

    # --- OpenSSL Includes ---
    # These should be handled automatically when the final library links
    # against the imported target OpenSSL::Crypto. Only add explicitly
    # using $<BUILD_INTERFACE:${OpenSSL_INCLUDE_DIR}> if you encounter
    # "openssl/... file not found" errors during compilation *of this backend*.
)

# Linking happens in parent scope (src/CMakeLists.txt)
