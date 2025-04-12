cmake_minimum_required(VERSION 3.10)

# OpenSSL is now found in the parent scope
message(STATUS "Found OpenSSL ${OpenSSL_VERSION} for backend cpace_backend_openssl")

add_library(cpace_backend_openssl OBJECT
    openssl_backend.c
    # openssl_elligator2.c # Add later when implemented
)

target_include_directories(cpace_backend_openssl PUBLIC
    # Provides access to src/common, src/crypto_iface etc.
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    # Provides access to include/easy_cpace.h (if needed by backend impl)
    # $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# Associate OpenSSL usage requirements with this target
target_include_directories(cpace_backend_openssl PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

# Explicitly link against OpenSSL for this object library to have access to headers
target_link_libraries(cpace_backend_openssl PRIVATE OpenSSL::Crypto)

# Actual library linking still happens in parent scope (src/CMakeLists.txt)
# when the final easy_cpace_core library is created.
