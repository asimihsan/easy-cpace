cmake_minimum_required(VERSION 3.10)

# Find OpenSSL within this backend's scope
find_package(OpenSSL REQUIRED)
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

# Associate OpenSSL usage requirements (include directories) with this target.
# Linking an OBJECT library against an INTERFACE library propagates the
# necessary include paths for compiling this target's sources.
# OpenSSL_INCLUDE_DIR is set by find_package(OpenSSL) in the parent scope (src/CMakeLists.txt).
target_include_directories(cpace_backend_openssl PRIVATE
    ${OpenSSL_INCLUDE_DIR}
)

# Actual library linking still happens in parent scope (src/CMakeLists.txt)
# when the final easy_cpace_core library is created.
