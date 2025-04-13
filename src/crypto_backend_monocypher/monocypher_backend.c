#include "../../include/easy_cpace.h"
#include "../common/utils.h"                 // For cpace_is_identity, debug print
#include "../crypto_iface/crypto_provider.h" // For struct definitions
#include "monocypher-ed25519.h"              // For SHA512 needed for ISK
#include "monocypher.h"

#include <errno.h>
#include <fcntl.h> // For O_RDONLY
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>  // For perror
#include <stdlib.h> // For abort
#include <string.h> // For memcmp, memcpy

// Platform-specific includes for RNG
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <unistd.h> // For read(), open(), close()
#define CPACE_OS_POSIX
#elif defined(_WIN32)
#include <Windows.h>
#include <bcrypt.h> // For BCryptGenRandom
#pragma comment(lib, "bcrypt.lib")
#define CPACE_OS_WINDOWS
#else
// Indicate no OS RNG found - functions will fail
#define CPACE_NO_OS_RNG
#warning "No OS-specific RNG implementation for this platform. CPace will not work."
#endif

// --- Helper Functions ---

// RFC 7748 Clamping for X25519 private keys
static void clamp_scalar(uint8_t scalar[CPACE_CRYPTO_SCALAR_BYTES])
{
    scalar[0] &= 248;  // 0b11111000
    scalar[31] &= 127; // 0b01111111
    scalar[31] |= 64;  // 0b01000000
}

// Constant time comparison using Monocypher verify functions
// Returns 0 if equal, non-zero otherwise (matches memcmp convention)
static int monocypher_const_time_memcmp(const void *a, const void *b, size_t size)
{
    // Use the largest verify function that fits, looping if necessary
    const uint8_t *a_ptr = (const uint8_t *)a;
    const uint8_t *b_ptr = (const uint8_t *)b;
    int result = 0;

    while (size >= 64) {
        result |= crypto_verify64(a_ptr, b_ptr);
        a_ptr += 64;
        b_ptr += 64;
        size -= 64;
    }
    while (size >= 32) {
        result |= crypto_verify32(a_ptr, b_ptr);
        a_ptr += 32;
        b_ptr += 32;
        size -= 32;
    }
    while (size >= 16) {
        result |= crypto_verify16(a_ptr, b_ptr);
        a_ptr += 16;
        b_ptr += 16;
        size -= 16;
    }
    // Handle remaining bytes (less than 16) - less critical for constant time?
    // Fallback to standard memcmp for the remainder, or pad and use verify16?
    // Padding seems safer.
    if (size > 0) {
        uint8_t padded_a[16] = {0};
        uint8_t padded_b[16] = {0};
        memcpy(padded_a, a_ptr, size);
        memcpy(padded_b, b_ptr, size);
        result |= crypto_verify16(padded_a, padded_b);
    }

    // crypto_verify returns 0 for equal, -1 for unequal.
    // We want 0 for equal, non-zero for unequal.
    return result; // Directly return the result (0 or -1)
}

// --- RNG Implementation ---
static int monocypher_random_bytes(uint8_t *buf, size_t len)
{
#if defined(CPACE_OS_POSIX)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/urandom");
        return 0; // Error
    }

    ssize_t bytes_read = 0;
    while (bytes_read < (ssize_t)len) {
        ssize_t ret = read(fd, buf + bytes_read, len - bytes_read);
        if (ret == -1) {
            if (errno == EINTR) {
                continue; // Interrupted, try again
            }
            perror("Failed to read from /dev/urandom");
            close(fd);
            return 0; // Error
        }
        if (ret == 0) {
            // Should not happen with /dev/urandom
            fprintf(stderr, "End of file reached on /dev/urandom\n");
            close(fd);
            return 0; // Error
        }
        bytes_read += ret;
    }

    close(fd);
    return 1; // OK
#elif defined(CPACE_OS_WINDOWS)
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenRandom failed with status: 0x%lx\n", status);
        return 0; // Error
    }
    return 1; // OK
#else
    // No RNG implementation available
    (void)buf; // Suppress unused parameter warning
    (void)len;
    return 0; // Error
#endif
}

// --- Hash Interface ---
// CPace currently only uses the one-shot digest. Implementing the incremental
// interface is not strictly necessary based on current core logic usage.
// We provide hash_digest and leave the incremental ones as NULL or stubs.

// Implement opaque context structure from crypto_provider.h
struct crypto_hash_ctx_st {
    // Not used by this backend as we only implement hash_digest
    uint8_t dummy;
};

static crypto_hash_ctx_t *monocypher_hash_new(void)
{
    // Not implemented/needed
    return NULL;
}
static void monocypher_hash_free(crypto_hash_ctx_t *ctx)
{
    // Not implemented/needed
    (void)ctx;
}
static int monocypher_hash_reset(crypto_hash_ctx_t *ctx)
{
    // Not implemented/needed
    (void)ctx;
    return 0; // Error
}
static int monocypher_hash_update(crypto_hash_ctx_t *ctx, const uint8_t *data, size_t len)
{
    // Not implemented/needed
    (void)ctx;
    (void)data;
    (void)len;
    return 0; // Error
}
static int monocypher_hash_final(crypto_hash_ctx_t *ctx, uint8_t *out)
{
    // Not implemented/needed
    (void)ctx;
    (void)out;
    return 0; // Error
}

// One-shot hash
static int monocypher_hash_digest(const uint8_t *data, size_t len, uint8_t *out, size_t out_len)
{
    if (!data || !out) {
        return 0; // Error: Invalid arguments
    }

    // Choose hash function based on required output length
    if (out_len == CPACE_ISK_BYTES) { // 64 bytes for ISK -> SHA512
        // Use Monocypher's SHA512 (requires monocypher-ed25519.c)
        crypto_sha512(out, data, len);
        return 1;                                          // OK
    } else if (out_len == CPACE_CRYPTO_FIELD_SIZE_BYTES) { // 32 bytes for map-to-curve -> BLAKE2b
            // Use Monocypher's BLAKE2b
            crypto_blake2b(out, out_len, data, len);
        return 1; // OK
    } else {
        // Unsupported output length for CPace needs
        // Could use BLAKE2b with variable length, but stick to required sizes.
        return 0; // Error: Unsupported output length
    }
}

static const crypto_hash_iface_t monocypher_hash_iface = {
    .hash_new = monocypher_hash_new,
    .hash_free = monocypher_hash_free,
    .hash_reset = monocypher_hash_reset,
    .hash_update = monocypher_hash_update,
    .hash_final = monocypher_hash_final,
    .hash_digest = monocypher_hash_digest,
};

// --- ECC Interface ---

static int monocypher_generate_scalar(uint8_t *out_scalar /* CPACE_CRYPTO_SCALAR_BYTES */)
{
    if (!monocypher_random_bytes(out_scalar, CPACE_CRYPTO_SCALAR_BYTES)) {
        return 0; // RNG failed
    }
    clamp_scalar(out_scalar);
    return 1; // OK
}

static int monocypher_scalar_mult(uint8_t *out_point /* CPACE_CRYPTO_POINT_BYTES */,
                                  const uint8_t *scalar /* CPACE_CRYPTO_SCALAR_BYTES */,
                                  const uint8_t *base_point /* CPACE_CRYPTO_POINT_BYTES */)
{
    // Monocypher's crypto_x25519 performs scalar multiplication.
    // It expects the private key (scalar) and the peer's public key (base_point).
    crypto_x25519(out_point, scalar, base_point);

    // Check if the result is the identity point (all zeros for X25519)
    if (cpace_is_identity(out_point)) {
#ifdef CPACE_DEBUG_LOG
        printf("DEBUG: Monocypher backend detected identity point result in scalar_mult.\n");
        cpace_debug_print_hex("Scalar", scalar, CPACE_CRYPTO_SCALAR_BYTES);
        cpace_debug_print_hex("Base Point", base_point, CPACE_CRYPTO_POINT_BYTES);
#endif
        return CRYPTO_ERR_POINT_IS_IDENTITY; // Return specific error code
    }

    return CRYPTO_OK; // OK
}

static int monocypher_map_to_curve(uint8_t *out_point /* CPACE_CRYPTO_POINT_BYTES */,
                                   const uint8_t *u_bytes /* CPACE_CRYPTO_FIELD_SIZE_BYTES
*/)
{
    // Monocypher provides Elligator 2 map directly
    crypto_elligator_map(out_point, u_bytes);
    // Monocypher's map function doesn't have a failure mode specified. Assume OK.
    return CRYPTO_OK;
}

static const crypto_ecc_iface_t monocypher_ecc_iface = {
    .generate_scalar = monocypher_generate_scalar,
    .scalar_mult = monocypher_scalar_mult,
    .map_to_curve = monocypher_map_to_curve,
};

// --- Misc Interface ---

static void monocypher_cleanse(void *ptr, size_t size) { crypto_wipe(ptr, size); }

static const crypto_misc_iface_t monocypher_misc_iface = {
    .cleanse = monocypher_cleanse,
    .const_time_memcmp = monocypher_const_time_memcmp,
    .random_bytes = monocypher_random_bytes,
};

// --- Provider Structure ---

static const crypto_provider_t monocypher_provider = {
    .hash_iface = &monocypher_hash_iface,
    .ecc_iface = &monocypher_ecc_iface,
    .misc_iface = &monocypher_misc_iface,
};

// --- Public API Functions ---

const crypto_provider_t *cpace_get_provider_monocypher(void)
{
    // Monocypher itself doesn't require global init/cleanup like OpenSSL BIGNUMs.
    // The RNG is stateless (opens/closes /dev/urandom or calls BCrypt each time).
    // So, we can just return the provider struct.
    return &monocypher_provider;
}

// Init/Cleanup functions (optional, could be empty)
cpace_error_t easy_cpace_monocypher_init(void)
{
    // No global initialization needed for Monocypher itself.
    // Could potentially pre-open /dev/urandom if performance was critical,
    // but the current approach is simpler.
    return CPACE_OK;
}

void easy_cpace_monocypher_cleanup(void)
{
    // No global cleanup needed for Monocypher.
}
