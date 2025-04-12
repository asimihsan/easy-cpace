#ifndef CRYPTO_PROVIDER_H
#define CRYPTO_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

// --- Return Codes ---
// Use consistent return codes across provider implementations
#define CRYPTO_OK 1
#define CRYPTO_ERROR 0
#define CRYPTO_ERR_POINT_IS_IDENTITY 2 // Specific error for scalar_mult

// --- Constants (for CPACE-X25519-SHA512) ---
#define CPACE_CRYPTO_FIELD_SIZE_BYTES 32
#define CPACE_CRYPTO_SCALAR_BYTES 32
#define CPACE_CRYPTO_POINT_BYTES 32
#define CPACE_CRYPTO_HASH_BYTES 64
#define CPACE_CRYPTO_HASH_BLOCK_BYTES 128
#define CPACE_CRYPTO_DSI "CPace255" // Domain Separation Identifier
#define CPACE_CRYPTO_DSI_LEN (sizeof(CPACE_CRYPTO_DSI) - 1)

// --- Hashing Interface (SHA-512) ---
// Opaque context for multi-part hashing
struct crypto_hash_ctx_st;
typedef struct crypto_hash_ctx_st crypto_hash_ctx_t;

typedef struct {
    crypto_hash_ctx_t *(*hash_new)(void);
    void (*hash_free)(crypto_hash_ctx_t *ctx);
    int (*hash_reset)(crypto_hash_ctx_t *ctx); // 1=OK, 0=Error
    int (*hash_update)(crypto_hash_ctx_t *ctx, const uint8_t *data,
                       size_t len);                                                        // 1=OK, 0=Error
    int (*hash_final)(crypto_hash_ctx_t *ctx, uint8_t *out /* CPACE_CRYPTO_HASH_BYTES */); // 1=OK, 0=Error

    // One-shot hash with specific output length (needed for generator
    // calculation) Returns 1=OK, 0=Error
    int (*hash_digest)(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);
} crypto_hash_iface_t;

// --- Elliptic Curve Interface (X25519) ---
typedef struct {
    // Generate a random scalar (private key). Returns 1=OK, 0=Error.
    int (*generate_scalar)(uint8_t *out_scalar /* CPACE_CRYPTO_SCALAR_BYTES */);

    // Perform X25519: out_point = scalar * base_point.
    // Returns CRYPTO_OK (1), CRYPTO_ERROR (0), or CRYPTO_ERR_POINT_IS_IDENTITY
    // (2).
    int (*scalar_mult)(uint8_t *out_point /* CPACE_CRYPTO_POINT_BYTES */,
                       const uint8_t *scalar /* CPACE_CRYPTO_SCALAR_BYTES */,
                       const uint8_t *base_point /* CPACE_CRYPTO_POINT_BYTES */);

    // Map 32-byte hash output 'u' to curve point using Elligator 2.
    // Returns 1=OK, 0=Error.
    int (*map_to_curve)(uint8_t *out_point /* CPACE_CRYPTO_POINT_BYTES */,
                        const uint8_t *u /* CPACE_CRYPTO_FIELD_SIZE_BYTES */);
} crypto_ecc_iface_t;

// --- Miscellaneous Interface ---
typedef struct {
    // Securely zero memory.
    void (*cleanse)(void *ptr, size_t size);
    // Constant-time memory comparison. Returns 0 if equal, non-zero otherwise.
    int (*const_time_memcmp)(const void *a, const void *b, size_t size);
    // Generate random bytes. Returns 1=OK, 0=Error.
    int (*random_bytes)(uint8_t *buf, size_t len);
} crypto_misc_iface_t;

// --- Crypto Provider Structure ---
// Holds pointers to the implementations of the interfaces.
typedef struct {
    const crypto_hash_iface_t *hash_iface;
    const crypto_ecc_iface_t *ecc_iface;
    const crypto_misc_iface_t *misc_iface;
} crypto_provider_t;

#endif // CRYPTO_PROVIDER_H
