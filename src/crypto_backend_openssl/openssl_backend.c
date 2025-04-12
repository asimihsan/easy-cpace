#include "../common/utils.h" // For cpace_const_time_memcmp
#include "../crypto_iface/crypto_provider.h"

#include <assert.h>
#include <openssl/crypto.h> // For CRYPTO_memcmp, OPENSSL_cleanse
#include <openssl/err.h>    // For error handling (optional but good)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h> // For memcpy

// Forward declare Elligator2 function from the other file in this backend
int openssl_elligator2_map_to_curve(uint8_t *out_point, const uint8_t *u);

// --- Hashing (SHA-512) ---

struct crypto_hash_ctx_st {
    EVP_MD_CTX *evp_ctx;
};

static crypto_hash_ctx_t *openssl_hash_new(void)
{
    crypto_hash_ctx_t *ctx = (crypto_hash_ctx_t *)OPENSSL_malloc(sizeof(crypto_hash_ctx_t));
    if (!ctx)
        return NULL;

    ctx->evp_ctx = EVP_MD_CTX_new();
    if (!ctx->evp_ctx) {
        OPENSSL_free(ctx);
        return NULL;
    }

    // Initialize for SHA-512
    if (EVP_DigestInit_ex(ctx->evp_ctx, EVP_sha512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx->evp_ctx);
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void openssl_hash_free(crypto_hash_ctx_t *ctx)
{
    if (ctx) {
        EVP_MD_CTX_free(ctx->evp_ctx);
        OPENSSL_free(ctx);
    }
}

static int openssl_hash_reset(crypto_hash_ctx_t *ctx)
{
    if (!ctx || !ctx->evp_ctx)
        return CRYPTO_ERROR;
    // Re-initialize for SHA-512
    return EVP_DigestInit_ex(ctx->evp_ctx, EVP_sha512(), NULL); // Returns 1 on success
}

static int openssl_hash_update(crypto_hash_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || !ctx->evp_ctx)
        return CRYPTO_ERROR;
    return EVP_DigestUpdate(ctx->evp_ctx, data, len); // Returns 1 on success
}

static int openssl_hash_final(crypto_hash_ctx_t *ctx, uint8_t *out)
{
    if (!ctx || !ctx->evp_ctx || !out)
        return CRYPTO_ERROR;
    unsigned int len = CPACE_CRYPTO_HASH_BYTES; // Should match EVP_MD_size
    // Final implicitly resets the context in OpenSSL >= 1.1.1 ? Check docs.
    // Let's reset explicitly just in case.
    int ret = EVP_DigestFinal_ex(ctx->evp_ctx, out, &len);
    // Reset after finalization to allow reuse
    if (openssl_hash_reset(ctx) == CRYPTO_ERROR) {
        // Handle error? For now, just return original final status
    }
    return (ret == 1 && len == CPACE_CRYPTO_HASH_BYTES) ? CRYPTO_OK : CRYPTO_ERROR;
}

// One-shot hash with specific output length
static int openssl_hash_digest(const uint8_t *data, size_t len, uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int hash_len = 0;
    uint8_t full_hash[CPACE_CRYPTO_HASH_BYTES]; // Max possible size
    int ret = CRYPTO_ERROR;

    if (!out || out_len == 0 || out_len > CPACE_CRYPTO_HASH_BYTES)
        return CRYPTO_ERROR;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return CRYPTO_ERROR;

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, data, len) != 1)
        goto cleanup;
    if (EVP_DigestFinal_ex(ctx, full_hash, &hash_len) != 1)
        goto cleanup;

    if (hash_len < out_len)
        goto cleanup; // Should not happen for SHA512

    memcpy(out, full_hash, out_len); // Take the first out_len bytes
    ret = CRYPTO_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(full_hash, sizeof(full_hash));
    return ret;
}

// --- ECC (X25519) ---

static int openssl_generate_scalar(uint8_t *out_scalar)
{
    // X25519 scalars need specific clamping according to RFC 7748
    if (RAND_bytes(out_scalar, CPACE_CRYPTO_SCALAR_BYTES) != 1) {
        return CRYPTO_ERROR;
    }
    out_scalar[0] &= 248;  // Clear bottom 3 bits
    out_scalar[31] &= 127; // Clear top bit
    out_scalar[31] |= 64;  // Set second highest bit
    return CRYPTO_OK;
}

static int openssl_scalar_mult(uint8_t *out_point, const uint8_t *scalar, const uint8_t *base_point)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY *priv_key = NULL;
    size_t secret_len = CPACE_CRYPTO_POINT_BYTES;
    int ret = CRYPTO_ERROR;

    if (!out_point || !scalar || !base_point)
        return CRYPTO_ERROR;

    // Create peer key object from base_point
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, base_point, CPACE_CRYPTO_POINT_BYTES);
    if (!peer_key)
        goto cleanup;

    // Create private key object from scalar
    // Note: OpenSSL clamps the scalar internally during derivation if using EVP_PKEY_derive
    // but if constructing the key manually, ensure it's clamped if necessary (openssl_generate_scalar does this)
    priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar, CPACE_CRYPTO_SCALAR_BYTES);
    if (!priv_key)
        goto cleanup;

    // Create context for derivation
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_derive_init(ctx) != 1)
        goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) != 1)
        goto cleanup;

    // Perform the derivation (scalar multiplication)
    if (EVP_PKEY_derive(ctx, out_point, &secret_len) != 1)
        goto cleanup;

    if (secret_len != CPACE_CRYPTO_POINT_BYTES) {
        // Should not happen for X25519
        goto cleanup;
    }

    // Check if the result is the identity point (all zeros)
    if (cpace_is_identity(out_point)) {
        ret = CRYPTO_ERR_POINT_IS_IDENTITY; // Specific error code
        // Cleanse the output buffer if it's identity
        OPENSSL_cleanse(out_point, CPACE_CRYPTO_POINT_BYTES);
    }
    else {
        ret = CRYPTO_OK;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(priv_key);
    return ret;
}

// Map to curve uses the function from the other file
static int openssl_map_to_curve(uint8_t *out_point, const uint8_t *u)
{
    return openssl_elligator2_map_to_curve(out_point, u);
}

// --- Miscellaneous ---

static void openssl_cleanse(void *ptr, size_t size) { OPENSSL_cleanse(ptr, size); }

static int openssl_const_time_memcmp(const void *a, const void *b, size_t size)
{
    // CRYPTO_memcmp is OpenSSL's constant time compare function
    return CRYPTO_memcmp(a, b, size);
}

static int openssl_random_bytes(uint8_t *buf, size_t len)
{
    return RAND_bytes(buf, len); // Returns 1 on success
}

// --- Provider Structures ---

static const crypto_hash_iface_t openssl_hash_provider = {
    .hash_new = openssl_hash_new,
    .hash_free = openssl_hash_free,
    .hash_reset = openssl_hash_reset,
    .hash_update = openssl_hash_update,
    .hash_final = openssl_hash_final,
    .hash_digest = openssl_hash_digest,
};

static const crypto_ecc_iface_t openssl_ecc_provider = {
    .generate_scalar = openssl_generate_scalar,
    .scalar_mult = openssl_scalar_mult,
    .map_to_curve = openssl_map_to_curve,
};

static const crypto_misc_iface_t openssl_misc_provider = {
    .cleanse = openssl_cleanse,
    .const_time_memcmp = openssl_const_time_memcmp,
    .random_bytes = openssl_random_bytes,
};

// The actual provider instance returned to the user
static const crypto_provider_t openssl_provider_instance = {
    .hash_iface = &openssl_hash_provider,
    .ecc_iface = &openssl_ecc_provider,
    .misc_iface = &openssl_misc_provider,
};

// --- Public API Function to get the provider ---

// Defined in include/easy_cpace.h
const crypto_provider_t *cpace_get_provider_openssl(void)
{
    // Could add initialization checks here if OpenSSL needs explicit init,
    // but modern OpenSSL often handles it automatically.
    // Check OPENSSL_init_crypto() ? Or assume caller handles it / library does.
    // For simplicity, just return the static instance.
    return &openssl_provider_instance;
}
