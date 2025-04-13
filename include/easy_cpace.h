#ifndef EASY_CPACE_H
#define EASY_CPACE_H

#include <stddef.h>
#include <stdint.h>

// --- Forward Declaration ---
// Forward declare the crypto provider struct; users don't need its internals,
// but they need to pass a pointer obtained from a backend function.
struct crypto_provider_st;
typedef struct crypto_provider_st crypto_provider_t;

// --- Opaque Context ---
// Hide internal implementation details from the user.
struct cpace_ctx_st;
typedef struct cpace_ctx_st cpace_ctx_t;

// --- Public Constants ---
// Sizes specific to the CPACE-X25519-SHA512 suite
#define CPACE_PUBLIC_BYTES 32 // Size of Ya / Yb messages
#define CPACE_ISK_BYTES 64    // Size of the output Intermediate Session Key

// --- Roles ---
typedef enum {
    CPACE_ROLE_INITIATOR, // Party A
    CPACE_ROLE_RESPONDER  // Party B
} cpace_role_t;

// --- Error Codes ---
typedef enum {
    CPACE_OK = 1,
    CPACE_ERROR = 0,
    CPACE_ERROR_INVALID_ARGUMENT = -1,
    CPACE_ERROR_INVALID_STATE = -2,
    CPACE_ERROR_CRYPTO_FAIL = -3,
    CPACE_ERROR_PEER_KEY_INVALID = -4, // K == Identity
    CPACE_ERROR_BUFFER_TOO_SMALL = -5, // Should not happen with fixed sizes
    CPACE_ERROR_MALLOC = -6,
    CPACE_ERROR_BACKEND_UNSUPPORTED = -7
} cpace_error_t;

// --- Backend Provider Functions ---
/**
 * @brief Get the crypto provider implementation for OpenSSL.
 * @return Pointer to the provider struct, or NULL if OpenSSL support not
 * compiled in or init failed.
 */
const crypto_provider_t *cpace_get_provider_openssl(void);

/**
 * @brief Get the crypto provider implementation for Mbed TLS.
 * @return Pointer to the provider struct, or NULL if Mbed TLS support not
 * compiled in or init failed.
 */
const crypto_provider_t *cpace_get_provider_mbedtls(void);

// --- OpenSSL Backend Specific Initialization ---
// These are only needed when using the OpenSSL backend.

/**
 * @brief Initializes internal OpenSSL constants (e.g., for Elligator2).
 * MUST be called once before performing CPace steps (start/respond) when
 * using the OpenSSL provider. It is safe to call multiple times; subsequent
 * calls have no effect unless easy_cpace_openssl_cleanup() has been called.
 * Not thread-safe for the *first* initialization if called concurrently.
 * @return CPACE_OK on success, CPACE_ERROR_CRYPTO_FAIL on failure.
 */
cpace_error_t easy_cpace_openssl_init(void);

/**
 * @brief Cleans up internal OpenSSL constants initialized by easy_cpace_openssl_init().
 * Should be called when the OpenSSL provider is no longer needed to free resources.
 * It is safe to call multiple times or if not initialized.
 */
void easy_cpace_openssl_cleanup(void);

// --- Context Management ---
/**
 * @brief Create a new CPace context.
 * @param role The role of this party (initiator or responder).
 * @param provider The cryptographic backend provider (e.g., from
 * cpace_get_provider_openssl). Must not be NULL.
 * @return A new context handle, or NULL on failure (e.g., malloc error,
 * provider init).
 */
cpace_ctx_t *cpace_ctx_new(cpace_role_t role, const crypto_provider_t *provider);

/**
 * @brief Free a CPace context and cleanse sensitive data.
 * @param ctx The context to free. Safe to pass NULL.
 */
void cpace_ctx_free(cpace_ctx_t *ctx);

// --- Protocol Steps ---
/**
 * @brief Step 1 (Initiator): Generate the first message (Ya).
 *
 * Calculates the generator g, samples ephemeral scalar ya, computes Ya =
 * X25519(ya, g). Stores internal state (ya, g, AD, sid, ci, prs_len).
 *
 * @param ctx Context handle (must be INITIATOR role).
 * @param prs Password Related String.
 * @param prs_len Length of prs.
 * @param sid Session ID (optional, NULL if sid_len is 0).
 * @param sid_len Length of sid.
 * @param ci Channel Identifier (optional, NULL if ci_len is 0).
 * @param ci_len Length of ci.
 * @param ad Associated Data (optional, NULL if ad_len is 0).
 * @param ad_len Length of ad.
 * @param msg1_out Output buffer for message Ya (must be CPACE_PUBLIC_BYTES
 * bytes).
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_initiator_start(cpace_ctx_t *ctx,
                                    const uint8_t *prs,
                                    size_t prs_len,
                                    const uint8_t *sid,
                                    size_t sid_len,
                                    const uint8_t *ci,
                                    size_t ci_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    uint8_t msg1_out[CPACE_PUBLIC_BYTES]);

/**
 * @brief Step 2 (Responder): Process msg1 (Ya), generate msg2 (Yb), compute
 * ISK.
 *
 * Calculates generator g, samples ephemeral scalar yb, computes Yb = X25519(yb,
 * g). Computes K = X25519(yb, Ya). Checks K != Identity. Computes ISK based on
 * transcript (Ya, AD_A, Yb, AD_B). Assumes AD is the same for both parties in
 * this simple API; use context setters for different AD.
 *
 * @param ctx Context handle (must be RESPONDER role).
 * @param prs Password Related String.
 * @param prs_len Length of prs.
 * @param sid Session ID (optional, NULL if sid_len is 0).
 * @param sid_len Length of sid.
 * @param ci Channel Identifier (optional, NULL if ci_len is 0).
 * @param ci_len Length of ci.
 * @param ad Associated Data (optional, NULL if ad_len is 0).
 * @param ad_len Length of ad.
 * @param msg1_in Input buffer containing message Ya (must be CPACE_PUBLIC_BYTES
 * bytes).
 * @param msg2_out Output buffer for message Yb (must be CPACE_PUBLIC_BYTES
 * bytes).
 * @param isk_out Output buffer for the ISK (must be CPACE_ISK_BYTES bytes).
 * @return CPACE_OK on success, or a cpace_error_t code on failure (e.g.,
 * CPACE_ERROR_PEER_KEY_INVALID).
 */
cpace_error_t cpace_responder_respond(cpace_ctx_t *ctx,
                                      const uint8_t *prs,
                                      size_t prs_len,
                                      const uint8_t *sid,
                                      size_t sid_len,
                                      const uint8_t *ci,
                                      size_t ci_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t msg1_in[CPACE_PUBLIC_BYTES],
                                      uint8_t msg2_out[CPACE_PUBLIC_BYTES],
                                      uint8_t isk_out[CPACE_ISK_BYTES]);

/**
 * @brief Step 3 (Initiator): Process msg2 (Yb), compute ISK.
 *
 * Computes K = X25519(ya, Yb). Checks K != Identity.
 * Computes ISK based on transcript (Ya, AD_A, Yb, AD_B).
 * Must be called after cpace_initiator_start.
 *
 * @param ctx Context handle (must be INITIATOR role).
 * @param msg2_in Input buffer containing message Yb (must be CPACE_PUBLIC_BYTES
 * bytes).
 * @param isk_out Output buffer for the ISK (must be CPACE_ISK_BYTES bytes).
 * @return CPACE_OK on success, or a cpace_error_t code on failure (e.g.,
 * CPACE_ERROR_PEER_KEY_INVALID).
 */
cpace_error_t
cpace_initiator_finish(cpace_ctx_t *ctx, const uint8_t msg2_in[CPACE_PUBLIC_BYTES], uint8_t isk_out[CPACE_ISK_BYTES]);

#endif // EASY_CPACE_H
