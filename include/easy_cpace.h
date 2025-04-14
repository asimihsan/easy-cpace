/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EASY_CPACE_H
#define EASY_CPACE_H

#include <stddef.h>
#include <stdint.h>

// --- Forward Declaration ---
// Forward declare the crypto provider struct; users don't need its internals,
// but they need to pass a pointer obtained from a backend function.
struct crypto_provider_st;
typedef struct crypto_provider_st crypto_provider_t;

// --- Public Constants ---
// Sizes specific to the CPACE-X25519-SHA512 suite
#define CPACE_PUBLIC_BYTES 32 // Size of Ya / Yb messages
#define CPACE_ISK_BYTES 64    // Size of the output Intermediate Session Key

// Maximum input sizes for embedded-friendly implementation
#define CPACE_MAX_SID_LEN 64 // Maximum Session ID length
#define CPACE_MAX_CI_LEN 64  // Maximum Channel ID length
#define CPACE_MAX_AD_LEN 128 // Maximum Associated Data length

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
    CPACE_ERROR_BUFFER_TOO_SMALL = -5, // Happens when SID/CI/AD exceeds MAX_LEN
    CPACE_ERROR_RNG_FAILED = -8
} cpace_error_t;

// --- Context Structure ---
// Making the context structure visible for stack/static allocation
struct cpace_ctx_st {
    const crypto_provider_t *provider;
    cpace_role_t role;
    int state_flags;

    // Ephemeral keys (need cleansing)
    uint8_t ephemeral_sk[CPACE_PUBLIC_BYTES];
    uint8_t shared_secret_k[CPACE_PUBLIC_BYTES]; // K = X25519(y_sk, peer_pk)

    // Protocol values
    uint8_t generator[CPACE_PUBLIC_BYTES]; // g = map_to_curve(hash(DSI1||...))
    uint8_t own_pk[CPACE_PUBLIC_BYTES];    // Ya or Yb (calculated)
    uint8_t peer_pk[CPACE_PUBLIC_BYTES];   // Yb or Ya (received)

    // Fixed-size buffers for inputs
    uint8_t sid_buf[CPACE_MAX_SID_LEN];
    size_t sid_len;
    uint8_t ci_buf[CPACE_MAX_CI_LEN];
    size_t ci_len;
    uint8_t ad_buf[CPACE_MAX_AD_LEN];
    size_t ad_len;
};
typedef struct cpace_ctx_st cpace_ctx_t;

// --- Backend Provider Function ---
/**
 * @brief Get the crypto provider implementation for Monocypher.
 * @return Pointer to the provider struct.
 */
const crypto_provider_t *cpace_get_provider_monocypher(void);

// --- Monocypher Backend Specific Initialization ---
/**
 * @brief Initializes the Monocypher backend (if necessary).
 * Currently a no-op, but kept for API consistency.
 * @return Always returns CPACE_OK.
 */
cpace_error_t easy_cpace_monocypher_init(void);

/**
 * @brief Cleans up the Monocypher backend (if necessary).
 * Currently a no-op, but kept for API consistency.
 */
void easy_cpace_monocypher_cleanup(void);

// --- Context Management ---
/**
 * @brief Initialize a user-provided CPace context.
 * @param ctx Pointer to a user-allocated cpace_ctx_t structure to initialize.
 * @param role The role of this party (initiator or responder).
 * @param provider The cryptographic backend provider (must be from
 * cpace_get_provider_monocypher). Must not be NULL.
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_ctx_init(cpace_ctx_t *ctx, cpace_role_t role, const crypto_provider_t *provider);

/**
 * @brief Clean up a CPace context and cleanse sensitive data.
 * This function does NOT free the memory for ctx since it's user-allocated.
 * @param ctx The context to clean up. Safe to pass NULL.
 */
void cpace_ctx_cleanup(cpace_ctx_t *ctx);

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
 * @param sid_len Length of sid. Must be <= CPACE_MAX_SID_LEN.
 * @param ci Channel Identifier (optional, NULL if ci_len is 0).
 * @param ci_len Length of ci. Must be <= CPACE_MAX_CI_LEN.
 * @param ad Associated Data (optional, NULL if ad_len is 0).
 * @param ad_len Length of ad. Must be <= CPACE_MAX_AD_LEN.
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
 * @param sid_len Length of sid. Must be <= CPACE_MAX_SID_LEN.
 * @param ci Channel Identifier (optional, NULL if ci_len is 0).
 * @param ci_len Length of ci. Must be <= CPACE_MAX_CI_LEN.
 * @param ad Associated Data (optional, NULL if ad_len is 0).
 * @param ad_len Length of ad. Must be <= CPACE_MAX_AD_LEN.
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
