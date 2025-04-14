/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef CPACE_CORE_H
#define CPACE_CORE_H

#include "../../include/easy_cpace.h"
#include "../crypto_iface/crypto_provider.h"
#include <stddef.h>
#include <stdint.h>

// --- State Flags ---
// Used internally to track the protocol progress within the context
#define CPACE_STATE_INITIALIZED 0x00
#define CPACE_STATE_I_STARTED 0x01   // Initiator called start
#define CPACE_STATE_R_RESPONDED 0x02 // Responder called respond (includes ISK derivation)
#define CPACE_STATE_I_FINISHED 0x04  // Initiator called finish (includes ISK derivation)
// Note: R_RESPONDED and I_FINISHED imply shared secret was derived and potentially cleansed
#define CPACE_STATE_ERROR 0x80 // Context encountered an unrecoverable error

// --- Internal Core Functions ---

/**
 * @brief Initialize a CPace context internals.
 * @param ctx Context to initialize. Must not be NULL.
 * @param role Role to assign to the context.
 * @param provider Provider to use for crypto operations.
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_core_ctx_init(cpace_ctx_t *ctx, cpace_role_t role, const crypto_provider_t *provider);

/**
 * @brief Cleans up a CPace context's internals, cleansing sensitive key material.
 * @param ctx The context to clean up. MUST NOT be NULL. Provider must be valid.
 */
void cpace_core_ctx_cleanup(cpace_ctx_t *ctx);

/**
 * @brief Core logic for Initiator Step 1.
 * Calculates g, generates y_a, calculates Y_a.
 * Stores state (y_a, g, Y_a, copies of inputs) in context.
 * @param ctx Context handle (must be INITIATOR role, state INITIALIZED).
 * @param prs Password Related String.
 * @param prs_len Length of prs.
 * @param sid Session ID.
 * @param sid_len Length of sid.
 * @param ci Channel Identifier.
 * @param ci_len Length of ci.
 * @param ad Associated Data.
 * @param ad_len Length of ad.
 * @param msg1_out Output buffer for message Ya (CPACE_PUBLIC_BYTES).
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_core_initiator_start(cpace_ctx_t *ctx,
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
 * @brief Core logic for Responder Step 2.
 * Calculates g, generates y_b, calculates Y_b, calculates K, checks K, derives ISK.
 * Stores state (Y_a, Y_b, copies of inputs) in context. Cleanses y_b, K.
 * @param ctx Context handle (must be RESPONDER role, state INITIALIZED).
 * @param prs Password Related String.
 * @param prs_len Length of prs.
 * @param sid Session ID.
 * @param sid_len Length of sid.
 * @param ci Channel Identifier.
 * @param ci_len Length of ci.
 * @param ad Associated Data.
 * @param ad_len Length of ad.
 * @param msg1_in Input buffer containing message Ya (CPACE_PUBLIC_BYTES).
 * @param msg2_out Output buffer for message Yb (CPACE_PUBLIC_BYTES).
 * @param isk_out Output buffer for the ISK (CPACE_ISK_BYTES).
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_core_responder_respond(cpace_ctx_t *ctx,
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
 * @brief Core logic for Initiator Step 3.
 * Retrieves y_a, calculates K, checks K, derives ISK.
 * Cleanses y_a, K.
 * @param ctx Context handle (must be INITIATOR role, state I_STARTED).
 * @param msg2_in Input buffer containing message Yb (CPACE_PUBLIC_BYTES).
 * @param isk_out Output buffer for the ISK (CPACE_ISK_BYTES).
 * @return CPACE_OK on success, or a cpace_error_t code on failure.
 */
cpace_error_t cpace_core_initiator_finish(cpace_ctx_t *ctx,
                                          const uint8_t msg2_in[CPACE_PUBLIC_BYTES],
                                          uint8_t isk_out[CPACE_ISK_BYTES]);

#endif // CPACE_CORE_H
