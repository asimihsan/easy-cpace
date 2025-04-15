/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include "cpace_core.h"
#include "../common/debug.h" // For debug macros
#include "../common/utils.h" // For construction helpers and is_identity
#include <string.h>          // For memcpy, memset

// --- Helper Function Prototypes ---

static cpace_error_t calculate_generator_g(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len);

static cpace_error_t derive_intermediate_key_isk(const cpace_ctx_t *ctx, uint8_t *isk_out);

// Helper to safely store input data into the context's fixed buffers
static cpace_error_t store_input_data(cpace_ctx_t *ctx,
                                      const uint8_t *sid,
                                      size_t sid_len,
                                      const uint8_t *ci,
                                      size_t ci_len,
                                      const uint8_t *ad,
                                      size_t ad_len);

// --- Context Management Implementation ---

cpace_error_t cpace_core_ctx_init(cpace_ctx_t *ctx, cpace_role_t role, const crypto_provider_t *provider)
{
    if (!ctx || !provider) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // Zero-initialize the entire context
    memset(ctx, 0, sizeof(cpace_ctx_t));

    // Set provider and role
    ctx->provider = provider;
    ctx->role = role;
    ctx->state_flags = CPACE_STATE_INITIALIZED;

    return CPACE_OK;
}

void cpace_core_ctx_cleanup(cpace_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    // Cleanse sensitive material - check provider exists first
    if (ctx->provider && ctx->provider->misc_iface && ctx->provider->misc_iface->cleanse) {
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        ctx->provider->misc_iface->cleanse(ctx->generator, sizeof(ctx->generator));
        ctx->provider->misc_iface->cleanse(ctx->own_pk, sizeof(ctx->own_pk));
        ctx->provider->misc_iface->cleanse(ctx->peer_pk, sizeof(ctx->peer_pk));
        ctx->provider->misc_iface->cleanse(ctx->sid_buf, sizeof(ctx->sid_buf));
        ctx->provider->misc_iface->cleanse(ctx->ci_buf, sizeof(ctx->ci_buf));
        ctx->provider->misc_iface->cleanse(ctx->ad_buf, sizeof(ctx->ad_buf));
    } else {
        // Fallback to volatile memset if cleanse unavailable (not ideal)
        memset((void *volatile)ctx->ephemeral_sk, 0, sizeof(ctx->ephemeral_sk));
        memset((void *volatile)ctx->shared_secret_k, 0, sizeof(ctx->shared_secret_k));
        memset((void *volatile)ctx->generator, 0, sizeof(ctx->generator));
        memset((void *volatile)ctx->own_pk, 0, sizeof(ctx->own_pk));
        memset((void *volatile)ctx->peer_pk, 0, sizeof(ctx->peer_pk));
        memset((void *volatile)ctx->sid_buf, 0, sizeof(ctx->sid_buf));
        memset((void *volatile)ctx->ci_buf, 0, sizeof(ctx->ci_buf));
        memset((void *volatile)ctx->ad_buf, 0, sizeof(ctx->ad_buf));
    }

    // Reset length fields and state
    ctx->sid_len = 0;
    ctx->ci_len = 0;
    ctx->ad_len = 0;
    ctx->state_flags = CPACE_STATE_INITIALIZED;
}

// --- Helper Function Implementations ---

// Store input data into fixed-size buffers in the context
static cpace_error_t store_input_data(cpace_ctx_t *ctx,
                                      const uint8_t *sid,
                                      size_t sid_len,
                                      const uint8_t *ci,
                                      size_t ci_len,
                                      const uint8_t *ad,
                                      size_t ad_len)
{
    // Reset stored data lengths
    ctx->sid_len = 0;
    ctx->ci_len = 0;
    ctx->ad_len = 0;

    // Copy Session ID if provided
    if (sid_len > 0) {
        if (sid_len > CPACE_MAX_SID_LEN) {
            return CPACE_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(ctx->sid_buf, sid, sid_len);
        ctx->sid_len = sid_len;
    }

    // Copy Channel ID if provided
    if (ci_len > 0) {
        if (ci_len > CPACE_MAX_CI_LEN) {
            return CPACE_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(ctx->ci_buf, ci, ci_len);
        ctx->ci_len = ci_len;
    }

    // Copy Associated Data if provided
    if (ad_len > 0) {
        if (ad_len > CPACE_MAX_AD_LEN) {
            return CPACE_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(ctx->ad_buf, ad, ad_len);
        ctx->ad_len = ad_len;
    }

    return CPACE_OK;
}

// Calculate generator g = map_to_curve(hash(DSI1 || PRS || ZPAD || L(CI) || CI || L(SID) || SID))
static cpace_error_t calculate_generator_g(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len)
{
    // SHA-512 produces 64 bytes but we only need the first 32 bytes for map_to_curve
    // Our hash_final implementation will handle the truncation
    uint8_t gen_hash_output[CPACE_CRYPTO_FIELD_SIZE_BYTES]; // 32 bytes
    cpace_error_t err = CPACE_OK;

    DEBUG_ENTER("calculate_generator_g");
    DEBUG_PTR("ctx", ctx);
    DEBUG_PTR("prs", prs);
    DEBUG_LOG("prs_len = %zu", prs_len);

    // Use incremental hashing to avoid large buffer allocation
    crypto_hash_ctx_t *hash_ctx = ctx->provider->hash_iface->hash_new();
    if (!hash_ctx) {
        DEBUG_LOG("Failed to create hash context");
        DEBUG_EXIT("calculate_generator_g", CPACE_ERROR_CRYPTO_FAIL);
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 1. Construct and hash DSI label
    uint8_t dsi_len = (uint8_t)CPACE_CRYPTO_DSI_LEN;
    if (ctx->provider->hash_iface->hash_update(hash_ctx, &dsi_len, 1) != CRYPTO_OK ||
        ctx->provider->hash_iface->hash_update(hash_ctx, (const uint8_t *)CPACE_CRYPTO_DSI, CPACE_CRYPTO_DSI_LEN) !=
            CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

    // 2. Add PRS with length prefix
    if (prs_len > 255) {
        err = CPACE_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    uint8_t prs_len_byte = (uint8_t)prs_len;
    if (ctx->provider->hash_iface->hash_update(hash_ctx, &prs_len_byte, 1) != CRYPTO_OK ||
        ctx->provider->hash_iface->hash_update(hash_ctx, prs, prs_len) != CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

    // 3. Calculate and add ZPAD
    // Calculate length based on same formula as in cpace_construct_generator_hash_input
    size_t lv_dsi_len = 1 + CPACE_CRYPTO_DSI_LEN;
    size_t lv_prs_len = 1 + prs_len;
    size_t zpad_len = 0;

    if ((lv_dsi_len + lv_prs_len) < (CPACE_CRYPTO_HASH_BLOCK_BYTES - 1)) {
        zpad_len = CPACE_CRYPTO_HASH_BLOCK_BYTES - 1 - lv_prs_len - lv_dsi_len;
    }

    if (zpad_len > 255) {
        err = CPACE_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    // Add ZPAD length and zeros
    uint8_t zpad_len_byte = (uint8_t)zpad_len;
    if (ctx->provider->hash_iface->hash_update(hash_ctx, &zpad_len_byte, 1) != CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

    // Add zero bytes one at a time to avoid buffer allocation
    uint8_t zero_byte = 0;
    for (size_t i = 0; i < zpad_len; i++) {
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &zero_byte, 1) != CRYPTO_OK) {
            err = CPACE_ERROR_CRYPTO_FAIL;
            goto cleanup;
        }
    }

    // 4. Add Channel ID if present
    if (ctx->ci_len > 0) {
        uint8_t ci_len_byte = (uint8_t)ctx->ci_len;
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &ci_len_byte, 1) != CRYPTO_OK ||
            ctx->provider->hash_iface->hash_update(hash_ctx, ctx->ci_buf, ctx->ci_len) != CRYPTO_OK) {
            err = CPACE_ERROR_CRYPTO_FAIL;
            goto cleanup;
        }
    } else {
        // Add empty CI with length 0
        uint8_t zero_len = 0;
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &zero_len, 1) != CRYPTO_OK) {
            err = CPACE_ERROR_CRYPTO_FAIL;
            goto cleanup;
        }
    }

    // 5. Add Session ID if present
    if (ctx->sid_len > 0) {
        uint8_t sid_len_byte = (uint8_t)ctx->sid_len;
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &sid_len_byte, 1) != CRYPTO_OK ||
            ctx->provider->hash_iface->hash_update(hash_ctx, ctx->sid_buf, ctx->sid_len) != CRYPTO_OK) {
            err = CPACE_ERROR_CRYPTO_FAIL;
            goto cleanup;
        }
    } else {
        // Add empty SID with length 0
        uint8_t zero_len = 0;
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &zero_len, 1) != CRYPTO_OK) {
            err = CPACE_ERROR_CRYPTO_FAIL;
            goto cleanup;
        }
    }

    // 6. Finalize hash
    // Note that SHA-512 produces 64 bytes, but we only need first 32 for map_to_curve
    uint8_t full_hash[CPACE_CRYPTO_HASH_BYTES] = {0}; // Full 64-byte SHA-512 output, initialize to zero

    if (ctx->provider->hash_iface->hash_final(hash_ctx, full_hash) != CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

    // Copy only the first 32 bytes (CPACE_CRYPTO_FIELD_SIZE_BYTES) to gen_hash_output
    memcpy(gen_hash_output, full_hash, CPACE_CRYPTO_FIELD_SIZE_BYTES);

    // Cleanse the full hash buffer
    ctx->provider->misc_iface->cleanse(full_hash, sizeof(full_hash));

    // 7. Map hash output to curve point
    if (ctx->provider->ecc_iface->map_to_curve(ctx->generator, gen_hash_output) != CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

cleanup:
    // Cleanse and free resources
    ctx->provider->misc_iface->cleanse(gen_hash_output, sizeof(gen_hash_output));
    if (hash_ctx) {
        ctx->provider->hash_iface->hash_free(hash_ctx);
    }

    DEBUG_EXIT("calculate_generator_g", err);
    return err;
}

// Derive ISK = hash(lv(DSI) || lv(SID) || lv(K) || lv(Ya) || lv(ADa) || lv(Yb) || lv(ADb))
// Assumes K, Ya, Yb, SID, AD are already in the context.
// Ya/Yb order depends on role. Uses symmetric AD assumption from API.
static cpace_error_t derive_intermediate_key_isk(const cpace_ctx_t *ctx, uint8_t *isk_out)
{
    // Use the DSI label from the draft B.1.5
    const uint8_t DSI_ISK[] = "CPace255_ISK";
    const uint8_t *ya_ptr;
    const uint8_t *yb_ptr;
    cpace_error_t err = CPACE_OK;

    // Determine which public key is Ya and which is Yb based on role
    if (ctx->role == CPACE_ROLE_INITIATOR) {
        ya_ptr = ctx->own_pk;
        yb_ptr = ctx->peer_pk;
    } else { // RESPONDER
        ya_ptr = ctx->peer_pk;
        yb_ptr = ctx->own_pk;
    }

    // Use incremental hashing to avoid large buffer allocation
    crypto_hash_ctx_t *hash_ctx = ctx->provider->hash_iface->hash_new();
    if (!hash_ctx) {
        return CPACE_ERROR_CRYPTO_FAIL;
    }

// Helper function to add a length-value encoded item to the hash
#define ADD_LV(data, data_len)                                                                                         \
    do {                                                                                                               \
        if ((data_len) > 255) {                                                                                        \
            err = CPACE_ERROR_INVALID_ARGUMENT;                                                                        \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        uint8_t len_byte = (uint8_t)(data_len);                                                                        \
        if (ctx->provider->hash_iface->hash_update(hash_ctx, &len_byte, 1) != CRYPTO_OK) {                             \
            err = CPACE_ERROR_CRYPTO_FAIL;                                                                             \
            goto cleanup;                                                                                              \
        }                                                                                                              \
        if ((data_len) > 0 && (data) != NULL) {                                                                        \
            if (ctx->provider->hash_iface->hash_update(hash_ctx, (data), (data_len)) != CRYPTO_OK) {                   \
                err = CPACE_ERROR_CRYPTO_FAIL;                                                                         \
                goto cleanup;                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

    // Add each component with length-value encoding
    // 1. DSI label
    ADD_LV(DSI_ISK, sizeof(DSI_ISK) - 1);

    // 2. Session ID
    ADD_LV(ctx->sid_buf, ctx->sid_len);

    // 3. Shared secret K
    ADD_LV(ctx->shared_secret_k, CPACE_CRYPTO_POINT_BYTES);

    // 4. Ya (initiator's public key)
    ADD_LV(ya_ptr, CPACE_CRYPTO_POINT_BYTES);

    // 5. ADa (initiator's associated data)
    ADD_LV(ctx->ad_buf, ctx->ad_len);

    // 6. Yb (responder's public key)
    ADD_LV(yb_ptr, CPACE_CRYPTO_POINT_BYTES);

    // 7. ADb (responder's associated data - same as ADa in this API)
    ADD_LV(ctx->ad_buf, ctx->ad_len);

    // Finalize hash to get ISK
    if (ctx->provider->hash_iface->hash_final(hash_ctx, isk_out) != CRYPTO_OK) {
        err = CPACE_ERROR_CRYPTO_FAIL;
        goto cleanup;
    }

cleanup:
#undef ADD_LV
    if (hash_ctx) {
        ctx->provider->hash_iface->hash_free(hash_ctx);
    }

    return err;
}

// --- Core Protocol Step Implementations ---

cpace_error_t cpace_core_initiator_start(cpace_ctx_t *ctx,
                                         const uint8_t *prs,
                                         size_t prs_len,
                                         const uint8_t *sid,
                                         size_t sid_len,
                                         const uint8_t *ci,
                                         size_t ci_len,
                                         const uint8_t *ad,
                                         size_t ad_len,
                                         uint8_t msg1_out[CPACE_PUBLIC_BYTES])
{
    // Store SID, CI, AD (must happen before calculate_generator_g)
    cpace_error_t err = store_input_data(ctx, sid, sid_len, ci, ci_len, ad, ad_len);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return err;
    }

    // 1. Calculate Generator g
    err = calculate_generator_g(ctx, prs, prs_len);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return err;
    }

    // 2. Generate ephemeral scalar y_a
    if (ctx->provider->ecc_iface->generate_scalar(ctx->ephemeral_sk) != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 3. Calculate public key Y_a = X25519(y_a, g)
    int mult_ret = ctx->provider->ecc_iface->scalar_mult(ctx->own_pk, ctx->ephemeral_sk, ctx->generator);
    if (mult_ret == CRYPTO_ERR_POINT_IS_IDENTITY) {
        // This shouldn't happen if g is calculated correctly and y_a is non-zero. Treat as error.
        ctx->state_flags = CPACE_STATE_ERROR;
        // Cleanse sk before returning
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        return CPACE_ERROR_CRYPTO_FAIL; // Internal crypto error
    } else if (mult_ret != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 4. Copy Y_a to output
    memcpy(msg1_out, ctx->own_pk, CPACE_PUBLIC_BYTES);

    // 5. Update state
    ctx->state_flags = CPACE_STATE_I_STARTED;
    return CPACE_OK;
}

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
                                           uint8_t isk_out[CPACE_ISK_BYTES])
{
    // Store SID, CI, AD
    cpace_error_t err = store_input_data(ctx, sid, sid_len, ci, ci_len, ad, ad_len);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return err;
    }

    // Store peer's public key Y_a
    memcpy(ctx->peer_pk, msg1_in, CPACE_PUBLIC_BYTES);

    // 1. Calculate Generator g
    err = calculate_generator_g(ctx, prs, prs_len);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return err;
    }

    // 2. Generate ephemeral scalar y_b
    if (ctx->provider->ecc_iface->generate_scalar(ctx->ephemeral_sk) != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 3. Calculate public key Y_b = X25519(y_b, g)
    int mult_ret_yb = ctx->provider->ecc_iface->scalar_mult(ctx->own_pk, ctx->ephemeral_sk, ctx->generator);
    if (mult_ret_yb == CRYPTO_ERR_POINT_IS_IDENTITY) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        return CPACE_ERROR_CRYPTO_FAIL;
    } else if (mult_ret_yb != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 4. Calculate shared secret K = X25519(y_b, Y_a)
    int mult_ret_k = ctx->provider->ecc_iface->scalar_mult(ctx->shared_secret_k, ctx->ephemeral_sk, ctx->peer_pk);
    if (mult_ret_k == CRYPTO_ERR_POINT_IS_IDENTITY) {
        // K is identity - protocol failure, according to spec!
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return CPACE_ERROR_PEER_KEY_INVALID;
    } else if (mult_ret_k != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 5. Derive Intermediate Session Key (ISK)
    err = derive_intermediate_key_isk(ctx, isk_out);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return err;
    }

    // 6. Copy Y_b to output
    memcpy(msg2_out, ctx->own_pk, CPACE_PUBLIC_BYTES);

    // 7. Cleanse sensitive intermediates before returning ISK
    ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
    ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));

    // 8. Update state
    ctx->state_flags = CPACE_STATE_R_RESPONDED;
    return CPACE_OK;
}

cpace_error_t cpace_core_initiator_finish(cpace_ctx_t *ctx,
                                          const uint8_t msg2_in[CPACE_PUBLIC_BYTES],
                                          uint8_t isk_out[CPACE_ISK_BYTES])
{
    // Store peer's public key Y_b
    memcpy(ctx->peer_pk, msg2_in, CPACE_PUBLIC_BYTES);

    // 1. Calculate shared secret K = X25519(y_a, Y_b)
    //    y_a should still be in ctx->ephemeral_sk from step 1
    int mult_ret_k = ctx->provider->ecc_iface->scalar_mult(ctx->shared_secret_k, ctx->ephemeral_sk, ctx->peer_pk);
    if (mult_ret_k == CRYPTO_ERR_POINT_IS_IDENTITY) {
        // K is identity - protocol failure!
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return CPACE_ERROR_PEER_KEY_INVALID;
    } else if (mult_ret_k != CRYPTO_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // 2. Derive Intermediate Session Key (ISK)
    cpace_error_t err = derive_intermediate_key_isk(ctx, isk_out);
    if (err != CPACE_OK) {
        ctx->state_flags = CPACE_STATE_ERROR;
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        return err;
    }

    // 3. Cleanse sensitive intermediates
    ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
    ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));

    // 4. Update state
    ctx->state_flags = CPACE_STATE_I_FINISHED;
    return CPACE_OK;
}
