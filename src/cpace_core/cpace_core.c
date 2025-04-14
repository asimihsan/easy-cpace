#include "cpace_core.h"
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
    uint8_t gen_input_buf[512]; // Adjust size if necessary, potentially large
    uint8_t gen_hash_output[CPACE_CRYPTO_FIELD_SIZE_BYTES];

    // Construct input for generator hash
    size_t gen_input_len = cpace_construct_generator_hash_input(prs,
                                                                prs_len,
                                                                ctx->ci_len > 0 ? ctx->ci_buf : NULL,
                                                                ctx->ci_len,
                                                                ctx->sid_len > 0 ? ctx->sid_buf : NULL,
                                                                ctx->sid_len,
                                                                gen_input_buf,
                                                                sizeof(gen_input_buf));
    if (gen_input_len == 0) {
        return CPACE_ERROR_BUFFER_TOO_SMALL;
    }

    // Hash the constructed input (output size is CPACE_CRYPTO_FIELD_SIZE_BYTES for map_to_curve)
    if (ctx->provider->hash_iface->hash_digest(gen_input_buf,
                                               gen_input_len,
                                               gen_hash_output,
                                               CPACE_CRYPTO_FIELD_SIZE_BYTES) != CRYPTO_OK) {
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // Map hash output to curve point
    if (ctx->provider->ecc_iface->map_to_curve(ctx->generator, gen_hash_output) != CRYPTO_OK) {
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // Cleanse intermediate hash output
    ctx->provider->misc_iface->cleanse(gen_hash_output, sizeof(gen_hash_output));

    return CPACE_OK;
}

// Derive ISK = hash(lv(DSI) || lv(SID) || lv(K) || lv(Ya) || lv(ADa) || lv(Yb) || lv(ADb))
// Assumes K, Ya, Yb, SID, AD are already in the context.
// Ya/Yb order depends on role. Uses symmetric AD assumption from API.
static cpace_error_t derive_intermediate_key_isk(const cpace_ctx_t *ctx, uint8_t *isk_out)
{
    uint8_t isk_input_buf[1024]; // Adjust size if needed
    size_t isk_input_len;
    // Use the DSI label from the draft B.1.5
    const uint8_t DSI_ISK[] = "CPace255_ISK";
    const uint8_t *ya_ptr;
    const uint8_t *yb_ptr;

    // Determine which public key is Ya and which is Yb based on role
    if (ctx->role == CPACE_ROLE_INITIATOR) {
        ya_ptr = ctx->own_pk;
        yb_ptr = ctx->peer_pk;
    } else { // RESPONDER
        ya_ptr = ctx->peer_pk;
        yb_ptr = ctx->own_pk;
    }

    // Construct input for ISK hash using the updated lv function
    // Pass ctx->ad_buf for both ADa and ADb, and ctx->ad_len for both lengths
    isk_input_len = cpace_construct_isk_hash_input(DSI_ISK,
                                                   sizeof(DSI_ISK) - 1,
                                                   ctx->sid_len > 0 ? ctx->sid_buf : NULL,
                                                   ctx->sid_len,
                                                   ctx->shared_secret_k, // K
                                                   ya_ptr,               // Ya
                                                   ctx->ad_len > 0 ? ctx->ad_buf : NULL,
                                                   ctx->ad_len, // ADa (using symmetric AD)
                                                   yb_ptr,      // Yb
                                                   ctx->ad_len > 0 ? ctx->ad_buf : NULL,
                                                   ctx->ad_len, // ADb (using symmetric AD)
                                                   isk_input_buf,
                                                   sizeof(isk_input_buf));

    if (isk_input_len == 0) {
        return CPACE_ERROR_BUFFER_TOO_SMALL;
    }

    // Hash the input to get the final ISK (CPACE_ISK_BYTES = 64 for SHA512)
    if (ctx->provider->hash_iface->hash_digest(isk_input_buf, isk_input_len, isk_out, CPACE_ISK_BYTES) != CRYPTO_OK) {
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    // Cleanse intermediate buffer
    ctx->provider->misc_iface->cleanse(isk_input_buf, sizeof(isk_input_buf));

    return CPACE_OK;
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
