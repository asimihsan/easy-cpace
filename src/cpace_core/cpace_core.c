#include "cpace_core.h"
#include "../common/utils.h" // For construction helpers and is_identity
#include <stdlib.h>          // For malloc, free
#include <string.h>          // For memcpy, memset

// --- Helper Function Prototypes ---

static cpace_error_t calculate_generator_g(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len);

static cpace_error_t derive_intermediate_key_isk(const cpace_ctx_t *ctx, uint8_t *isk_out);

// Helper to safely duplicate input data into the context
static cpace_error_t store_input_data(cpace_ctx_t *ctx, const uint8_t *sid, size_t sid_len, const uint8_t *ci,
                                      size_t ci_len, const uint8_t *ad, size_t ad_len);

// --- Context Management Implementation ---

cpace_ctx_t *cpace_core_ctx_new(void)
{
    // Use calloc for zero-initialization
    cpace_ctx_t *ctx = (cpace_ctx_t *)calloc(1, sizeof(cpace_ctx_t));
    if (!ctx) {
        return NULL;
    }
    // The API layer will set provider and role after allocation
    ctx->state_flags = CPACE_STATE_INITIALIZED;
    return ctx;
}

void cpace_core_ctx_free_internals(cpace_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    // Cleanse-sensitive material - check provider exists first
    if (ctx->provider && ctx->provider->misc_iface && ctx->provider->misc_iface->cleanse) {
        ctx->provider->misc_iface->cleanse(ctx->ephemeral_sk, sizeof(ctx->ephemeral_sk));
        ctx->provider->misc_iface->cleanse(ctx->shared_secret_k, sizeof(ctx->shared_secret_k));
        // Also cleanse g, pk? Maybe less critical but good practice
        ctx->provider->misc_iface->cleanse(ctx->generator, sizeof(ctx->generator));
        ctx->provider->misc_iface->cleanse(ctx->own_pk, sizeof(ctx->own_pk));
        ctx->provider->misc_iface->cleanse(ctx->peer_pk, sizeof(ctx->peer_pk));
    }
    else {
        // Fallback to volatile memset if cleanse unavailable (not ideal)
        memset((void *volatile)ctx->ephemeral_sk, 0, sizeof(ctx->ephemeral_sk));
        memset((void *volatile)ctx->shared_secret_k, 0, sizeof(ctx->shared_secret_k));
        memset((void *volatile)ctx->generator, 0, sizeof(ctx->generator));
        memset((void *volatile)ctx->own_pk, 0, sizeof(ctx->own_pk));
        memset((void *volatile)ctx->peer_pk, 0, sizeof(ctx->peer_pk));
    }

    // Free duplicated input data
    free(ctx->sid);
    free(ctx->ci);
    free(ctx->ad);

    // Zero out the rest of the struct before freeing the memory itself
    // (cleansing handles most sensitive parts)
    memset(ctx, 0, sizeof(cpace_ctx_t));

    // Note: The API layer (`cpace_api.c`) is responsible for free(ctx) itself.
    // This function only handles the internals allocated *by* the core logic.
}

// --- Helper Function Implementations ---

// Safely duplicate input data into the context
static cpace_error_t store_input_data(cpace_ctx_t *ctx, const uint8_t *sid, size_t sid_len, const uint8_t *ci,
                                      size_t ci_len, const uint8_t *ad, size_t ad_len)
{
    // Free potentially existing data first (shouldn't happen with current state machine)
    free(ctx->sid);
    ctx->sid = NULL;
    ctx->sid_len = 0;
    free(ctx->ci);
    ctx->ci = NULL;
    ctx->ci_len = 0;
    free(ctx->ad);
    ctx->ad = NULL;
    ctx->ad_len = 0;

    if (sid_len > 0) {
        ctx->sid = (uint8_t *)malloc(sid_len);
        if (!ctx->sid)
            return CPACE_ERROR_MALLOC;
        memcpy(ctx->sid, sid, sid_len);
        ctx->sid_len = sid_len;
    }
    if (ci_len > 0) {
        ctx->ci = (uint8_t *)malloc(ci_len);
        if (!ctx->ci) {
            free(ctx->sid);
            ctx->sid = NULL;
            return CPACE_ERROR_MALLOC;
        }
        memcpy(ctx->ci, ci, ci_len);
        ctx->ci_len = ci_len;
    }
    if (ad_len > 0) {
        ctx->ad = (uint8_t *)malloc(ad_len);
        if (!ctx->ad) {
            free(ctx->sid);
            ctx->sid = NULL;
            free(ctx->ci);
            ctx->ci = NULL;
            return CPACE_ERROR_MALLOC;
        }
        memcpy(ctx->ad, ad, ad_len);
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
    size_t gen_input_len = cpace_construct_generator_hash_input(prs, prs_len, ctx->ci, ctx->ci_len, ctx->sid,
                                                                ctx->sid_len, gen_input_buf, sizeof(gen_input_buf));
    if (gen_input_len == 0) {
        return CPACE_ERROR_BUFFER_TOO_SMALL; // Or potentially invalid length args to constructor
    }

    // Hash the constructed input (output size is CPACE_CRYPTO_FIELD_SIZE_BYTES for map_to_curve)
    if (ctx->provider->hash_iface->hash_digest(gen_input_buf, gen_input_len, gen_hash_output,
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

// Derive ISK = hash(DSI2 || SID || K || Ya || AD || Yb || AD)
// Assumes K, Ya, Yb, SID, AD are already in the context.
// Ya/Yb order depends on a role.
static cpace_error_t derive_intermediate_key_isk(const cpace_ctx_t *ctx, uint8_t *isk_out)
{
    uint8_t isk_input_buf[1024];                      // Adjust size if needed
    const uint8_t DSI_ISK[] = "CPACE_CRYPTO_DSI_ISK"; // Choose appropriate label
    const uint8_t *ya_ptr;
    const uint8_t *yb_ptr;

    // Determine which public key is Ya and which is Yb based on a role
    if (ctx->role == CPACE_ROLE_INITIATOR) {
        ya_ptr = ctx->own_pk;
        yb_ptr = ctx->peer_pk;
    }
    else { // RESPONDER
        ya_ptr = ctx->peer_pk;
        yb_ptr = ctx->own_pk;
    }

    // Construct input for ISK hash
    // Using the symmetric AD assumption: ADa = ADb = ctx->ad
    size_t isk_input_len = cpace_construct_isk_hash_input(DSI_ISK, sizeof(DSI_ISK) - 1, ctx->sid, ctx->sid_len,
                                                          ctx->shared_secret_k, ya_ptr, ctx->ad, ctx->ad_len, yb_ptr,
                                                          ctx->ad, ctx->ad_len, isk_input_buf, sizeof(isk_input_buf));

    if (isk_input_len == 0) {
        return CPACE_ERROR_BUFFER_TOO_SMALL;
    }

    // Hash the input to get the final ISK
    if (ctx->provider->hash_iface->hash_digest(isk_input_buf, isk_input_len, isk_out, CPACE_ISK_BYTES) != CRYPTO_OK) {
        return CPACE_ERROR_CRYPTO_FAIL;
    }

    return CPACE_OK;
}

// --- Core Protocol Step Implementations ---

cpace_error_t cpace_core_initiator_start(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len, const uint8_t *sid,
                                         size_t sid_len, const uint8_t *ci, size_t ci_len, const uint8_t *ad,
                                         size_t ad_len, uint8_t msg1_out[CPACE_PUBLIC_BYTES])
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
    }
    else if (mult_ret != CRYPTO_OK) {
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

cpace_error_t cpace_core_responder_respond(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len, const uint8_t *sid,
                                           size_t sid_len, const uint8_t *ci, size_t ci_len, const uint8_t *ad,
                                           size_t ad_len, const uint8_t msg1_in[CPACE_PUBLIC_BYTES],
                                           uint8_t msg2_out[CPACE_PUBLIC_BYTES], uint8_t isk_out[CPACE_ISK_BYTES])
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
    }
    else if (mult_ret_yb != CRYPTO_OK) {
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
    }
    else if (mult_ret_k != CRYPTO_OK) {
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

cpace_error_t cpace_core_initiator_finish(cpace_ctx_t *ctx, const uint8_t msg2_in[CPACE_PUBLIC_BYTES],
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
    }
    else if (mult_ret_k != CRYPTO_OK) {
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
