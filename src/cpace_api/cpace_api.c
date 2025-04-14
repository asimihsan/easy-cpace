#include "../../include/easy_cpace.h"
#include "../cpace_core/cpace_core.h" // Internal core logic header
#include <stdio.h>
#include <stdlib.h> // For NULL

// --- Helper for checking provider validity ---
static int is_valid_provider(const crypto_provider_t *provider)
{
    if (!provider || !provider->hash_iface || !provider->ecc_iface || !provider->misc_iface) {
        return 0; // Essential interfaces must be present
    }
    // Could add more checks for specific function pointers if needed
    return 1;
}

// --- Context Management Implementation ---

cpace_error_t cpace_ctx_init(cpace_ctx_t *ctx, cpace_role_t role, const crypto_provider_t *provider)
{
    // Basic validation
    if (!ctx) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    if (!is_valid_provider(provider)) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    if (role != CPACE_ROLE_INITIATOR && role != CPACE_ROLE_RESPONDER) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // Initialize the context using core function
    return cpace_core_ctx_init(ctx, role, provider);
}

void cpace_ctx_cleanup(cpace_ctx_t *ctx)
{
    if (!ctx) {
        return; // Safe to call with NULL
    }

    // Clean up internal state and cleanse keys
    cpace_core_ctx_cleanup(ctx);
}

// --- Protocol Steps Implementation ---

cpace_error_t cpace_initiator_start(cpace_ctx_t *ctx,
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
    // --- Argument Validation ---
    if (!ctx || !ctx->provider || !prs || !msg1_out) {
        // Cannot set ctx state to error if ctx is NULL
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // Check role and state
    if (ctx->role != CPACE_ROLE_INITIATOR) {
        ctx->state_flags = CPACE_STATE_ERROR; // Mark context as unusable
        return CPACE_ERROR_INVALID_STATE;
    }

    if (ctx->state_flags != CPACE_STATE_INITIALIZED) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }

    // Ensure provider is still valid (paranoid check)
    if (!is_valid_provider(ctx->provider)) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // --- Call Core Logic ---
    return cpace_core_initiator_start(ctx, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1_out);
}

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
                                      uint8_t isk_out[CPACE_ISK_BYTES])
{
    // --- Argument Validation ---
    if (!ctx || !ctx->provider || !prs || !msg1_in || !msg2_out || !isk_out) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // Check role and state
    if (ctx->role != CPACE_ROLE_RESPONDER) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }

    if (ctx->state_flags != CPACE_STATE_INITIALIZED) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }

    if (!is_valid_provider(ctx->provider)) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // --- Call Core Logic ---
    return cpace_core_responder_respond(ctx,
                                        prs,
                                        prs_len,
                                        sid,
                                        sid_len,
                                        ci,
                                        ci_len,
                                        ad,
                                        ad_len,
                                        msg1_in,
                                        msg2_out,
                                        isk_out);
}

cpace_error_t
cpace_initiator_finish(cpace_ctx_t *ctx, const uint8_t msg2_in[CPACE_PUBLIC_BYTES], uint8_t isk_out[CPACE_ISK_BYTES])
{
    // --- Argument Validation ---
    if (!ctx || !ctx->provider || !msg2_in || !isk_out) {
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // Check role and state
    if (ctx->role != CPACE_ROLE_INITIATOR) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }

    // Must have called start previously
    if (ctx->state_flags != CPACE_STATE_I_STARTED) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }

    if (!is_valid_provider(ctx->provider)) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_ARGUMENT;
    }

    // --- Call Core Logic ---
    return cpace_core_initiator_finish(ctx, msg2_in, isk_out);
}

// Note: cpace_get_provider_monocypher() is implemented in the backend C file
// (monocypher_backend.c) and declared in easy_cpace.h.
