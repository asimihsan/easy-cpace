#include "../../include/easy_cpace.h"
#include "../cpace_core/cpace_core.h" // Internal core logic header
#include <stdlib.h>                   // For NULL, free

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

cpace_ctx_t *cpace_ctx_new(cpace_role_t role, const crypto_provider_t *provider)
{
    // Basic validation
    if (!is_valid_provider(provider)) {
        return NULL; // Invalid provider
    }
    if (role != CPACE_ROLE_INITIATOR && role != CPACE_ROLE_RESPONDER) {
        return NULL; // Invalid role
    }

    // Allocate using the core function
    cpace_ctx_t *ctx = cpace_core_ctx_new();
    if (!ctx) {
        return NULL; // Allocation failed
    }

    // Assign provider and role
    ctx->provider = provider;
    ctx->role = role;
    // State defaults to CPACE_STATE_INITIALIZED via calloc in core_ctx_new

    return ctx;
}

void cpace_ctx_free(cpace_ctx_t *ctx)
{
    if (ctx == NULL) {
        return; // Safe to call with NULL
    }

    // Free internal data (SID/CI/AD copies) and cleanse keys
    // Requires provider to be valid, which should be true if ctx_new succeeded.
    if (ctx->provider) {
        cpace_core_ctx_free_internals(ctx);
    }

    // Free the context structure itself
    free(ctx);
}

// --- Protocol Steps Implementation ---

cpace_error_t cpace_initiator_start(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len, const uint8_t *sid,
                                    size_t sid_len, const uint8_t *ci, size_t ci_len, const uint8_t *ad, size_t ad_len,
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
        // Allow re-start? No, spec implies one-shot. Mark as error.
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_STATE;
    }
    // Ensure provider is still valid (paranoid check)
    if (!is_valid_provider(ctx->provider)) {
        ctx->state_flags = CPACE_STATE_ERROR;
        return CPACE_ERROR_INVALID_ARGUMENT; // Or maybe crypto fail?
    }

    // --- Call Core Logic ---
    cpace_error_t result =
        cpace_core_initiator_start(ctx, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1_out);

    // Core function should update state_flags internally on success/failure
    return result;
}

cpace_error_t cpace_responder_respond(cpace_ctx_t *ctx, const uint8_t *prs, size_t prs_len, const uint8_t *sid,
                                      size_t sid_len, const uint8_t *ci, size_t ci_len, const uint8_t *ad,
                                      size_t ad_len, const uint8_t msg1_in[CPACE_PUBLIC_BYTES],
                                      uint8_t msg2_out[CPACE_PUBLIC_BYTES], uint8_t isk_out[CPACE_ISK_BYTES])
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
    cpace_error_t result = cpace_core_responder_respond(ctx, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len,
                                                        msg1_in, msg2_out, isk_out);

    return result;
}

cpace_error_t cpace_initiator_finish(cpace_ctx_t *ctx, const uint8_t msg2_in[CPACE_PUBLIC_BYTES],
                                     uint8_t isk_out[CPACE_ISK_BYTES])
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
    cpace_error_t result = cpace_core_initiator_finish(ctx, msg2_in, isk_out);

    return result;
}

// Note: cpace_get_provider_openssl() and cpace_get_provider_mbedtls()
// are implemented in their respective backend C files (e.g., openssl_backend.c)
// and declared in easy_cpace.h. They are not part of this API implementation file.
