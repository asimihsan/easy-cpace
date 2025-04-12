#include "../crypto_iface/crypto_provider.h" // For constants
#include "openssl_elligator2_internal.h"
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/err.h>

// Elligator 2 constants for Curve25519
// p = 2^255 - 19
// A = 486662
// B = 1
// c = -1 (non-square)
// Z = (A - 2) / 4 = (486662 - 2) / 4 = 486660 / 4 = 121665 (RFC 9380 Appendix A.1 uses Z=121665)
// J = A = 486662 (Using notation from cPace-OpenSSL which used J = A)
// Let's use RFC 9380 variable names more closely: A=486662, c=-1, Z=121665
// Elligator2 mapping:
// 1. tv1 = Z * u^2
// 2. tv2 = tv1^2
// 3. xd = (tv1 + 1) * tv1
// 4. xn = (A + tv1) * ( tv2 + A*tv1 )
// 5. If xd == 0, x = A / ( Z * (-2) )  -- Simplified case for u=0
// 6. gxd = xd ^ (p+1)/2  = sqrt(xd) mod p? No, Legendre symbol check. gxd = xd^((p-1)/2) mod p
// 7. If gxd == 1 (xd is QR), x = xn/xd
// 8. If gxd != 1 (xd is NR), x = c * xn/xd = -xn/xd

// Need BIGNUM constants: p, A=486662, Z=121665, c=-1 (represented as p-1), one, two
static BN_CTX *elligator_bn_ctx = NULL;
static BIGNUM *bn_p = NULL; // 2^255 - 19
static BIGNUM *bn_A = NULL; // 486662
static BIGNUM *bn_Z = NULL; // 121665
static BIGNUM *bn_c = NULL; // -1 mod p = p-1
static BIGNUM *bn_one = NULL;
static BIGNUM *bn_two = NULL;
static BIGNUM *bn_p_plus_1_div_2 = NULL;  // (p+1)/2 exponent for sqrt
static BIGNUM *bn_p_minus_1_div_2 = NULL; // (p-1)/2 exponent for Legendre

// Internal init/cleanup for constants
// Returns 1 on success, 0 on failure.
int ensure_elligator_constants(void)
{
    // Check if already initialized (pointer check is sufficient)
    if (bn_p != NULL)
        return 1;

    int ok = 0;
    // Use a local context *only* for the duration of initialization
    BN_CTX *init_ctx = BN_CTX_new();
    if (!init_ctx)
        return 0; // Cannot even create context

    // Allocate global context used by map_to_curve operations
    elligator_bn_ctx = BN_CTX_new();

    // Allocate BIGNUMs
    bn_p = BN_new();
    bn_A = BN_new();
    bn_Z = BN_new();
    bn_c = BN_new();
    bn_one = BN_new();
    bn_two = BN_new();
    bn_p_plus_1_div_2 = BN_new();
    bn_p_minus_1_div_2 = BN_new();

    if (!elligator_bn_ctx || !bn_p || !bn_A || !bn_Z || !bn_c || !bn_one || !bn_two || !bn_p_plus_1_div_2 ||
        !bn_p_minus_1_div_2)
        goto cleanup; // BIGNUM or global ctx allocation failed

    // p = 2^255 - 19
    if (!BN_lshift(bn_p, BN_value_one(), 255))
        goto cleanup;
    if (!BN_sub_word(bn_p, 19))
        goto cleanup;

    // A = 486662
    if (!BN_set_word(bn_A, 486662))
        goto cleanup;
    // Z = 121665
    if (!BN_set_word(bn_Z, 121665))
        goto cleanup;
    // c = p - 1 (use init_ctx here)
    if (!BN_sub_word(bn_c, 1))
        goto cleanup;
    if (!BN_mod_add(bn_c, bn_c, bn_p, bn_p, init_ctx))
        goto cleanup; // Use init_ctx
    // one = 1
    if (!BN_one(bn_one))
        goto cleanup;
    // two = 2
    if (!BN_set_word(bn_two, 2))
        goto cleanup;
    // (p+1)/2 (use init_ctx here)
    if (!BN_add(bn_p_plus_1_div_2, bn_p, bn_one))
        goto cleanup;
    if (!BN_rshift1(bn_p_plus_1_div_2, bn_p_plus_1_div_2))
        goto cleanup;
    // (p-1)/2 (use init_ctx here)
    if (!BN_sub(bn_p_minus_1_div_2, bn_p, bn_one))
        goto cleanup;
    if (!BN_rshift1(bn_p_minus_1_div_2, bn_p_minus_1_div_2))
        goto cleanup;

    ok = 1; // Initialization successful

cleanup:
    BN_CTX_free(init_ctx); // Free the temporary init context regardless of success/failure

    if (!ok) {
        // If init failed partway, clean up everything allocated so far
        // Call the main cleanup function
        openssl_elligator2_cleanup_constants();
    }
    return ok;
}

// Public function called by the backend
// Assumes constants are initialized (ensure_elligator_constants called previously)
int openssl_elligator2_map_to_curve(uint8_t *out_point /* 32 bytes */, const uint8_t *u_bytes /* 32 bytes */)
{
    // Ensure constants are ready (lazy init if user forgot easy_cpace_openssl_init)
    // This might fail but we proceed anyway; subsequent BN operations will likely fail too.
    // Proper usage requires calling easy_cpace_openssl_init() first.
    if (!ensure_elligator_constants()) {
        // Constants not initialized, this call will likely fail below.
        // We could return CRYPTO_ERROR here, but let the BN calls fail naturally.
    }
    // Check if the global context is available (it should be if ensure_... succeeded)
    if (!elligator_bn_ctx) {
        return CRYPTO_ERROR; // Cannot proceed without context
    }

    int ok = 0;
    BIGNUM *u = NULL, *tv1 = NULL, *tv2 = NULL, *xd = NULL, *xn = NULL, *gxd = NULL, *x = NULL, *inv_xd = NULL;
    // Use the globally initialized elligator_bn_ctx for operations within this function
    BN_CTX *ctx = elligator_bn_ctx;
    BN_CTX_start(ctx); // Start a frame for local BIGNUMs

    // Allocate temporary BIGNUMs within the current frame
    u = BN_CTX_get(ctx);
    tv1 = BN_CTX_get(ctx);
    tv2 = BN_CTX_get(ctx);
    xd = BN_CTX_get(ctx);
    xn = BN_CTX_get(ctx);
    gxd = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    inv_xd = BN_CTX_get(ctx);

    // Check if allocations failed (BN_CTX_get returns NULL)
    if (!inv_xd) // Check the last one allocated
        goto cleanup;

    // 1. Decode u from bytes (little-endian) and reduce mod p
    if (!BN_lebin2bn(u_bytes, CPACE_CRYPTO_FIELD_SIZE_BYTES, u))
        goto cleanup;
    if (!BN_mod(u, u, bn_p, ctx))
        goto cleanup; // u = u mod p

    // Handle u=0 case separately
    if (BN_is_zero(u)) {
        // x = A / (Z * -2) mod p. Need modular inverse.
        BIGNUM *den = BN_CTX_get(ctx); // Allocate in frame
        if (!den)
            goto cleanup;
        if (!BN_mod_mul(den, bn_Z, bn_two, bn_p, ctx))
            goto cleanup; // Z*2
        if (!BN_mod_sub(den, bn_p, den, bn_p, ctx))
            goto cleanup; // - (Z*2) mod p
        if (!BN_mod_inverse(den, den, bn_p, ctx))
            goto cleanup; // 1 / (-Z*2)
        if (!BN_mod_mul(x, bn_A, den, bn_p, ctx))
            goto cleanup; // A / (-Z*2)
        // den is auto-freed by BN_CTX_end
    }
    else {
        // Main Elligator 2 path
        // 1. tv1 = Z * u^2 mod p
        if (!BN_mod_sqr(tv1, u, bn_p, ctx))
            goto cleanup;
        if (!BN_mod_mul(tv1, bn_Z, tv1, bn_p, ctx))
            goto cleanup;

        // 2. tv2 = tv1^2 mod p
        if (!BN_mod_sqr(tv2, tv1, bn_p, ctx))
            goto cleanup;

        // 3. xd = (tv1 + 1) * tv1 mod p = tv2 + tv1 mod p
        if (!BN_mod_add(xd, tv2, tv1, bn_p, ctx))
            goto cleanup;

        // 4. xn = (A + tv1) * ( tv2 + A*tv1 ) mod p
        BIGNUM *xn_term1 = BN_CTX_get(ctx);
        BIGNUM *xn_term2 = BN_CTX_get(ctx);
        if (!xn_term2)
            goto cleanup; // Check last one
        if (!BN_mod_add(xn_term1, bn_A, tv1, bn_p, ctx))
            goto cleanup;
        if (!BN_mod_mul(xn_term2, bn_A, tv1, bn_p, ctx))
            goto cleanup;
        if (!BN_mod_add(xn_term2, tv2, xn_term2, bn_p, ctx))
            goto cleanup;
        if (!BN_mod_mul(xn, xn_term1, xn_term2, bn_p, ctx))
            goto cleanup;
        // xn_term1, xn_term2 are auto-freed

        // 5. If xd == 0
        if (BN_is_zero(xd)) {
            BIGNUM *den = BN_CTX_get(ctx);
            if (!den)
                goto cleanup;
            if (!BN_mod_mul(den, bn_Z, bn_two, bn_p, ctx))
                goto cleanup; // Z*2
            if (!BN_mod_sub(den, bn_p, den, bn_p, ctx))
                goto cleanup; // - (Z*2) mod p
            if (!BN_mod_inverse(den, den, bn_p, ctx))
                goto cleanup; // 1 / (-Z*2)
            if (!BN_mod_mul(x, bn_A, den, bn_p, ctx))
                goto cleanup; // A / (-Z*2)
                              // den auto-freed
        }
        else {
            // 6. gxd = legendre(xd, p) = xd^((p-1)/2) mod p
            if (!BN_mod_exp(gxd, xd, bn_p_minus_1_div_2, bn_p, ctx))
                goto cleanup;

            // Calculate inverse needed for both cases: inv_xd = xd^-1 mod p
            if (!BN_mod_inverse(inv_xd, xd, bn_p, ctx))
                goto cleanup;

            // 7. If gxd == 1 (QR) -> x = xn / xd = xn * inv_xd mod p
            BIGNUM *x_qr = BN_CTX_get(ctx);
            if (!x_qr)
                goto cleanup;
            if (!BN_mod_mul(x_qr, xn, inv_xd, bn_p, ctx))
                goto cleanup;

            // 8. If gxd != 1 (NR or 0) -> x = c * xn / xd = -1 * xn * inv_xd mod p
            BIGNUM *x_nr = BN_CTX_get(ctx);
            if (!x_nr)
                goto cleanup;
            if (!BN_mod_mul(x_nr, bn_c, x_qr, bn_p, ctx))
                goto cleanup; // x_nr = -x_qr

            // Select x based on gxd using constant-time conditional select if possible.
            // BN_is_one(gxd) determines the condition (1 if QR, 0 otherwise)
            // BN_copy selects based on non-constant time condition.
            // For constant time: BN_conditional_copy(to, from_1, from_0, condition)
            // condition = BN_is_one(gxd); // 1 if QR, 0 if NR/Zero
            // Need to check if BN_conditional_copy exists and works as expected.
            // Assuming it exists and condition=1 means copy from_1:
            // BN_conditional_copy(x, x_qr, x_nr, BN_is_one(gxd)); // If QR (gxd=1) copy x_qr, else copy x_nr
            // Let's use the simple conditional for now, aware of side channels.
            if (BN_is_one(gxd)) {
                if (!BN_copy(x, x_qr))
                    goto cleanup;
            }
            else {
                if (!BN_copy(x, x_nr))
                    goto cleanup;
            }
            // x_qr, x_nr auto-freed
        }
    }

    // Convert result x to little-endian bytes
    if (BN_bn2lebinpad(x, out_point, CPACE_CRYPTO_POINT_BYTES) <= 0)
        goto cleanup;

    ok = 1; // Success

cleanup:
    // Free BIGNUMs allocated in the frame
    if (ctx) {
        BN_CTX_end(ctx);
    }
    // Don't free the global elligator_bn_ctx here

    return ok ? CRYPTO_OK : CRYPTO_ERROR;
}

// Cleanup function remains largely the same, frees statics
void openssl_elligator2_cleanup_constants()
{
    // Free static BIGNUMs
    BN_free(bn_p_minus_1_div_2);
    bn_p_minus_1_div_2 = NULL;
    BN_free(bn_p_plus_1_div_2);
    bn_p_plus_1_div_2 = NULL;
    BN_free(bn_two);
    bn_two = NULL;
    BN_free(bn_one);
    bn_one = NULL;
    BN_free(bn_c);
    bn_c = NULL;
    BN_free(bn_Z);
    bn_Z = NULL;
    BN_free(bn_A);
    bn_A = NULL;
    BN_free(bn_p);
    bn_p = NULL;

    // Free the static context
    if (elligator_bn_ctx) {
        BN_CTX_free(elligator_bn_ctx);
        elligator_bn_ctx = NULL;
    }
}
