#include "../crypto_iface/crypto_provider.h" // For constants
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
static int ensure_elligator_constants(void)
{
    if (bn_p != NULL)
        return 1; // Already initialized

    int ok = 0;
    elligator_bn_ctx = BN_CTX_new();
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
        goto cleanup;

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
    // c = p - 1
    if (!BN_sub_word(bn_c, 1))
        goto cleanup; // c = -1 temp
    if (!BN_mod_add(bn_c, bn_c, bn_p, bn_p, elligator_bn_ctx))
        goto cleanup; // c = p-1
    // one = 1
    if (!BN_one(bn_one))
        goto cleanup;
    // two = 2
    if (!BN_set_word(bn_two, 2))
        goto cleanup;
    // (p+1)/2
    if (!BN_add(bn_p_plus_1_div_2, bn_p, bn_one))
        goto cleanup;
    if (!BN_rshift1(bn_p_plus_1_div_2, bn_p_plus_1_div_2))
        goto cleanup;
    // (p-1)/2
    if (!BN_sub(bn_p_minus_1_div_2, bn_p, bn_one))
        goto cleanup;
    if (!BN_rshift1(bn_p_minus_1_div_2, bn_p_minus_1_div_2))
        goto cleanup;

    // Mark constants as constant time if needed/possible? Might not apply here.
    // BN_set_flags(bn_p, BN_FLG_CONSTTIME); // Not usually needed for modulus

    ok = 1;

cleanup:
    if (!ok) {
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
        BN_CTX_free(elligator_bn_ctx);
        elligator_bn_ctx = NULL;
    }
    return ok;
}

// Public function called by the backend
int openssl_elligator2_map_to_curve(uint8_t *out_point /* 32 bytes */, const uint8_t *u_bytes /* 32 bytes */)
{
    int ok = 0;
    BIGNUM *u = NULL, *tv1 = NULL, *tv2 = NULL, *xd = NULL, *xn = NULL, *gxd = NULL, *x = NULL, *inv_xd = NULL;
    BN_CTX *ctx = NULL; // Use local ctx

    if (!ensure_elligator_constants())
        return CRYPTO_ERROR;
    if (!out_point || !u_bytes)
        return CRYPTO_ERROR;

    ctx = BN_CTX_new();
    u = BN_new();
    tv1 = BN_new();
    tv2 = BN_new();
    xd = BN_new();
    xn = BN_new();
    gxd = BN_new();
    x = BN_new();
    inv_xd = BN_new();
    if (!ctx || !u || !tv1 || !tv2 || !xd || !xn || !gxd || !x || !inv_xd)
        goto cleanup;

    // 1. Decode u from bytes (little-endian) and reduce mod p
    if (!BN_lebin2bn(u_bytes, CPACE_CRYPTO_FIELD_SIZE_BYTES, u))
        goto cleanup;
    if (!BN_mod(u, u, bn_p, ctx))
        goto cleanup; // u = u mod p

    // Handle u=0 case separately (optional, but might simplify main path)
    if (BN_is_zero(u)) {
        // x = A / (Z * -2) mod p. Need modular inverse.
        BIGNUM *den = BN_new();
        if (!den)
            goto cleanup;
        if (!BN_mod_mul(den, bn_Z, bn_two, bn_p, ctx)) {
            BN_free(den);
            goto cleanup;
        } // Z*2
        if (!BN_mod_sub(den, bn_p, den, bn_p, ctx)) {
            BN_free(den);
            goto cleanup;
        } // - (Z*2) mod p
        if (!BN_mod_inverse(den, den, bn_p, ctx)) {
            BN_free(den);
            goto cleanup;
        } // 1 / (-Z*2)
        if (!BN_mod_mul(x, bn_A, den, bn_p, ctx)) {
            BN_free(den);
            goto cleanup;
        } // A / (-Z*2)
        BN_free(den);
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
        //    xn_term1 = A + tv1
        //    xn_term2 = tv2 + A*tv1
        BIGNUM *xn_term1 = BN_new();
        BIGNUM *xn_term2 = BN_new();
        if (!xn_term1 || !xn_term2) {
            BN_free(xn_term1);
            BN_free(xn_term2);
            goto cleanup;
        }
        if (!BN_mod_add(xn_term1, bn_A, tv1, bn_p, ctx)) {
            BN_free(xn_term1);
            BN_free(xn_term2);
            goto cleanup;
        }
        if (!BN_mod_mul(xn_term2, bn_A, tv1, bn_p, ctx)) {
            BN_free(xn_term1);
            BN_free(xn_term2);
            goto cleanup;
        }
        if (!BN_mod_add(xn_term2, tv2, xn_term2, bn_p, ctx)) {
            BN_free(xn_term1);
            BN_free(xn_term2);
            goto cleanup;
        }
        if (!BN_mod_mul(xn, xn_term1, xn_term2, bn_p, ctx)) {
            BN_free(xn_term1);
            BN_free(xn_term2);
            goto cleanup;
        }
        BN_free(xn_term1);
        BN_free(xn_term2);

        // 5. If xd == 0 (should only happen if tv1 = 0 or tv1 = -1)
        //    The u=0 case handles tv1=0. If tv1 = -1, then u^2 = -1/Z.
        //    If xd == 0, RFC says use the exception case x = A / (Z * -2).
        if (BN_is_zero(xd)) {
            BIGNUM *den = BN_new();
            if (!den)
                goto cleanup;
            if (!BN_mod_mul(den, bn_Z, bn_two, bn_p, ctx)) {
                BN_free(den);
                goto cleanup;
            } // Z*2
            if (!BN_mod_sub(den, bn_p, den, bn_p, ctx)) {
                BN_free(den);
                goto cleanup;
            } // - (Z*2) mod p
            if (!BN_mod_inverse(den, den, bn_p, ctx)) {
                BN_free(den);
                goto cleanup;
            } // 1 / (-Z*2)
            if (!BN_mod_mul(x, bn_A, den, bn_p, ctx)) {
                BN_free(den);
                goto cleanup;
            } // A / (-Z*2)
            BN_free(den);
        }
        else {
            // 6. gxd = legendre(xd, p) = xd^((p-1)/2) mod p
            if (!BN_mod_exp(gxd, xd, bn_p_minus_1_div_2, bn_p, ctx))
                goto cleanup;

            // Calculate inverse needed for both cases: inv_xd = xd^-1 mod p
            if (!BN_mod_inverse(inv_xd, xd, bn_p, ctx))
                goto cleanup;

            // 7. If gxd == 1 (QR) -> x = xn / xd = xn * inv_xd mod p
            BIGNUM *x_qr = BN_new();
            if (!x_qr)
                goto cleanup;
            if (!BN_mod_mul(x_qr, xn, inv_xd, bn_p, ctx)) {
                BN_free(x_qr);
                goto cleanup;
            }

            // 8. If gxd != 1 (NR or 0 - handled above) -> x = c * xn / xd = -1 * xn * inv_xd mod p
            BIGNUM *x_nr = BN_new();
            if (!x_nr) {
                BN_free(x_qr);
                goto cleanup;
            }
            if (!BN_mod_mul(x_nr, bn_c, x_qr, bn_p, ctx)) {
                BN_free(x_qr);
                BN_free(x_nr);
                goto cleanup;
            } // x_nr = -x_qr

            // Select x based on gxd using constant-time conditional select logic if possible.
            // BN_cmp(gxd, bn_one) == 0 means gxd == 1.
            // BN_cmp returns -1, 0, 1. We need 0 or 1 for the selector.
            // Let's use a simple conditional for now, aware of side channels.
            // TODO: Implement constant-time select using BN_is_one() or BN_cmp() carefully.
            // BN_is_one() might be okay.
            if (BN_is_one(gxd)) {
                if (!BN_copy(x, x_qr)) {
                    BN_free(x_qr);
                    BN_free(x_nr);
                    goto cleanup;
                }
            }
            else {
                if (!BN_copy(x, x_nr)) {
                    BN_free(x_qr);
                    BN_free(x_nr);
                    goto cleanup;
                }
            }
            BN_free(x_qr);
            BN_free(x_nr);
        }
    }

    // Convert result x to little-endian bytes
    if (BN_bn2lebinpad(x, out_point, CPACE_CRYPTO_POINT_BYTES) <= 0)
        goto cleanup;

    ok = 1; // Success

cleanup:
    // Free local BIGNUMs
    BN_clear_free(inv_xd);
    BN_clear_free(x);
    BN_clear_free(gxd);
    BN_clear_free(xn);
    BN_clear_free(xd);
    BN_clear_free(tv2);
    BN_clear_free(tv1);
    BN_clear_free(u);
    BN_CTX_free(ctx); // Free local context

    // Static constants are freed elsewhere if needed (e.g., library unload)

    return ok ? CRYPTO_OK : CRYPTO_ERROR;
}

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

    if (elligator_bn_ctx) {
        BN_CTX_free(elligator_bn_ctx);
        elligator_bn_ctx = NULL;
    }
}
