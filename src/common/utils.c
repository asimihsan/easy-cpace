#include "utils.h"
#include <assert.h>
#include <string.h> // For memcpy, memset

// Internal helper for constant time conditional select.
// selects b if cond is 1, a if cond is 0.
// cond must be 0 or 1.
static uint8_t cpace_const_time_select(uint8_t a, uint8_t b, uint8_t cond)
{
    // mask is 0xFF if cond=1, 0x00 if cond=0
    uint8_t mask = (uint8_t)(-(int8_t)cond);
    return (uint8_t)(a ^ (mask & (a ^ b)));
}

// Constant-time memory comparison
int cpace_const_time_memcmp(const void *a, const void *b, size_t size)
{
    const uint8_t *a_ptr = (const uint8_t *)a;
    const uint8_t *b_ptr = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < size; ++i) {
        diff |= (a_ptr[i] ^ b_ptr[i]);
    }
    // If any byte is different, diff will be non-zero.
    // Convert non-zero to 1, zero stays zero.
    // Trick: (diff | -diff) >> 7 (assuming 8-bit byte and 2's complement)
    // Simpler: return diff != 0, but that might not be constant time.
    // More robust constant time check:
    // Shift diff bits right until only MSB potentially remains, check if non-zero.
    // Or use a masking approach:
    uint8_t is_zero_mask = 0; // Will be 0xFF if diff is 0, 0x00 otherwise
    // This relies on compiler not optimizing out the loop based on diff value
    // A common trick is to use volatile or specific assembly if needed.
    // Let's try a simpler approach that's often constant time on modern CPUs:
    // Convert diff to 0 or 1 using bitwise ops that avoid branching.
    // If diff is 0, result is 0. If diff is non-zero, result is non-zero (e.g. 1).
    // (diff | (0 - diff)) >> (sizeof(diff)*8 - 1) -> only works for signed types?
    // Let's use a simpler reduction:
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    // Now diff's LSB is 1 if original diff was non-zero, 0 otherwise.
    return (int)(diff & 1);
}

#ifdef CPACE_DEBUG_LOG
#include <stdio.h> // Include stdio only when debugging is enabled
// Debug print helper implementation
void cpace_debug_print_hex(const char *label, const uint8_t *data, size_t len)
{
    if (!label || !data) {
        return;
    }
    printf("DEBUG: %s (%zu bytes): ", label, len);
    if (len == 0) {
        printf("(empty)\n");
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
#endif // CPACE_DEBUG_LOG

// Check if point is identity (all zeros)
int cpace_is_identity(const uint8_t point[CPACE_CRYPTO_POINT_BYTES])
{
    uint8_t result = 0;
    for (size_t i = 0; i < CPACE_CRYPTO_POINT_BYTES; ++i) {
        result |= point[i];
    }
    // Return 1 if result is 0, 0 otherwise (using constant time compare idea)
    return cpace_const_time_memcmp(&result, "\0", 1) == 0;
}

// Helper to safely append data to a buffer
static uint8_t *append_data(uint8_t *dest, const uint8_t *src, size_t len, size_t *written, size_t capacity)
{
    if (!dest || !src || (*written + len) > capacity) {
        return NULL; // Error: buffer overflow or invalid input
    }
    memcpy(dest + *written, src, len);
    *written += len;
    return dest; // Return original dest pointer for chaining (or NULL on error)
}

// Internal helper to append length-prefixed data (single byte length)
// Returns updated dest pointer or NULL on error.
static uint8_t *append_lv(uint8_t *dest, const uint8_t *src, size_t len, size_t *written, size_t capacity)
{
    if (!dest || len > 255) { // Check length fits in one byte
        return NULL;
    }
    // Check capacity: need 1 byte for length + len bytes for data
    if ((*written + 1 + len) > capacity) {
        return NULL; // Error: buffer overflow
    }
    uint8_t u8_len = (uint8_t)len;
    memcpy(dest + *written, &u8_len, 1);
    *written += 1;
    if (len > 0) { // Only copy data if length > 0
        if (!src) {
            return NULL; // Source must be valid if len > 0
        }
        memcpy(dest + *written, src, len);
        *written += len;
    }
    return dest; // Return original dest pointer for chaining
}

// Construct input for ISK derivation hash
// Format: lv(dsi_label) || lv(sid) || lv(K) || lv(Ya) || lv(ADa) || lv(Yb) || lv(ADb)
size_t cpace_construct_isk_hash_input(const uint8_t *dsi_label,
                                      size_t dsi_label_len,
                                      const uint8_t *sid,
                                      size_t sid_len,
                                      const uint8_t K[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t Ya[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t *ADa,
                                      size_t ADa_len,
                                      const uint8_t Yb[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t *ADb,
                                      size_t ADb_len,
                                      uint8_t *out,
                                      size_t out_capacity)
{
    size_t written = 0;
    uint8_t *current_out = out;

    // Validate inputs and lengths (single-byte length limit)
    if (dsi_label_len > 255 || sid_len > 255 || ADa_len > 255 || ADb_len > 255 ||
        CPACE_CRYPTO_POINT_BYTES > 255 /* Should not happen */) {
        return 0; // Invalid length for lv encoding
    }
    if (!K || !Ya || !Yb || !out || (dsi_label_len > 0 && !dsi_label) || (sid_len > 0 && !sid) ||
        (ADa_len > 0 && !ADa) || (ADb_len > 0 && !ADb)) {
        return 0; // Invalid argument
    }

    // Calculate required size: Sum of (1 + length) for each component
    size_t required_size = (1 + dsi_label_len) + (1 + sid_len) + (1 + CPACE_CRYPTO_POINT_BYTES) +
                           (1 + CPACE_CRYPTO_POINT_BYTES) + (1 + ADa_len) + (1 + CPACE_CRYPTO_POINT_BYTES) +
                           (1 + ADb_len);

    if (out_capacity < required_size) {
        return 0; // Buffer too small
    }

    // Append components using length-value encoding
    current_out = append_lv(current_out, dsi_label, dsi_label_len, &written, out_capacity);
    current_out = append_lv(current_out, sid, sid_len, &written, out_capacity);
    current_out = append_lv(current_out, K, CPACE_CRYPTO_POINT_BYTES, &written, out_capacity);
    current_out = append_lv(current_out, Ya, CPACE_CRYPTO_POINT_BYTES, &written, out_capacity);
    current_out = append_lv(current_out, ADa, ADa_len, &written, out_capacity);
    current_out = append_lv(current_out, Yb, CPACE_CRYPTO_POINT_BYTES, &written, out_capacity);
    current_out = append_lv(current_out, ADb, ADb_len, &written, out_capacity);

    if (!current_out) { // Check if any append failed
        // Should ideally cleanse 'out' buffer here if partially written
        memset(out, 0, out_capacity); // Simple cleanse
        return 0;
    }

    assert(written == required_size);
    return written;
}

// Construct input string for generator hash according to RFC Appendix A.2 (lv_cat)
// Format: lv(DSI) || lv(PRS) || lv(ZPAD) || lv(CI) || lv(SID)
size_t cpace_construct_generator_hash_input(const uint8_t *prs,
                                            size_t prs_len,
                                            const uint8_t *ci,
                                            size_t ci_len,
                                            const uint8_t *sid,
                                            size_t sid_len,
                                            uint8_t *out,
                                            size_t out_size)
{
    size_t written = 0;
    uint8_t *current_out = out;
    size_t required_size = 0;
    size_t zpad_len = 0;
    uint8_t zpad_buf[CPACE_CRYPTO_HASH_BLOCK_BYTES]; // Max possible ZPAD size

    // Validate lengths for single-byte lv encoding
    if (CPACE_CRYPTO_DSI_LEN > 255 || prs_len > 255 || ci_len > 255 || sid_len > 255) {
        return 0; // Lengths too large for single-byte encoding
    }
    if (!prs || !ci || !sid || !out) {
        return 0; // Invalid arguments
    }

    // Calculate ZPAD length based on RFC A.2
    // len(prepend_len(X)) = 1 + len(X) for single-byte length
    size_t lv_dsi_len = 1 + CPACE_CRYPTO_DSI_LEN;
    size_t lv_prs_len = 1 + prs_len;
    if ((lv_dsi_len + lv_prs_len) < (CPACE_CRYPTO_HASH_BLOCK_BYTES - 1)) { // -1 for the ZPAD length byte itself
        zpad_len = CPACE_CRYPTO_HASH_BLOCK_BYTES - 1 - lv_prs_len - lv_dsi_len;
    }
    // Ensure zpad_len doesn't exceed buffer or 255
    if (zpad_len > sizeof(zpad_buf) || zpad_len > 255) {
        // This case should ideally not happen with standard block sizes and inputs
        return 0; // ZPAD too large
    }
    memset(zpad_buf, 0, zpad_len); // Prepare ZPAD content

    // Calculate total required size for lv_cat(DSI, PRS, ZPAD, CI, SID)
    required_size = (1 + CPACE_CRYPTO_DSI_LEN) + (1 + prs_len) + (1 + zpad_len) + (1 + ci_len) + (1 + sid_len);

    if (out_size < required_size) {
        return 0; // Buffer too small
    }

    // Construct using lv encoding for all parts
    current_out = append_lv(current_out, (const uint8_t *)CPACE_CRYPTO_DSI, CPACE_CRYPTO_DSI_LEN, &written, out_size);
    current_out = append_lv(current_out, prs, prs_len, &written, out_size);
    current_out = append_lv(current_out, zpad_buf, zpad_len, &written, out_size); // Append ZPAD content
    current_out = append_lv(current_out, ci, ci_len, &written, out_size);
    current_out = append_lv(current_out, sid, sid_len, &written, out_size);

    if (!current_out) {           // Check if any append failed
        memset(out, 0, out_size); // Simple cleanse
        return 0;
    }

    assert(written == required_size);

#ifdef CPACE_DEBUG_LOG
    cpace_debug_print_hex("Constructed Generator Input", out, written);
#endif // CPACE_DEBUG_LOG
    return written;
}
