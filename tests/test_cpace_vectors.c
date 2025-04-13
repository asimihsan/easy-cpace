#include "../include/easy_cpace.h"
#include "../src/common/utils.h"                 // For direct testing of construct functions
#include "../src/crypto_iface/crypto_provider.h" // For crypto interface types
#include "unity.h"
#include "unity_test_helpers.h"
#include <stdio.h>  // For printf
#include <string.h> // For memcmp

// --- Test Vectors from draft-irtf-cfrg-cpace-13 Appendix B.1.8 ---
// (Copied directly from the draft)
const unsigned char tc_PRS[] = {0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};
const size_t tc_PRS_len = sizeof(tc_PRS);
const unsigned char tc_CI[] = {0x6f, 0x63, 0x0b, 0x42, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65,
                               0x72, 0x0b, 0x41, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72};
const size_t tc_CI_len = sizeof(tc_CI);
const unsigned char tc_sid[] = {
    0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57};
const size_t tc_sid_len = sizeof(tc_sid);
const unsigned char tc_g[] = {0x64, 0xe8, 0x09, 0x9e, 0x3e, 0xa6, 0x82, 0xcf, 0xdc, 0x5c, 0xb6,
                              0x65, 0xc0, 0x57, 0xeb, 0xb5, 0x14, 0xd0, 0x6b, 0xf2, 0x3e, 0xbc,
                              0x9f, 0x74, 0x3b, 0x51, 0xb8, 0x22, 0x42, 0x32, 0x70, 0x74};
// const unsigned char tc_ya[] = { ... }; // Not used directly by API tests
const unsigned char tc_ADa[] = {0x41, 0x44, 0x61};
const size_t tc_ADa_len = sizeof(tc_ADa);
const unsigned char tc_Ya[] = {0x1b, 0x02, 0xda, 0xd6, 0xdb, 0xd2, 0x9a, 0x07, 0xb6, 0xd2, 0x8c,
                               0x9e, 0x04, 0xcb, 0x2f, 0x18, 0x4f, 0x07, 0x34, 0x35, 0x0e, 0x32,
                               0xbb, 0x7e, 0x62, 0xff, 0x9d, 0xbc, 0xfd, 0xb6, 0x3d, 0x15};
// const unsigned char tc_yb[] = { ... }; // Not used directly by API tests
const unsigned char tc_ADb[] = {0x41, 0x44, 0x62};
const size_t tc_ADb_len = sizeof(tc_ADb);
const unsigned char tc_Yb[] = {0x20, 0xcd, 0xa5, 0x95, 0x5f, 0x82, 0xc4, 0x93, 0x15, 0x45, 0xbc,
                               0xbf, 0x40, 0x75, 0x8c, 0xe1, 0x01, 0x0d, 0x7d, 0xb4, 0xdb, 0x2a,
                               0x90, 0x70, 0x13, 0xd7, 0x9c, 0x7a, 0x8f, 0xcf, 0x95, 0x7f};
const unsigned char tc_K[] = {0xf9, 0x7f, 0xdf, 0xcf, 0xff, 0x1c, 0x98, 0x3e, 0xd6, 0x28, 0x38,
                              0x56, 0xa4, 0x01, 0xde, 0x31, 0x91, 0xca, 0x91, 0x99, 0x02, 0xb3,
                              0x23, 0xc5, 0xf9, 0x50, 0xc9, 0x70, 0x3d, 0xf7, 0x29, 0x7a};
const unsigned char tc_ISK_IR[] = {0xa0, 0x51, 0xee, 0x5e, 0xe2, 0x49, 0x9d, 0x16, 0xda, 0x3f, 0x69, 0xf4, 0x30,
                                   0x21, 0x8b, 0x8e, 0xa9, 0x4a, 0x18, 0xa4, 0x5b, 0x67, 0xf9, 0xe8, 0x64, 0x95,
                                   0xb3, 0x82, 0xc3, 0x3d, 0x14, 0xa5, 0xc3, 0x8c, 0xec, 0xc0, 0xcc, 0x83, 0x4f,
                                   0x96, 0x0e, 0x39, 0xe0, 0xd1, 0xbf, 0x7d, 0x76, 0xb9, 0xef, 0x5d, 0x54, 0xee,
                                   0xcc, 0x5e, 0x0f, 0x38, 0x6c, 0x97, 0xad, 0x12, 0xda, 0x8c, 0x3d, 0x5f};
// Expected output from cpace_construct_generator_hash_input (B.1.1) - Corrected to 172 bytes based on RFC 7.1 definition
const unsigned char tc_generator_string[] = {
    // lv(DSI) = 0x08 || "CPace255" (9 bytes)
    0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35,
    // lv(PRS) = 0x08 || "Password" (9 bytes)
    0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
    // lv(ZPAD) = 0x6d || 109 * 0x00 (110 bytes)
    0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // lv(CI) = 0x1a || "oc..." (27 bytes)
    0x1a, 0x6f, 0x63, 0x0b, 0x42, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x0b, 0x41, 0x5f, 0x69,
    0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
    // lv(sid) = 0x10 || sid_bytes (17 bytes)
    0x10, 0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57};
// Explicitly define the length to avoid potential sizeof issues/compiler quirks
#define TC_GENERATOR_STRING_LEN 172
const size_t tc_generator_string_len = TC_GENERATOR_STRING_LEN;
// Expected hash output from generator string (B.1.1) - first 32 bytes for map_to_curve
const unsigned char tc_generator_hash[] = {0x92, 0x80, 0x6d, 0xc6, 0x08, 0x98, 0x4d, 0xbf, 0x4e, 0x4a, 0xae,
                                           0x47, 0x8c, 0x6e, 0xc4, 0x53, 0xae, 0x97, 0x9c, 0xc0, 0x1e, 0xcc,
                                           0x1a, 0x2a, 0x7c, 0xf4, 0x9f, 0x5c, 0xee, 0x56, 0x55, 0x1b};
// Expected ISK input string (B.1.5) - decode from hex
const unsigned char tc_isk_input_string[] = {
    0x0c, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x5f, 0x49, 0x53, 0x4b, 0x10, 0x7e, 0x4b, 0x47, 0x91,
    0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57, 0x20, 0xf9, 0x7f, 0xdf, 0xcf, 0xff,
    0x1c, 0x98, 0x3e, 0xd6, 0x28, 0x38, 0x56, 0xa4, 0x01, 0xde, 0x31, 0x91, 0xca, 0x91, 0x99, 0x02, 0xb3, 0x23,
    0xc5, 0xf9, 0x50, 0xc9, 0x70, 0x3d, 0xf7, 0x29, 0x7a, 0x20, 0x1b, 0x02, 0xda, 0xd6, 0xdb, 0xd2, 0x9a, 0x07,
    0xb6, 0xd2, 0x8c, 0x9e, 0x04, 0xcb, 0x2f, 0x18, 0x4f, 0x07, 0x34, 0x35, 0x0e, 0x32, 0xbb, 0x7e, 0x62, 0xff,
    0x9d, 0xbc, 0xfd, 0xb6, 0x3d, 0x15, 0x03, 0x41, 0x44, 0x61, 0x20, 0x20, 0xcd, 0xa5, 0x95, 0x5f, 0x82, 0xc4,
    0x93, 0x15, 0x45, 0xbc, 0xbf, 0x40, 0x75, 0x8c, 0xe1, 0x01, 0x0d, 0x7d, 0xb4, 0xdb, 0x2a, 0x90, 0x70, 0x13,
    0xd7, 0x9c, 0x7a, 0x8f, 0xcf, 0x95, 0x7f, 0x03, 0x41, 0x44, 0x62};
const size_t tc_isk_input_string_len = sizeof(tc_isk_input_string);

// Test vector scalar from B.1.10
const unsigned char tc_s[] = {0xaf, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
                              0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
                              0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xff};
// Test vector low-order points u0-u5, u7 from B.1.10 that MUST yield identity K
const unsigned char tc_u0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const unsigned char tc_u1[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const unsigned char tc_u2[] = {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
const unsigned char tc_u3[] = {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
                               0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
                               0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00};
const unsigned char tc_u4[] = {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
                               0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
                               0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57};
const unsigned char tc_u5[] = {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
const unsigned char tc_u7[] = {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

// --- Global variables for tests ---
const crypto_provider_t *vector_test_provider = NULL;

// --- Setup/Teardown for Vector Tests ---
void setUp_vectors(void)
{
    // Make sure OpenSSL is initialized first
    TEST_ASSERT_EQUAL_MESSAGE(CPACE_OK, easy_cpace_openssl_init(), "Failed to initialize OpenSSL backend");

    // Get the provider
    vector_test_provider = cpace_get_provider_openssl();
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider, "Failed to get OpenSSL provider in vector setUp");
}

void tearDown_vectors(void)
{
    vector_test_provider = NULL;
    // Cleanup called in runner main
}

// --- Test Cases ---
// stdio.h and string.h included at the top

// Test B.1.1 - Generator String Construction (using the corrected utility)
void test_vector_generator_string_construction(void)
{
    uint8_t actual_gen_input[512]; // Ensure buffer is large enough
    size_t actual_gen_input_len;
    // Create a local copy of the expected string to avoid potential issues with global const array access in macros
    uint8_t expected_gen_input[TC_GENERATOR_STRING_LEN];
    memcpy(expected_gen_input, tc_generator_string, TC_GENERATOR_STRING_LEN);


    actual_gen_input_len = cpace_construct_generator_hash_input(tc_PRS,
                                                                tc_PRS_len,
                                                                tc_CI,
                                                                tc_CI_len,
                                                                tc_sid,
                                                                tc_sid_len,
                                                                actual_gen_input,
                                                                sizeof(actual_gen_input));

    // Compare length and content against the RFC test vector B.1.1
#ifdef CPACE_DEBUG_LOG
    // Add specific debug print for the values being compared in the assertion below
    // Use %llu and cast to unsigned long long just to rule out printf issues with %zu
    printf("DEBUG_TEST: Comparing lengths: Expected (TC_GENERATOR_STRING_LEN) = %llu, Actual (actual_gen_input_len) = %llu\n",
           (unsigned long long)TC_GENERATOR_STRING_LEN, (unsigned long long)actual_gen_input_len);
#endif // CPACE_DEBUG_LOG
    // Use TEST_ASSERT_EQUAL_UINT64_MESSAGE for size_t comparison for potentially better portability/clarity
    // Use the macro directly for the expected value
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((uint64_t)TC_GENERATOR_STRING_LEN, (uint64_t)actual_gen_input_len, "Generator string length mismatch");
    if (TC_GENERATOR_STRING_LEN == actual_gen_input_len) {
#ifdef CPACE_DEBUG_LOG
        // Manual memcmp and byte check right before the assertion
        int memcmp_result = memcmp(expected_gen_input, actual_gen_input, TC_GENERATOR_STRING_LEN);
        printf("DEBUG_TEST: Manual memcmp result before assert = %d\n", memcmp_result);
        printf("DEBUG_TEST: Byte 128 before assert: Expected=0x%02x, Actual=0x%02x\n", expected_gen_input[128], actual_gen_input[128]);
        // Optionally dump full buffers again if mismatch detected by memcmp
        if (memcmp_result != 0) {
            cpace_debug_print_hex("Expected (local copy pre-assert)", expected_gen_input, TC_GENERATOR_STRING_LEN);
            cpace_debug_print_hex("Actual (actual_gen_input pre-assert)", actual_gen_input, actual_gen_input_len);
        }
#endif // CPACE_DEBUG_LOG
        // Compare against the local copy
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_gen_input,
                                         actual_gen_input,
                                         TC_GENERATOR_STRING_LEN, // Use macro here too
                                         "Generator string content mismatch");
    } else {
        // This block should NOT be reached if lengths match, but if it does, print details
#ifdef CPACE_DEBUG_LOG
        printf("ERROR: Lengths mismatch but entering else block? Expected=%llu, Actual=%llu\n",
               (unsigned long long)TC_GENERATOR_STRING_LEN, (unsigned long long)actual_gen_input_len);
        cpace_debug_print_hex("Expected Generator String (in else)", expected_gen_input, TC_GENERATOR_STRING_LEN);
        cpace_debug_print_hex("Actual Generator String (in else)", actual_gen_input, actual_gen_input_len);
#endif // CPACE_DEBUG_LOG
    }
}

// Test B.1.1 - Hashing Generator String and Mapping to Curve Point 'g'
void test_vector_generator_mapping(void)
{
    uint8_t actual_gen_input[512]; // Buffer for constructed input
    size_t actual_gen_input_len;
    uint8_t actual_hash[CPACE_CRYPTO_FIELD_SIZE_BYTES]; // Need 32 bytes for map_to_curve
    uint8_t actual_g[CPACE_CRYPTO_POINT_BYTES];

    // 1. Construct the generator input string using our implementation
    actual_gen_input_len = cpace_construct_generator_hash_input(tc_PRS,
                                                                tc_PRS_len,
                                                                tc_CI,
                                                                tc_CI_len,
                                                                tc_sid,
                                                                tc_sid_len,
                                                                actual_gen_input,
                                                                sizeof(actual_gen_input));
    // Basic check that construction succeeded
    TEST_ASSERT_GREATER_THAN_UINT(0, actual_gen_input_len);
    // Optional: Verify against tc_generator_string again if desired, but test_vector_generator_string_construction
    // should cover this.

    // 2. Hash the *constructed* input string
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider, "vector_test_provider is NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->hash_iface, "vector_test_provider->hash_iface is NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->hash_iface->hash_digest,
                                 "vector_test_provider->hash_iface->hash_digest is NULL");

    int hash_ok =
        vector_test_provider->hash_iface->hash_digest(actual_gen_input, // Use the string we just built
                                                      actual_gen_input_len,
                                                      actual_hash,
                                                      sizeof(actual_hash)); // Hash output is 32 bytes for map_to_curve

    TEST_ASSERT_EQUAL_INT_MESSAGE(CRYPTO_OK, hash_ok, "Hashing the constructed generator string failed");

    // 3. Compare the resulting hash with the expected hash from RFC B.1.1
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(tc_generator_hash, actual_hash, sizeof(actual_hash), "Generator hash mismatch");
#ifdef CPACE_DEBUG_LOG
    if (memcmp(tc_generator_hash, actual_hash, sizeof(actual_hash)) != 0) {
        cpace_debug_print_hex("Expected Generator Hash", tc_generator_hash, sizeof(tc_generator_hash));
        cpace_debug_print_hex("Actual Generator Hash", actual_hash, sizeof(actual_hash));
    }
#endif // CPACE_DEBUG_LOG

    // 4. Map the resulting hash to the curve
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->ecc_iface, "vector_test_provider->ecc_iface is NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->ecc_iface->map_to_curve,
                                 "vector_test_provider->ecc_iface->map_to_curve is NULL");
    int map_ok = vector_test_provider->ecc_iface->map_to_curve(actual_g, actual_hash);
    TEST_ASSERT_EQUAL_INT(CRYPTO_OK, map_ok);

    // Compare with the expected generator point 'g'
    TEST_ASSERT_EQUAL_MEMORY(tc_g, actual_g, sizeof(actual_g));
}

// Test B.1.5 - ISK Input String Construction (using the *modified* utility directly)
void test_vector_isk_string_construction(void)
{
    uint8_t actual_isk_input[512];
    size_t actual_isk_input_len;
    const uint8_t DSI_ISK[] = "CPace255_ISK"; // From B.1.5

    // Use the modified constructor
    actual_isk_input_len = cpace_construct_isk_hash_input(DSI_ISK,
                                                          sizeof(DSI_ISK) - 1,
                                                          tc_sid,
                                                          tc_sid_len,
                                                          tc_K,
                                                          tc_Ya,
                                                          tc_ADa,
                                                          tc_ADa_len, // Use ADa for first AD
                                                          tc_Yb,
                                                          tc_ADb,
                                                          tc_ADb_len, // Use ADb for second AD
                                                          actual_isk_input,
                                                          sizeof(actual_isk_input));

    TEST_ASSERT_EQUAL_UINT(tc_isk_input_string_len, actual_isk_input_len);
    TEST_ASSERT_EQUAL_MEMORY(tc_isk_input_string, actual_isk_input, tc_isk_input_string_len);
}

// Test B.1.5 - Final ISK Calculation
void test_vector_isk_calculation(void)
{
    uint8_t actual_isk[CPACE_ISK_BYTES];

    // Hash the known correct ISK input string
    int hash_ok = vector_test_provider->hash_iface->hash_digest(tc_isk_input_string,
                                                                tc_isk_input_string_len,
                                                                actual_isk,
                                                                sizeof(actual_isk));
    TEST_ASSERT_EQUAL_INT(CRYPTO_OK, hash_ok);
    TEST_ASSERT_EQUAL_MEMORY(tc_ISK_IR, actual_isk, sizeof(actual_isk));
}

// Test B.1.10 - Low Order Points yielding identity K
void test_vector_low_order_mult_identity(void)
{
    const unsigned char *low_order_us[] = {tc_u0, tc_u1, tc_u2, tc_u3, tc_u4, tc_u5, tc_u7};
    int num_tests = sizeof(low_order_us) / sizeof(low_order_us[0]);
    uint8_t result_point[CPACE_CRYPTO_POINT_BYTES];

    for (int i = 0; i < num_tests; ++i) {
        int mult_ret = vector_test_provider->ecc_iface->scalar_mult(result_point, tc_s, low_order_us[i]);

        // Expect the scalar_mult function to return the specific identity error code
        TEST_ASSERT_EQUAL_INT(CRYPTO_ERR_POINT_IS_IDENTITY, mult_ret);
    }
}

// Combined test function for RFC vectors as required by test_vectors_runner.c
void test_rfc_vectors(void)
{
    // Run all the individual vector tests from within this function
    test_vector_generator_string_construction();
    test_vector_generator_mapping();
    test_vector_isk_string_construction();
    test_vector_isk_calculation();
    test_vector_low_order_mult_identity();
}
