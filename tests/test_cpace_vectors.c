/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include "../include/easy_cpace.h"
#include "../src/common/utils.h"                 // For direct testing of construct functions
#include "../src/crypto_iface/crypto_provider.h" // For crypto interface types
#include "generated_rfc_vectors.h"               // Include the generated vectors
#include "unity.h"
#include <stdio.h>  // For printf
#include <string.h> // For memcmp

// --- Global variables for tests ---
const crypto_provider_t *vector_test_provider = NULL;

// --- Setup/Teardown for Vector Tests ---
void setUp_vectors(void)
{
    // Initialize Monocypher backend (optional, but good practice)
    TEST_ASSERT_EQUAL_MESSAGE(CPACE_OK, easy_cpace_monocypher_init(), "Failed to initialize Monocypher backend");

    // Get the provider
    vector_test_provider = cpace_get_provider_monocypher();
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider, "Failed to get Monocypher provider in vector setUp");
}

void tearDown_vectors(void)
{
    vector_test_provider = NULL;
    // Cleanup called in runner main (easy_cpace_monocypher_cleanup)
}

// --- Test Cases ---
// stdio.h and string.h included at the top

// Test B.1.1 - Generator String Construction (using the corrected utility)
void test_vector_generator_string_construction(void)
{
    uint8_t actual_gen_input[512]; // Ensure buffer is large enough
    size_t actual_gen_input_len;

    actual_gen_input_len = cpace_construct_generator_hash_input(RFC_B1_PRS,
                                                                RFC_B1_PRS_LEN,
                                                                RFC_B1_CI,
                                                                RFC_B1_CI_LEN,
                                                                RFC_B1_SID,
                                                                RFC_B1_SID_LEN,
                                                                actual_gen_input,
                                                                sizeof(actual_gen_input));

    // Compare length and content against the generated RFC test vector B.1.1
#ifdef CPACE_DEBUG_LOG
    printf("DEBUG_TEST: Comparing lengths: Expected (RFC_B1_GENERATOR_INPUT_STRING_LEN) = %zu, Actual "
           "(actual_gen_input_len) = %zu\n",
           RFC_B1_GENERATOR_INPUT_STRING_LEN,
           actual_gen_input_len);
#endif // CPACE_DEBUG_LOG
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((uint64_t)RFC_B1_GENERATOR_INPUT_STRING_LEN,
                                     (uint64_t)actual_gen_input_len,
                                     "Generator string length mismatch");

    if (RFC_B1_GENERATOR_INPUT_STRING_LEN == actual_gen_input_len) {
#ifdef CPACE_DEBUG_LOG
        int memcmp_result = memcmp(RFC_B1_GENERATOR_INPUT_STRING, actual_gen_input, RFC_B1_GENERATOR_INPUT_STRING_LEN);
        printf("DEBUG_TEST: Manual memcmp result before assert = %d\n", memcmp_result);
        if (memcmp_result != 0) {
            cpace_debug_print_hex("Expected (Generated)",
                                  RFC_B1_GENERATOR_INPUT_STRING,
                                  RFC_B1_GENERATOR_INPUT_STRING_LEN);
            cpace_debug_print_hex("Actual (Constructed)", actual_gen_input, actual_gen_input_len);
        }
#endif // CPACE_DEBUG_LOG
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(RFC_B1_GENERATOR_INPUT_STRING,
                                         actual_gen_input,
                                         RFC_B1_GENERATOR_INPUT_STRING_LEN,
                                         "Generator string content mismatch");
    } else {
#ifdef CPACE_DEBUG_LOG
        printf("ERROR: Lengths mismatch but entering else block? Expected=%zu, Actual=%zu\n",
               RFC_B1_GENERATOR_INPUT_STRING_LEN,
               actual_gen_input_len);
        cpace_debug_print_hex("Expected Generator String (in else)",
                              RFC_B1_GENERATOR_INPUT_STRING,
                              RFC_B1_GENERATOR_INPUT_STRING_LEN);
        cpace_debug_print_hex("Actual Generator String (in else)", actual_gen_input, actual_gen_input_len);
#endif // CPACE_DEBUG_LOG
    }
}

// Test B.1.1 - Hashing Generator String and Mapping to Curve Point 'g'
void test_vector_generator_mapping(void)
{
    uint8_t actual_gen_input[512] = {0}; // Buffer for constructed input, initialize to zero
    size_t actual_gen_input_len;
    uint8_t actual_hash[CPACE_CRYPTO_FIELD_SIZE_BYTES] = {0}; // Need 32 bytes for map_to_curve, initialize to zero
    uint8_t actual_g[CPACE_CRYPTO_POINT_BYTES] = {0};         // Initialize to zero

    // 1. Construct the generator input string using our implementation
    // (This is already verified by test_vector_generator_string_construction,
    // but we need the output for the next step)
    actual_gen_input_len = cpace_construct_generator_hash_input(RFC_B1_PRS,
                                                                RFC_B1_PRS_LEN,
                                                                RFC_B1_CI,
                                                                RFC_B1_CI_LEN,
                                                                RFC_B1_SID,
                                                                RFC_B1_SID_LEN,
                                                                actual_gen_input,
                                                                sizeof(actual_gen_input));
    // Basic check that construction succeeded and matches expected length
    TEST_ASSERT_EQUAL_UINT(RFC_B1_GENERATOR_INPUT_STRING_LEN, actual_gen_input_len);

    // 2. Hash the *constructed* input string (which should match RFC_B1_GENERATOR_INPUT_STRING)
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

    // 3. Compare the resulting hash with the expected hash from the generated vectors
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(RFC_B1_HASH_GENERATOR_STRING,
                                     actual_hash,
                                     RFC_B1_HASH_GENERATOR_STRING_LEN,
                                     "Generator hash mismatch");
#ifdef CPACE_DEBUG_LOG
    if (memcmp(RFC_B1_HASH_GENERATOR_STRING, actual_hash, RFC_B1_HASH_GENERATOR_STRING_LEN) != 0) {
        cpace_debug_print_hex("Expected Generator Hash",
                              RFC_B1_HASH_GENERATOR_STRING,
                              RFC_B1_HASH_GENERATOR_STRING_LEN);
        cpace_debug_print_hex("Actual Generator Hash", actual_hash, sizeof(actual_hash)); // actual_hash is fixed size
    }
#endif // CPACE_DEBUG_LOG

    // 4. Map the resulting hash to the curve
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->ecc_iface, "vector_test_provider->ecc_iface is NULL");
    TEST_ASSERT_NOT_NULL_MESSAGE(vector_test_provider->ecc_iface->map_to_curve,
                                 "vector_test_provider->ecc_iface->map_to_curve is NULL");
    int map_ok = vector_test_provider->ecc_iface->map_to_curve(actual_g, actual_hash);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CRYPTO_OK, map_ok, "map_to_curve failed");

    // Compare with the expected generator point 'g' from the generated vectors
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(RFC_B1_GENERATOR_G,
                                     actual_g,
                                     RFC_B1_GENERATOR_G_LEN,
                                     "Generator point 'g' mismatch");
}

// Test B.1.5 - ISK Input String Construction (using the *modified* utility directly)
void test_vector_isk_string_construction(void)
{
    uint8_t actual_isk_input[512];
    size_t actual_isk_input_len;
    const uint8_t DSI_ISK[] = "CPace255_ISK"; // From B.1.5

    // Use the constructor with generated vector inputs
    actual_isk_input_len = cpace_construct_isk_hash_input(DSI_ISK,
                                                          sizeof(DSI_ISK) - 1, // DSI is still hardcoded here
                                                          RFC_B1_SID,
                                                          RFC_B1_SID_LEN,
                                                          RFC_B1_K,
                                                          RFC_B1_YA,
                                                          RFC_B1_ADA,
                                                          RFC_B1_ADA_LEN,
                                                          RFC_B1_YB,
                                                          RFC_B1_ADB,
                                                          RFC_B1_ADB_LEN,
                                                          actual_isk_input,
                                                          sizeof(actual_isk_input));

    // Compare length and content against the generated RFC test vector B.1.5
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((uint64_t)RFC_B1_ISK_INPUT_STRING_LEN,
                                     (uint64_t)actual_isk_input_len,
                                     "ISK input string length mismatch");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(RFC_B1_ISK_INPUT_STRING,
                                     actual_isk_input,
                                     RFC_B1_ISK_INPUT_STRING_LEN,
                                     "ISK input string content mismatch");
}

// Test B.1.5 - Final ISK Calculation
void test_vector_isk_calculation(void)
{
    uint8_t actual_isk[CPACE_ISK_BYTES]; // ISK is fixed size (64 bytes for SHA512)

    // Hash the known correct ISK input string from the generated vectors
    int hash_ok = vector_test_provider->hash_iface->hash_digest(RFC_B1_ISK_INPUT_STRING,
                                                                RFC_B1_ISK_INPUT_STRING_LEN,
                                                                actual_isk,
                                                                sizeof(actual_isk)); // Request 64 bytes output
    TEST_ASSERT_EQUAL_INT_MESSAGE(CRYPTO_OK, hash_ok, "Hashing ISK input string failed");

    // Compare with the expected ISK from the generated vectors
    TEST_ASSERT_EQUAL_UINT_MESSAGE(CPACE_ISK_BYTES,
                                   RFC_B1_ISK_IR_LEN,
                                   "Generated ISK_IR length mismatch"); // Sanity check
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(RFC_B1_ISK_IR, actual_isk, RFC_B1_ISK_IR_LEN, "ISK calculation mismatch");
}

// Helper for low order point tests
static void check_low_order(const unsigned char *u, size_t u_len, const char *u_name)
{
    uint8_t result_point[CPACE_CRYPTO_POINT_BYTES];
    char msg_buffer[128];

    TEST_ASSERT_EQUAL_UINT_MESSAGE(CPACE_CRYPTO_POINT_BYTES, u_len, "Low order point length mismatch"); // Sanity check

    int mult_ret = vector_test_provider->ecc_iface->scalar_mult(result_point, RFC_B1_S, u);

    // Expect the scalar_mult function to return the specific identity error code
    snprintf(msg_buffer, sizeof(msg_buffer), "Scalar mult with %s did not return identity error", u_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CRYPTO_ERR_POINT_IS_IDENTITY, mult_ret, msg_buffer);
}

// Test B.1.10 - Low Order Points yielding identity K
void test_vector_low_order_mult_identity(void)
{
    TEST_ASSERT_EQUAL_UINT_MESSAGE(CPACE_CRYPTO_SCALAR_BYTES,
                                   RFC_B1_S_LEN,
                                   "Scalar 's' length mismatch"); // Sanity check

    check_low_order(RFC_B1_U0, RFC_B1_U0_LEN, "u0");
    check_low_order(RFC_B1_U1, RFC_B1_U1_LEN, "u1");
    check_low_order(RFC_B1_U2, RFC_B1_U2_LEN, "u2");
    check_low_order(RFC_B1_U3, RFC_B1_U3_LEN, "u3");
    check_low_order(RFC_B1_U4, RFC_B1_U4_LEN, "u4");
    check_low_order(RFC_B1_U5, RFC_B1_U5_LEN, "u5");
    check_low_order(RFC_B1_U7, RFC_B1_U7_LEN, "u7");
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
