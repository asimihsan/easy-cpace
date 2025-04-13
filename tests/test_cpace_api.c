#include "../include/easy_cpace.h"
#include "unity.h"           // Use include path for Unity headers
#include "unity_internals.h" // Use include path for Unity headers
#include <stdio.h>           // For printf in tests (optional)
#include <string.h>          // For memcmp

// Test Inputs (use fixed values for deterministic tests)
static const uint8_t TEST_PRS[] = "test_password";
static const size_t TEST_PRS_LEN = sizeof(TEST_PRS) - 1;
static const uint8_t TEST_SID[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const size_t TEST_SID_LEN = sizeof(TEST_SID);
static const uint8_t TEST_CI[] = "TestChannelID";
static const size_t TEST_CI_LEN = sizeof(TEST_CI) - 1;
static const uint8_t TEST_AD[] = {0xAA, 0xBB, 0xCC};
static const size_t TEST_AD_LEN = sizeof(TEST_AD);

// Test Provider (Using OpenSSL for now)
const crypto_provider_t *test_provider = NULL;

// --- Test Setup and Teardown (API specific) ---

void setUp_api(void)
{
    // Runs before each test function in this file
    test_provider = cpace_get_provider_openssl();
    TEST_ASSERT_NOT_NULL_MESSAGE(test_provider, "Failed to get OpenSSL provider");
    // Note: easy_cpace_openssl_init() is called once in test_runner.c main()
}

void tearDown_api(void)
{
    // Runs after each test function in this file
    test_provider = NULL;
    // Note: easy_cpace_openssl_cleanup() is called once in test_runner.c main()
}

// --- Test Cases ---
// stdio.h and string.h included at the top

void test_context_new_free(void)
{
    cpace_ctx_t *ctx_i = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx_i, "Initiator context creation failed");

    cpace_ctx_t *ctx_r = cpace_ctx_new(CPACE_ROLE_RESPONDER, test_provider);
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx_r, "Responder context creation failed");

    cpace_ctx_free(ctx_i);
    cpace_ctx_free(ctx_r);
    cpace_ctx_free(NULL); // Should be safe
}

void test_context_new_invalid_args(void)
{
    // Invalid role
    cpace_ctx_t *ctx = cpace_ctx_new((cpace_role_t)99, test_provider);
    TEST_ASSERT_NULL_MESSAGE(ctx, "Context creation should fail with invalid role");

    // Invalid provider
    ctx = cpace_ctx_new(CPACE_ROLE_INITIATOR, NULL);
    TEST_ASSERT_NULL_MESSAGE(ctx, "Context creation should fail with NULL provider");
}

void test_basic_initiator_responder_exchange_ok(void)
{
    cpace_ctx_t *ctx_i = NULL;
    cpace_ctx_t *ctx_r = NULL;
    uint8_t msg1[CPACE_PUBLIC_BYTES];
    uint8_t msg2[CPACE_PUBLIC_BYTES];
    uint8_t isk_i[CPACE_ISK_BYTES];
    uint8_t isk_r[CPACE_ISK_BYTES];
    cpace_error_t err;

    // 1. Create contexts
    ctx_i = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL(ctx_i);
    ctx_r = cpace_ctx_new(CPACE_ROLE_RESPONDER, test_provider);
    TEST_ASSERT_NOT_NULL(ctx_r);

    // 2. Initiator Start
    err = cpace_initiator_start(ctx_i,
                                TEST_PRS,
                                TEST_PRS_LEN,
                                TEST_SID,
                                TEST_SID_LEN,
                                TEST_CI,
                                TEST_CI_LEN,
                                TEST_AD,
                                TEST_AD_LEN,
                                msg1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_OK, err, "Initiator start failed");
    // Basic check on msg1 (e.g., not all zeros - weak check)
    int is_zero = 1;
    for (size_t i = 0; i < CPACE_PUBLIC_BYTES; ++i) {
        if (msg1[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE_MESSAGE(is_zero, "Initiator msg1 should not be all zeros");

    // 3. Responder Respond
    err = cpace_responder_respond(ctx_r,
                                  TEST_PRS,
                                  TEST_PRS_LEN,
                                  TEST_SID,
                                  TEST_SID_LEN,
                                  TEST_CI,
                                  TEST_CI_LEN,
                                  TEST_AD,
                                  TEST_AD_LEN,
                                  msg1,
                                  msg2,
                                  isk_r);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_OK, err, "Responder respond failed");
    // Basic check on msg2
    is_zero = 1;
    for (size_t i = 0; i < CPACE_PUBLIC_BYTES; ++i) {
        if (msg2[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE_MESSAGE(is_zero, "Responder msg2 should not be all zeros");

    // 4. Initiator Finish
    err = cpace_initiator_finish(ctx_i, msg2, isk_i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_OK, err, "Initiator finish failed");

    // 5. Verify ISKs match
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(isk_r, isk_i, CPACE_ISK_BYTES, "ISKs do not match!");

    // 6. Cleanup
    cpace_ctx_free(ctx_i);
    cpace_ctx_free(ctx_r);
}

void test_invalid_state_transitions(void)
{
    cpace_ctx_t *ctx = NULL;
    uint8_t dummy_msg[CPACE_PUBLIC_BYTES] = {0};
    uint8_t dummy_isk[CPACE_ISK_BYTES];
    cpace_error_t err;

    // --- Scenario 1: Initiator finish before start ---
    ctx = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL(ctx);
    err = cpace_initiator_finish(ctx, dummy_msg, dummy_isk);
    TEST_ASSERT_EQUAL_INT(CPACE_ERROR_INVALID_STATE, err);
    // Optional: Check if state is now ERROR (might need internal access or a helper)
    // TEST_ASSERT_TRUE((ctx->state_flags & CPACE_STATE_ERROR) != 0); // Requires direct struct access - not ideal for
    // API test
    cpace_ctx_free(ctx);
    ctx = NULL;

    // --- Scenario 2: Initiator start twice ---
    ctx = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL(ctx);
    // First start should succeed
    err = cpace_initiator_start(ctx,
                                TEST_PRS,
                                TEST_PRS_LEN,
                                TEST_SID,
                                TEST_SID_LEN,
                                TEST_CI,
                                TEST_CI_LEN,
                                TEST_AD,
                                TEST_AD_LEN,
                                dummy_msg);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_OK, err, "First initiator start failed unexpectedly");
    // Second start should fail (state is now I_STARTED, not INITIALIZED)
    err = cpace_initiator_start(ctx,
                                TEST_PRS,
                                TEST_PRS_LEN,
                                TEST_SID,
                                TEST_SID_LEN,
                                TEST_CI,
                                TEST_CI_LEN,
                                TEST_AD,
                                TEST_AD_LEN,
                                dummy_msg);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_ERROR_INVALID_STATE, err, "Second initiator start should fail");
    cpace_ctx_free(ctx);
    ctx = NULL;

    // --- Scenario 3: Responder calls initiator function ---
    ctx = cpace_ctx_new(CPACE_ROLE_RESPONDER, test_provider);
    TEST_ASSERT_NOT_NULL(ctx);
    // Try finish (should fail role check)
    err = cpace_initiator_finish(ctx, dummy_msg, dummy_isk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_ERROR_INVALID_STATE, err, "Responder calling initiator_finish should fail");
    cpace_ctx_free(ctx);
    ctx = NULL;

    // --- Scenario 4: Initiator calls responder function ---
    ctx = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL(ctx);
    uint8_t dummy_msg2[CPACE_PUBLIC_BYTES];
    // Try respond (should fail role check)
    err = cpace_responder_respond(ctx,
                                  TEST_PRS,
                                  TEST_PRS_LEN,
                                  TEST_SID,
                                  TEST_SID_LEN,
                                  TEST_CI,
                                  TEST_CI_LEN,
                                  TEST_AD,
                                  TEST_AD_LEN,
                                  dummy_msg,
                                  dummy_msg2,
                                  dummy_isk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_ERROR_INVALID_STATE, err, "Initiator calling responder_respond should fail");
    cpace_ctx_free(ctx);
    ctx = NULL;

    // Add more scenarios as needed...
}

// The setUp_api and tearDown_api functions are now used through the standard Unity
// setUp and tearDown functions defined in test_api_runner.c.
// Individual test functions are called directly via RUN_TEST in the runner.
