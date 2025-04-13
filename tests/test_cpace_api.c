// tests/test_cpace_api.c
#include "easy_cpace.h"
#include "unity.h"
#include <stdio.h>  // For printf in tests (optional)
#include <string.h> // For memcmp

// Test Inputs (use fixed values for deterministic tests)
static const uint8_t TEST_PRS[] = "test_password";
static const size_t TEST_PRS_LEN = sizeof(TEST_PRS) - 1;
static const uint8_t TEST_SID[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const size_t TEST_SID_LEN = sizeof(TEST_SID);
static const uint8_t TEST_CI[] = "TestChannelID";
static const size_t TEST_CI_LEN = sizeof(TEST_CI) - 1;
static const uint8_t TEST_AD[] = {0xAA, 0xBB, 0xCC};
static const size_t TEST_AD_LEN = sizeof(TEST_AD);

// Test Provider (Using OpenSSL for now)
const crypto_provider_t *test_provider = NULL;

// --- Test Setup and Teardown ---

void setUp(void)
{
    // Runs before each test function in this file
    test_provider = cpace_get_provider_openssl();
    TEST_ASSERT_NOT_NULL_MESSAGE(test_provider, "Failed to get OpenSSL provider");
    // Note: easy_cpace_openssl_init() is called once in test_runner.c main()
}

void tearDown(void)
{
    // Runs after each test function in this file
    test_provider = NULL;
    // Note: easy_cpace_openssl_cleanup() is called once in test_runner.c main()
}

// --- Test Cases ---

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
    printf("  Initiator: Starting...\n");
    err = cpace_initiator_start(ctx_i, TEST_PRS, TEST_PRS_LEN, TEST_SID, TEST_SID_LEN, TEST_CI, TEST_CI_LEN, TEST_AD,
                                TEST_AD_LEN, msg1);
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
    printf("  Responder: Responding...\n");
    err = cpace_responder_respond(ctx_r, TEST_PRS, TEST_PRS_LEN, TEST_SID, TEST_SID_LEN, TEST_CI, TEST_CI_LEN, TEST_AD,
                                  TEST_AD_LEN, msg1, msg2, isk_r);
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
    printf("  Initiator: Finishing...\n");
    err = cpace_initiator_finish(ctx_i, msg2, isk_i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CPACE_OK, err, "Initiator finish failed");

    // 5. Verify ISKs match
    printf("  Verifying ISKs...\n");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(isk_r, isk_i, CPACE_ISK_BYTES, "ISKs do not match!");

    // 6. Cleanup
    cpace_ctx_free(ctx_i);
    cpace_ctx_free(ctx_r);
}

void test_invalid_state_transitions(void)
{
    cpace_ctx_t *ctx_i = cpace_ctx_new(CPACE_ROLE_INITIATOR, test_provider);
    TEST_ASSERT_NOT_NULL(ctx_i);
    uint8_t dummy_msg[CPACE_PUBLIC_BYTES] = {0};
    uint8_t dummy_isk[CPACE_ISK_BYTES];

    // Try finish before start
    cpace_error_t err = cpace_initiator_finish(ctx_i, dummy_msg, dummy_isk);
    TEST_ASSERT_EQUAL_INT(CPACE_ERROR_INVALID_STATE, err);

    // Start successfully
    err = cpace_initiator_start(ctx_i, TEST_PRS, TEST_PRS_LEN, TEST_SID, TEST_SID_LEN, TEST_CI, TEST_CI_LEN, TEST_AD,
                                TEST_AD_LEN, dummy_msg);
    TEST_ASSERT_EQUAL_INT(CPACE_OK, err);

    // Try start again
    err = cpace_initiator_start(ctx_i, TEST_PRS, TEST_PRS_LEN, TEST_SID, TEST_SID_LEN, TEST_CI, TEST_CI_LEN, TEST_AD,
                                TEST_AD_LEN, dummy_msg);
    TEST_ASSERT_EQUAL_INT(CPACE_ERROR_INVALID_STATE, err);

    cpace_ctx_free(ctx_i);

    // Similar checks for responder...
    cpace_ctx_t *ctx_r = cpace_ctx_new(CPACE_ROLE_RESPONDER, test_provider);
    TEST_ASSERT_NOT_NULL(ctx_r);
    // Try finish (should fail role check)
    err = cpace_initiator_finish(ctx_r, dummy_msg, dummy_isk);
    TEST_ASSERT_EQUAL_INT(CPACE_ERROR_INVALID_STATE, err);
    cpace_ctx_free(ctx_r);
}

// --- Test Suite Runner ---
// This function is called by test_runner.c
void run_api_tests(void)
{
    // Setup for the whole suite (if needed, beyond setUp/tearDown)
    printf("Setting up API Test Suite...\n");

    // Run individual tests
    RUN_TEST(test_context_new_free);
    RUN_TEST(test_context_new_invalid_args);
    RUN_TEST(test_basic_initiator_responder_exchange_ok);
    RUN_TEST(test_invalid_state_transitions);
    // Add RUN_TEST calls for more tests here

    // Teardown for the whole suite (if needed)
    printf("API Test Suite Finished.\n");
}
