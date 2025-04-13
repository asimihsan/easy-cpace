#include "../include/easy_cpace.h"
#include "unity.h"
#include "unity_test_helpers.h"

// Import test function declarations
extern void test_context_new_free(void);
extern void test_context_new_invalid_args(void);
extern void test_basic_initiator_responder_exchange_ok(void);
extern void test_invalid_state_transitions(void);

// Import setup/teardown functions
extern void setUp_api(void);
extern void tearDown_api(void);

// Standard Unity setup/teardown functions (required)
void setUp(void) { setUp_api(); }

void tearDown(void) { tearDown_api(); }

int main(void)
{
    // Initialize OpenSSL backend
    if (easy_cpace_openssl_init() != CPACE_OK) {
        printf("FATAL: Failed to initialize OpenSSL backend constants!\n");
        return 1;
    }

    UNITY_BEGIN();

    // Run all API tests with proper setup/teardown
    RUN_TEST(test_context_new_free);
    RUN_TEST(test_context_new_invalid_args);
    RUN_TEST(test_basic_initiator_responder_exchange_ok);
    RUN_TEST(test_invalid_state_transitions);

    int result = UNITY_END();

    // Cleanup OpenSSL
    easy_cpace_openssl_cleanup();

    return result;
}