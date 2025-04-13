#include "../include/easy_cpace.h"
#include "unity.h"
#include "unity_test_helpers.h"

// Import test function declarations - these should exist in test_cpace_vectors.c
extern void test_rfc_vectors(void); // Assuming this exists

// Import setup/teardown functions if they exist
extern void setUp_vectors(void);
extern void tearDown_vectors(void);

// Standard Unity setup/teardown functions (required)
void setUp(void)
{
    // Call the vectors-specific setup
    setUp_vectors();
}

void tearDown(void)
{
    // Call the vectors-specific teardown
    tearDown_vectors();
}

int main(void)
{
    // Initialize OpenSSL backend
    if (easy_cpace_openssl_init() != CPACE_OK) {
        printf("FATAL: Failed to initialize OpenSSL backend constants!\n");
        return 1;
    }

    UNITY_BEGIN();

    // Run the vector tests
    RUN_TEST(test_rfc_vectors); // Assuming this exists

    int result = UNITY_END();

    // Cleanup OpenSSL
    easy_cpace_openssl_cleanup();

    return result;
}