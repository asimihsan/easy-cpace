// tests/test_runner.c
#include "easy_cpace.h" // Include to call init/cleanup
#include "unity.h"
#include <stdio.h>

// --- Declare Test Suites ---
// Forward declare functions that run tests from different files
extern void run_api_tests(void);
// Add declarations for other test suites here later

// --- Main Test Runner ---
int main(void)
{
    int failures = 0;
    printf("Initializing OpenSSL backend...\n");
    // --- !!! IMPORTANT: Initialize OpenSSL Backend !!! ---
    // Required for tests using the OpenSSL provider, especially Elligator2.
    // Assumes tests primarily use OpenSSL for now.
    // If testing MbedTLS, similar init might be needed if it requires it.
    if (easy_cpace_openssl_init() != CPACE_OK) {
        printf("FATAL: Failed to initialize OpenSSL backend constants!\n");
        return 1; // Cannot run tests
    }

    UNITY_BEGIN();

    // --- Run Test Suites ---
    printf("\n--- Running API Tests ---\n");
    run_api_tests();
    // Call other test suite runners here later

    failures = UNITY_END(); // Returns number of failures

    // --- !!! IMPORTANT: Cleanup OpenSSL Backend !!! ---
    printf("Cleaning up OpenSSL backend...\n");
    easy_cpace_openssl_cleanup();

    return failures; // Return non-zero if tests failed
}
