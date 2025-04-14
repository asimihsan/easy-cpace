/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include "../include/easy_cpace.h" // Include to call init/cleanup
#include "unity.h"
#include <stdio.h>

// --- Declare Test Suites ---
// Forward declare functions that run tests from different files
extern void run_api_tests(void);
extern void run_vector_tests(void);
// Add declarations for other test suites here later

// --- Main Test Runner ---
#include <stdio.h> // Ensure printf/fflush are available

int main(void)
{
    int failures = 0;
    printf("Initializing Monocypher backend (if needed)...\n");
    // --- Initialize Monocypher Backend (Optional but good practice) ---
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        // This currently always returns OK, but check anyway.
        printf("FATAL: Failed to initialize Monocypher backend!\n");
        return 1; // Cannot run tests
    }

    UNITY_BEGIN();

    // --- Run Test Suites ---
    printf("\n--- Running API Tests ---\n");
    run_api_tests();
    printf("\n--- Running Vector Tests ---\n");
    run_vector_tests();

    failures = UNITY_END(); // Returns number of failures

    // --- Cleanup Monocypher Backend (Optional) ---
    printf("Cleaning up Monocypher backend (if needed)...\n");
    easy_cpace_monocypher_cleanup();

    return failures; // Return non-zero if tests failed
}
