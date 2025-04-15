/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include "../include/easy_cpace.h"
#include "unity.h"

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
    // Initialize Monocypher backend (optional, but good practice)
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        // This currently always returns OK, but check anyway.
        printf("FATAL: Failed to initialize Monocypher backend!\n");
        return 1;
    }

    UNITY_BEGIN();

    // Run the vector tests
    RUN_TEST(test_rfc_vectors); // Assuming this exists

    int result = UNITY_END();

    // Cleanup Monocypher backend (optional)
    easy_cpace_monocypher_cleanup();

    // No special cleanup for macOS - handled by sanitizer suppression

    return result;
}
