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

// Import test function declarations
extern void test_context_init_cleanup(void);
extern void test_context_init_invalid_args(void);
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
    // Initialize Monocypher backend (optional, but good practice)
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        // This currently always returns OK, but check anyway.
        printf("FATAL: Failed to initialize Monocypher backend!\n");
        return 1;
    }

    UNITY_BEGIN();

    // Run all API tests with proper setup/teardown
    RUN_TEST(test_context_init_cleanup);
    RUN_TEST(test_context_init_invalid_args);
    RUN_TEST(test_basic_initiator_responder_exchange_ok);
    RUN_TEST(test_invalid_state_transitions);

    int result = UNITY_END();

    // Cleanup Monocypher backend (optional)
    easy_cpace_monocypher_cleanup();

    return result;
}
