/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include <easy_cpace.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>  // For fprintf, stderr
#include <stdlib.h> // For abort()
#include <string.h> // For memcpy

// Include internal headers needed for the target functions
#include "../src/common/utils.h"

// One-time initialization (optional, but good for crypto libraries)
__attribute__((constructor)) static void fuzzer_global_init()
{
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        fprintf(stderr, "FATAL: Fuzzer failed to initialize Monocypher backend!\n");
        abort(); // Cannot continue without backend
    }
}

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Target 1: cpace_construct_generator_hash_input
    // Needs PRS, CI, SID. We'll split the input data.
    // Use a simple scheme: first byte = prs_len, second = ci_len, third = sid_len
    if (Size >= 3) {
        size_t prs_len = Data[0];
        size_t ci_len = Data[1];
        size_t sid_len = Data[2];
        size_t header_size = 3;
        size_t required_data = prs_len + ci_len + sid_len;

        // Check if lengths are within reasonable limits (e.g., <= max allowed by protocol)
        // and if the total size is sufficient.
        if (prs_len <= 255 && ci_len <= CPACE_MAX_CI_LEN && sid_len <= CPACE_MAX_SID_LEN &&
            Size >= header_size + required_data) {

            const uint8_t *prs_ptr = Data + header_size;
            const uint8_t *ci_ptr = prs_ptr + prs_len;
            const uint8_t *sid_ptr = ci_ptr + ci_len;

            // Allocate a buffer large enough for the potential output + some margin
            // Max size: (1+DSI) + (1+PRS_MAX) + (1+ZPAD_MAX) + (1+CI_MAX) + (1+SID_MAX)
            // ZPAD_MAX is roughly HASH_BLOCK_BYTES. Let's overestimate slightly.
            uint8_t gen_out_buf[1 + 10 + 1 + 255 + 1 + CPACE_CRYPTO_HASH_BLOCK_BYTES + 1 + CPACE_MAX_CI_LEN + 1 +
                                CPACE_MAX_SID_LEN + 10]; // Added margin

            (void)cpace_construct_generator_hash_input(prs_ptr,
                                                       prs_len,
                                                       ci_ptr,
                                                       ci_len,
                                                       sid_ptr,
                                                       sid_len,
                                                       gen_out_buf,
                                                       sizeof(gen_out_buf));
            // Ignore return value, rely on sanitizers.
        }
    }

    // Target 2: cpace_construct_isk_hash_input
    // Needs: dsi_label, sid, K, Ya, ADa, Yb, ADb
    // Simpler scheme: Treat input as concatenation of fixed-size + variable-size parts.
    // Requires at least 3 * POINT_BYTES for K, Ya, Yb.
    if (Size >= 3 * CPACE_CRYPTO_POINT_BYTES) {
        const uint8_t DSI_ISK[] = "CPace255_ISK"; // Example DSI
        size_t dsi_len = sizeof(DSI_ISK) - 1;

        // Assign fixed parts
        const uint8_t *K_ptr = Data;
        const uint8_t *Ya_ptr = Data + CPACE_CRYPTO_POINT_BYTES;
        const uint8_t *Yb_ptr = Ya_ptr + CPACE_CRYPTO_POINT_BYTES;
        size_t fixed_size = 3 * CPACE_CRYPTO_POINT_BYTES;

        // Use remaining data for variable parts: sid, ADa, ADb
        // Split remaining data roughly in three parts (can be improved)
        const uint8_t *var_data_start = Data + fixed_size;
        size_t var_data_size = Size - fixed_size;
        size_t sid_len = var_data_size / 3;
        size_t ADa_len = var_data_size / 3;
        size_t ADb_len = var_data_size - sid_len - ADa_len; // Remainder

        // Ensure lengths don't exceed limits
        if (sid_len > CPACE_MAX_SID_LEN) {
            sid_len = CPACE_MAX_SID_LEN;
        }
        if (ADa_len > CPACE_MAX_AD_LEN) {
            ADa_len = CPACE_MAX_AD_LEN;
        }
        if (ADb_len > CPACE_MAX_AD_LEN) {
            ADb_len = CPACE_MAX_AD_LEN;
        }

        const uint8_t *sid_ptr = var_data_start;
        const uint8_t *ADa_ptr = sid_ptr + sid_len;
        const uint8_t *ADb_ptr = ADa_ptr + ADa_len;

        // Check if we have enough data after potential truncation
        if (Size >= fixed_size + sid_len + ADa_len + ADb_len) {
            // Allocate output buffer
            // Max size: (1+DSI) + (1+SID_MAX) + (1+K) + (1+Ya) + (1+ADa_MAX) + (1+Yb) + (1+ADb_MAX)
            uint8_t isk_out_buf[1 + 15 + 1 + CPACE_MAX_SID_LEN + 1 + CPACE_CRYPTO_POINT_BYTES + 1 +
                                CPACE_CRYPTO_POINT_BYTES + 1 + CPACE_MAX_AD_LEN + 1 + CPACE_CRYPTO_POINT_BYTES + 1 +
                                CPACE_MAX_AD_LEN + 10]; // Added margin

            (void)cpace_construct_isk_hash_input(DSI_ISK,
                                                 dsi_len,
                                                 sid_ptr,
                                                 sid_len,
                                                 K_ptr,
                                                 Ya_ptr,
                                                 ADa_ptr,
                                                 ADa_len,
                                                 Yb_ptr,
                                                 ADb_ptr,
                                                 ADb_len,
                                                 isk_out_buf,
                                                 sizeof(isk_out_buf));
            // Ignore return value, rely on sanitizers.
        }
    }

    // Add more targets here...

    return 0; // Required return value
}
