/*
 * Copyright 2025 Asim Ihsan
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef CPACE_UTILS_H
#define CPACE_UTILS_H

#include "../crypto_iface/crypto_provider.h" // For constants
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Concatenates inputs for the Intermediate Session Key (ISK) derivation hash.
 * Format follows draft-irtf-cfrg-cpace-13 B.1.5:
 * lv(dsi_label) || lv(sid) || lv(K) || lv(Ya) || lv(ADa) || lv(Yb) || lv(ADb)
 * where transcript is Ya || ADa || Yb || ADb (or similar based on role/order)
 *
 * Note: This implementation uses single-byte length prefixes (lv). Lengths MUST be <= 255.
 * It assumes symmetric AD based on the current EasyCPace API, duplicating the AD input.
 *
 * @param dsi_label The domain separation label (e.g., "CPACE_CRYPTO_DSI_ISK").
 * @param dsi_label_len Length of dsi_label.
 * @param sid Session ID buffer.
 * @param sid_len Length of sid.
 * @param K Shared secret point K buffer (CPACE_CRYPTO_POINT_BYTES).
 * @param Ya Initiator's public key buffer (CPACE_CRYPTO_POINT_BYTES).
 * @param ADa Initiator's associated data buffer.
 * @param ADa_len Length of ADa.
 * @param Yb Responder's public key buffer (CPACE_CRYPTO_POINT_BYTES).
 * @param ADb Responder's associated data buffer.
 * @param ADb_len Length of ADb.
 * @param out Buffer to write the concatenated result.
 * @param out_capacity Size of the output buffer.
 * @return The total number of bytes written to 'out', or 0 on error (e.g., buffer too small).
 */
size_t cpace_construct_isk_hash_input(const uint8_t *dsi_label,
                                      size_t dsi_label_len,
                                      const uint8_t *sid,
                                      size_t sid_len,
                                      const uint8_t K[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t Ya[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t *ADa,
                                      size_t ADa_len,
                                      const uint8_t Yb[CPACE_CRYPTO_POINT_BYTES],
                                      const uint8_t *ADb,
                                      size_t ADb_len,
                                      uint8_t *out,
                                      size_t out_capacity);

/**
 * @brief Constructs the input string for the generator hash (gen_str).
 * Format roughly follows draft-irtf-cfrg-cpace `generator_string` function:
 * DSI || PRS || ZPAD || L(CI) || CI || L(sid) || sid
 * Uses simplified length encoding (single byte) assuming lengths fit.
 * ZPAD ensures the first hash block is full.
 *
 * @param prs Password Related String.
 * @param prs_len Length of prs.
 * @param ci Channel Identifier.
 * @param ci_len Length of ci (MUST be <= 255).
 * @param sid Session ID.
 * @param sid_len Length of sid (MUST be <= 255).
 * @param out Buffer to write the concatenated result.
 * @param out_size Size of the output buffer.
 * @return The total number of bytes written to 'out', or 0 on error (e.g., buffer too small, length overflow).
 */
size_t cpace_construct_generator_hash_input(const uint8_t *prs,
                                            size_t prs_len,
                                            const uint8_t *ci,
                                            size_t ci_len,
                                            const uint8_t *sid,
                                            size_t sid_len,
                                            uint8_t *out,
                                            size_t out_size);

#ifdef CPACE_DEBUG_LOG
#include <stdio.h> // Include stdio only when debugging is enabled
/**
 * @brief Prints a byte array in hex format for debugging.
 * Only compiled if CPACE_DEBUG_LOG is defined.
 * @param label A descriptive label for the output.
 * @param data The byte array to print.
 * @param len The length of the byte array.
 */
void cpace_debug_print_hex(const char *label, const uint8_t *data, size_t len);
#endif // CPACE_DEBUG_LOG

#endif // CPACE_UTILS_H
