#include <easy_cpace.h>
#include <stdio.h>
#include <string.h>

/**
 * Example usage of the embedded-friendly CPace API.
 * This example demonstrates how to use the library without dynamic memory allocation.
 */
int main(void)
{
    // Initialize the provider first (for Monocypher backend)
    cpace_error_t result = easy_cpace_monocypher_init();
    if (result != CPACE_OK) {
        printf("Failed to initialize Monocypher backend: %d\n", result);
        return 1;
    }

    // Get the crypto provider
    const crypto_provider_t *provider = cpace_get_provider_monocypher();
    if (!provider) {
        printf("Failed to get Monocypher provider\n");
        return 1;
    }

    // Test inputs
    const uint8_t prs[] = "shared_password";
    const size_t prs_len = sizeof(prs) - 1;
    const uint8_t sid[] = {0x01, 0x02, 0x03, 0x04};
    const size_t sid_len = sizeof(sid);
    const uint8_t ci[] = "my_channel";
    const size_t ci_len = sizeof(ci) - 1;
    const uint8_t ad[] = {0xaa, 0xbb, 0xcc};
    const size_t ad_len = sizeof(ad);

    // Protocol messages and outputs
    uint8_t msg1[CPACE_PUBLIC_BYTES]; // Ya (from initiator to responder)
    uint8_t msg2[CPACE_PUBLIC_BYTES]; // Yb (from responder to initiator)
    uint8_t isk_i[CPACE_ISK_BYTES];   // Initiator's derived key
    uint8_t isk_r[CPACE_ISK_BYTES];   // Responder's derived key

    // Allocate context structures on the stack
    cpace_ctx_t initiator_ctx;
    cpace_ctx_t responder_ctx;

    // Initialize contexts
    result = cpace_ctx_init(&initiator_ctx, CPACE_ROLE_INITIATOR, provider);
    if (result != CPACE_OK) {
        printf("Failed to initialize initiator context: %d\n", result);
        return 1;
    }

    result = cpace_ctx_init(&responder_ctx, CPACE_ROLE_RESPONDER, provider);
    if (result != CPACE_OK) {
        printf("Failed to initialize responder context: %d\n", result);
        cpace_ctx_cleanup(&initiator_ctx);
        return 1;
    }

    // Step 1: Initiator generates first message (Ya)
    result = cpace_initiator_start(&initiator_ctx, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1);
    if (result != CPACE_OK) {
        printf("Initiator start failed: %d\n", result);
        cpace_ctx_cleanup(&initiator_ctx);
        cpace_ctx_cleanup(&responder_ctx);
        return 1;
    }
    printf("Initiator generated message 1 (Ya)\n");

    // Step 2: Responder processes msg1, generates msg2 and ISK
    result =
        cpace_responder_respond(&responder_ctx, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1, msg2, isk_r);
    if (result != CPACE_OK) {
        printf("Responder respond failed: %d\n", result);
        cpace_ctx_cleanup(&initiator_ctx);
        cpace_ctx_cleanup(&responder_ctx);
        return 1;
    }
    printf("Responder generated message 2 (Yb) and derived ISK\n");

    // Step 3: Initiator processes msg2 and derives ISK
    result = cpace_initiator_finish(&initiator_ctx, msg2, isk_i);
    if (result != CPACE_OK) {
        printf("Initiator finish failed: %d\n", result);
        cpace_ctx_cleanup(&initiator_ctx);
        cpace_ctx_cleanup(&responder_ctx);
        return 1;
    }
    printf("Initiator derived ISK\n");

    // Verify both parties derived the same key
    if (memcmp(isk_i, isk_r, CPACE_ISK_BYTES) != 0) {
        printf("ERROR: Derived keys do not match!\n");
    } else {
        printf("SUCCESS: Both parties derived the same key\n");
        // In a real application, you'd use this key for further cryptographic operations
    }

    // Clean up resources (zero out sensitive data)
    cpace_ctx_cleanup(&initiator_ctx);
    cpace_ctx_cleanup(&responder_ctx);
    easy_cpace_monocypher_cleanup();

    return 0;
}
