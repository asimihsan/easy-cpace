#include <easy_cpace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // For memcmp

/**
 * EasyCPace Basic Exchange Example
 *
 * This example demonstrates a complete CPace protocol exchange between an
 * initiator and responder, resulting in a shared secret key.
 *
 * The CPace protocol is a balanced PAKE (Password-Authenticated Key Exchange)
 * that allows two parties who share a password to establish a strong shared
 * secret key over an insecure channel without revealing the password.
 */

// Helper function to print hex data
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    if (len == 0) {
        printf("(empty)\n");
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main()
{
    printf("--- Starting EasyCPace Basic Exchange Example ---\n");

    // --- Common Inputs ---
    /**
     * Protocol Parameters:
     *
     * prs (Password-Related String): The shared secret password between parties.
     *     This is the authentication factor that allows secure key agreement.
     *
     * sid (Session ID): A unique identifier for this session that helps prevent
     *     replay attacks and ensures uniqueness for each exchange. In practice,
     *     this should be randomly generated for each session.
     *
     * ci (Channel ID): An identifier for the communication channel. This can be
     *     used to separate different contexts where the same password might be used.
     *
     * ad (Associated Data): Optional additional authenticated data that both parties
     *     want to bind to this key exchange. This data is not encrypted but is
     *     authenticated by the protocol.
     */
    const uint8_t prs[] = "test_password";
    const size_t prs_len = sizeof(prs) - 1;
    const uint8_t sid[] =
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const size_t sid_len = sizeof(sid);
    const uint8_t ci[] = "TestChannelID";
    const size_t ci_len = sizeof(ci) - 1;
    const uint8_t ad[] = {0xAA, 0xBB, 0xCC};
    const size_t ad_len = sizeof(ad);

    // --- Variables ---
    /**
     * Protocol Runtime Variables:
     *
     * ctx_i: The CPace context for the initiator side
     * ctx_r: The CPace context for the responder side
     *
     * msg1: The first message sent from initiator to responder (contains Ya, the initiator's public key)
     * msg2: The second message sent from responder to initiator (contains Yb, the responder's public key)
     *
     * isk_i: The Implicit Shared Key derived by the initiator
     * isk_r: The Implicit Shared Key derived by the responder
     *      - Both ISKs should be identical if the protocol succeeds
     *      - The ISK is the cryptographic key that can be used for subsequent encrypted communication
     */
    // Stack-allocated contexts
    cpace_ctx_t ctx_i;
    cpace_ctx_t ctx_r;
    uint8_t msg1[CPACE_PUBLIC_BYTES]; // First message (initiator → responder)
    uint8_t msg2[CPACE_PUBLIC_BYTES]; // Second message (responder → initiator)
    uint8_t isk_i[CPACE_ISK_BYTES];   // Initiator's derived shared key
    uint8_t isk_r[CPACE_ISK_BYTES];   // Responder's derived shared key
    cpace_error_t err = CPACE_OK;
    const crypto_provider_t *provider = NULL;
    int final_status = EXIT_FAILURE; // Assume failure initially

    // --- Initialization ---
    printf("Initializing Monocypher backend...\n");
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        fprintf(stderr, "Error: Failed to initialize Monocypher backend.\n");
        // No cleanup needed yet as nothing else was allocated
        return EXIT_FAILURE;
    }

    printf("Getting Monocypher provider...\n");
    provider = cpace_get_provider_monocypher();
    if (!provider) {
        fprintf(stderr, "Error: Failed to get Monocypher provider.\n");
        goto cleanup; // Need to cleanup backend
    }

    // --- Context Initialization ---
    printf("Initializing Initiator context...\n");
    err = cpace_ctx_init(&ctx_i, CPACE_ROLE_INITIATOR, provider);
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Failed to initialize Initiator context: %d\n", err);
        goto cleanup;
    }

    printf("Initializing Responder context...\n");
    err = cpace_ctx_init(&ctx_r, CPACE_ROLE_RESPONDER, provider);
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Failed to initialize Responder context: %d\n", err);
        goto cleanup;
    }

    // --- Protocol Steps ---
    /**
     * CPace Protocol Flow:
     *
     * The protocol consists of a 3-step exchange:
     *
     * 1. Initiator Start:
     *    - The initiator generates and sends its public key (Ya) to the responder
     *    - Uses PRS (password), SID, CI, and AD as inputs to the key generation
     *
     * 2. Responder Respond:
     *    - The responder receives Ya from the initiator
     *    - Generates its own public key (Yb) using the same inputs
     *    - Computes the shared key (ISK) using the initiator's public key
     *    - Sends Yb back to the initiator
     *
     * 3. Initiator Finish:
     *    - The initiator receives Yb from the responder
     *    - Computes the shared key (ISK) using the responder's public key
     *
     * If both parties used the same password and parameters, they will derive
     * identical ISK values that can be used for subsequent secure communication.
     */

    // 1. Initiator Starts
    printf("Initiator: Starting protocol...\n");
    err = cpace_initiator_start(&ctx_i, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1);
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Initiator start failed with code %d.\n", err);
        goto cleanup;
    }
    print_hex("Initiator: Sent Msg1 (Ya)", msg1, CPACE_PUBLIC_BYTES);

    // 2. Responder Responds
    printf("Responder: Responding to Msg1...\n");
    err = cpace_responder_respond(&ctx_r, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1, msg2, isk_r);
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Responder respond failed with code %d.\n", err);
        goto cleanup;
    }
    print_hex("Responder: Sent Msg2 (Yb)", msg2, CPACE_PUBLIC_BYTES);
    print_hex("Responder: Derived ISK", isk_r, CPACE_ISK_BYTES);

    // 3. Initiator Finishes
    printf("Initiator: Finishing protocol with Msg2...\n");
    err = cpace_initiator_finish(&ctx_i, msg2, isk_i);
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Initiator finish failed with code %d.\n", err);
        goto cleanup;
    }
    print_hex("Initiator: Derived ISK", isk_i, CPACE_ISK_BYTES);

    // --- Verification ---
    printf("Verifying ISKs match...\n");
    if (memcmp(isk_i, isk_r, CPACE_ISK_BYTES) == 0) {
        printf("SUCCESS: ISKs match!\n");
        final_status = EXIT_SUCCESS; // Mark as success
    } else {
        fprintf(stderr, "FAILURE: ISKs do NOT match!\n");
        // final_status remains EXIT_FAILURE
    }

// --- Cleanup ---
cleanup:
    printf("Cleaning up...\n");
    // Clean up the contexts (safe to call regardless of initialization state)
    cpace_ctx_cleanup(&ctx_i);
    printf("Cleaned up Initiator context.\n");
    cpace_ctx_cleanup(&ctx_r);
    printf("Cleaned up Responder context.\n");

    // Always cleanup the backend if initialization was attempted
    easy_cpace_monocypher_cleanup();
    printf("Cleaned up Monocypher backend.\n");

    printf("--- Basic Exchange Example Finished (%s) ---\n", (final_status == EXIT_SUCCESS) ? "SUCCESS" : "FAILURE");
    return final_status;
}
