#include "easy_cpace.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUM_ITERATIONS 10000
#define PASSWORD "test-password"
#define CHANNEL_ID "test-channel"
#define USER_ID_A "alice"
#define USER_ID_B "bob"

// Helper function to measure time
double measure_time_ms(struct timespec start, struct timespec end)
{
    return ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_nsec - start.tv_nsec) / 1000000.0);
}

// Helper for generating random data using /dev/urandom directly
// This is just for the benchmark - in real code, use the crypto provider
int secure_random_bytes(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/urandom");
        return 0; // Error
    }

    ssize_t bytes_read = 0;
    while (bytes_read < (ssize_t)len) {
        ssize_t ret = read(fd, buf + bytes_read, len - bytes_read);
        if (ret == -1) {
            if (errno == EINTR) {
                continue; // Interrupted, try again
            }
            perror("Failed to read from /dev/urandom");
            close(fd);
            return 0; // Error
        }
        if (ret == 0) {
            // Should not happen with /dev/urandom
            fprintf(stderr, "End of file reached on /dev/urandom\n");
            close(fd);
            return 0; // Error
        }
        bytes_read += ret;
    }

    close(fd);
    return 1; // OK
}

int main(void)
{

    // Setup variables
    cpace_ctx_t alice, bob;
    uint8_t alice_m1[CPACE_PUBLIC_BYTES], bob_m1[CPACE_PUBLIC_BYTES];
    uint8_t alice_m2[CPACE_PUBLIC_BYTES], bob_m2[CPACE_PUBLIC_BYTES];
    uint8_t alice_key[CPACE_ISK_BYTES], bob_key[CPACE_ISK_BYTES];
    double total_time_init = 0.0;
    double total_time_m1 = 0.0;
    double total_time_m2 = 0.0;
    double total_time_key = 0.0;
    struct timespec start, end;
    cpace_error_t err;
    const crypto_provider_t *provider;

    printf("Running CPace benchmark with %d iterations...\n", NUM_ITERATIONS);

    // Generate some random data to test our secure_random_bytes function
    uint8_t random_seed[32];
    if (!secure_random_bytes(random_seed, sizeof(random_seed))) {
        fprintf(stderr, "Error: Failed to generate random seed.\n");
        return EXIT_FAILURE;
    }

    // Initialize backend
    err = easy_cpace_monocypher_init();
    if (err != CPACE_OK) {
        fprintf(stderr, "Error: Failed to initialize Monocypher backend.\n");
        return EXIT_FAILURE;
    }

    // Get provider
    provider = cpace_get_provider_monocypher();
    if (!provider) {
        fprintf(stderr, "Error: Failed to get Monocypher provider.\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Measure initialization time
        clock_gettime(CLOCK_MONOTONIC, &start);
        err = cpace_ctx_init(&alice, CPACE_ROLE_INITIATOR, provider);
        if (err != CPACE_OK) {
            fprintf(stderr, "Error: Failed to initialize Alice context: %d\n", err);
            return EXIT_FAILURE;
        }

        err = cpace_ctx_init(&bob, CPACE_ROLE_RESPONDER, provider);
        if (err != CPACE_OK) {
            fprintf(stderr, "Error: Failed to initialize Bob context: %d\n", err);
            return EXIT_FAILURE;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_init += measure_time_ms(start, end);

        // Measure first message generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        err = cpace_initiator_start(&alice,
                                    (const uint8_t *)PASSWORD,
                                    strlen(PASSWORD),
                                    (const uint8_t *)CHANNEL_ID,
                                    strlen(CHANNEL_ID),
                                    (const uint8_t *)USER_ID_A,
                                    strlen(USER_ID_A),
                                    (const uint8_t *)USER_ID_B,
                                    strlen(USER_ID_B),
                                    alice_m1);
        if (err != CPACE_OK) {
            fprintf(stderr, "Error: Alice failed to generate message 1: %d\n", err);
            return EXIT_FAILURE;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_m1 += measure_time_ms(start, end);

        // Measure second message generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        err = cpace_responder_respond(&bob,
                                      (const uint8_t *)PASSWORD,
                                      strlen(PASSWORD),
                                      (const uint8_t *)CHANNEL_ID,
                                      strlen(CHANNEL_ID),
                                      (const uint8_t *)USER_ID_A,
                                      strlen(USER_ID_A),
                                      (const uint8_t *)USER_ID_B,
                                      strlen(USER_ID_B),
                                      alice_m1,
                                      bob_m2,
                                      bob_key);
        if (err != CPACE_OK) {
            fprintf(stderr, "Error: Bob failed to generate message 2: %d\n", err);
            return EXIT_FAILURE;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_m2 += measure_time_ms(start, end);

        // Measure key generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        err = cpace_initiator_finish(&alice, bob_m2, alice_key);
        if (err != CPACE_OK) {
            fprintf(stderr, "Error: Alice failed to generate key: %d\n", err);
            return EXIT_FAILURE;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_key += measure_time_ms(start, end);

        // Verify keys match
        if (memcmp(alice_key, bob_key, CPACE_ISK_BYTES) != 0) {
            fprintf(stderr, "Error: Keys do not match at iteration %d\n", i);
            return EXIT_FAILURE;
        }

        // Clean up contexts
        cpace_ctx_cleanup(&alice);
        cpace_ctx_cleanup(&bob);
    }

    // Clean up backend
    easy_cpace_monocypher_cleanup();

    // Print results
    printf("CPace Benchmark Results (%d iterations)\n", NUM_ITERATIONS);
    printf("---------------------------------------\n");
    printf("Init:        %.4f ms (avg: %.6f ms)\n", total_time_init, total_time_init / NUM_ITERATIONS);
    printf("Message 1:   %.4f ms (avg: %.6f ms)\n", total_time_m1, total_time_m1 / NUM_ITERATIONS);
    printf("Message 2:   %.4f ms (avg: %.6f ms)\n", total_time_m2, total_time_m2 / NUM_ITERATIONS);
    printf("Key Gen:     %.4f ms (avg: %.6f ms)\n", total_time_key, total_time_key / NUM_ITERATIONS);
    printf("Total Time:  %.4f ms (avg: %.6f ms)\n",
           total_time_init + total_time_m1 + total_time_m2 + total_time_key,
           (total_time_init + total_time_m1 + total_time_m2 + total_time_key) / NUM_ITERATIONS);

    return EXIT_SUCCESS;
}