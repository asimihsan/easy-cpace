#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "easy_cpace.h"

#define NUM_ITERATIONS 10000
#define PASSWORD "test-password"
#define CHANNEL_ID "test-channel"
#define USER_ID_A "alice"
#define USER_ID_B "bob"

// Helper function to measure time
double measure_time_ms(struct timespec start, struct timespec end) {
    return ((end.tv_sec - start.tv_sec) * 1000.0) +
           ((end.tv_nsec - start.tv_nsec) / 1000000.0);
}

// Helper for generating random data
void generate_random_data(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

int main(void) {
    // Seed random number generator
    srand((unsigned int)time(NULL));
    
    // Setup variables
    cpace_ctx_t alice, bob;
    cpace_message_t alice_m1, bob_m1, alice_m2, bob_m2;
    cpace_key_t alice_key, bob_key;
    double total_time_init = 0.0;
    double total_time_m1 = 0.0;
    double total_time_m2 = 0.0;
    double total_time_key = 0.0;
    struct timespec start, end;
    
    printf("Running CPace benchmark with %d iterations...\n", NUM_ITERATIONS);
    
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Measure initialization time
        clock_gettime(CLOCK_MONOTONIC, &start);
        cpace_init(&alice, CPACE_ROLE_INITIATOR, PASSWORD, strlen(PASSWORD),
                  CHANNEL_ID, strlen(CHANNEL_ID), USER_ID_A, strlen(USER_ID_A),
                  USER_ID_B, strlen(USER_ID_B));
        cpace_init(&bob, CPACE_ROLE_RESPONDER, PASSWORD, strlen(PASSWORD),
                  CHANNEL_ID, strlen(CHANNEL_ID), USER_ID_A, strlen(USER_ID_A),
                  USER_ID_B, strlen(USER_ID_B));
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_init += measure_time_ms(start, end);
        
        // Measure first message generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        cpace_generate_message_1(&alice, &alice_m1);
        cpace_generate_message_1(&bob, &bob_m1);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_m1 += measure_time_ms(start, end);
        
        // Measure second message generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        cpace_generate_message_2(&alice, &bob_m1, &alice_m2);
        cpace_generate_message_2(&bob, &alice_m1, &bob_m2);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_m2 += measure_time_ms(start, end);
        
        // Measure key generation time
        clock_gettime(CLOCK_MONOTONIC, &start);
        cpace_generate_key(&alice, &bob_m2, &alice_key);
        cpace_generate_key(&bob, &alice_m2, &bob_key);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_time_key += measure_time_ms(start, end);
        
        // Verify keys match
        if (memcmp(&alice_key, &bob_key, sizeof(cpace_key_t)) != 0) {
            fprintf(stderr, "Error: Keys do not match at iteration %d\n", i);
            return EXIT_FAILURE;
        }
    }
    
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