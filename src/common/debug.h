#ifndef CPACE_DEBUG_H
#define CPACE_DEBUG_H

#include <stdint.h>
#include <stdio.h>

#ifdef CPACE_DEBUG_LOG
#define DEBUG_LOG(fmt, ...)                                                                                            \
    printf("DEBUG: " fmt "\n", ##__VA_ARGS__);                                                                         \
    fflush(stdout)
#define DEBUG_ENTER(func)                                                                                              \
    printf("DEBUG: --> %s\n", func);                                                                                   \
    fflush(stdout)
#define DEBUG_EXIT(func, status)                                                                                       \
    printf("DEBUG: <-- %s: %d\n", func, (int)(status));                                                                \
    fflush(stdout)
#define DEBUG_PTR(name, ptr)                                                                                           \
    printf("DEBUG: %s = %p\n", name, (void *)(ptr));                                                                   \
    fflush(stdout)
#define DEBUG_HEX(name, data, len)                                                                                     \
    do {                                                                                                               \
        if ((data) != NULL) {                                                                                          \
            printf("DEBUG: %s (%zu bytes):\n", name, (size_t)(len));                                                   \
            for (size_t i = 0; i < (size_t)(len); ++i) {                                                               \
                printf("%02x", ((const uint8_t *)(data))[i]);                                                          \
                if ((i + 1) % 16 == 0)                                                                                 \
                    printf("\n");                                                                                      \
                else if ((i + 1) % 8 == 0)                                                                             \
                    printf("  ");                                                                                      \
                else                                                                                                   \
                    printf(" ");                                                                                       \
            }                                                                                                          \
            if ((size_t)(len) % 16 != 0)                                                                               \
                printf("\n");                                                                                          \
            fflush(stdout);                                                                                            \
        } else {                                                                                                       \
            printf("DEBUG: %s = NULL\n", name);                                                                        \
        }                                                                                                              \
    } while (0)
#else
#define DEBUG_LOG(fmt, ...)
#define DEBUG_ENTER(func)
#define DEBUG_EXIT(func, status)
#define DEBUG_PTR(name, ptr)
#define DEBUG_HEX(name, data, len)
#endif

#endif /* CPACE_DEBUG_H */