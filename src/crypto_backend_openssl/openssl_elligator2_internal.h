#ifndef OPENSSL_ELLIGATOR2_INTERNAL_H
#define OPENSSL_ELLIGATOR2_INTERNAL_H

#include "../crypto_iface/crypto_provider.h" // For CRYPTO_OK/CRYPTO_ERROR constants
#include <stdint.h>

// Make initialization check return status
int ensure_elligator_constants(void);
// Declare cleanup function
void openssl_elligator2_cleanup_constants(void);
// Declare map function (already used by backend)
int openssl_elligator2_map_to_curve(uint8_t *out_point, const uint8_t *u);

#endif // OPENSSL_ELLIGATOR2_INTERNAL_H
