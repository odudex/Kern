#ifndef BIP138_CRYPTO_H
#define BIP138_CRYPTO_H

#include <bip138.h>

/* SHA-256 and randomness from crypto_utils, ChaCha20-Poly1305 from PSA. */
const bip138_crypto *kern_bip138_crypto(void);

#endif // BIP138_CRYPTO_H
