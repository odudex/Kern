#ifndef CRYPTO_INIT_H
#define CRYPTO_INIT_H

#include <stdbool.h>

/* Sets libwally up as the firmware signs with it: the library, the secp256k1
 * blinding and the BIP39 seed PBKDF2. The firmware, the simulator and the
 * signing tests all start here, so the tests' known-answer signatures cover
 * any hook added to it. False only when libwally fails to initialize. */
bool crypto_init(void);

#endif // CRYPTO_INIT_H
