#ifndef SECP_HARDENING_H
#define SECP_HARDENING_H

#include <stdbool.h>

/* Re-randomizes the secp256k1 context's blinding, so repeated derivations and
 * signatures do not run with the same, otherwise fixed, blinding values. It
 * never changes a signature: nonces stay RFC6979 and BIP340, so anyone holding
 * the seed can check them. Call at boot, before loading a key and before
 * signing. False when no randomness or memory was available; the previous
 * blinding then stays. */
bool secp_blind_refresh(void);

#endif // SECP_HARDENING_H
