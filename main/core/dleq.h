#ifndef DLEQ_H
#define DLEQ_H

#include "../utils/attributes.h"
#include <secp256k1.h>
#include <stdbool.h>

#define DLEQ_PROOF_LEN 64
#define DLEQ_AUX_LEN 32
#define DLEQ_MESSAGE_LEN 32

// BIP374 proof that `secret` is the discrete log of both secret*generator
// and the shared secret secret*base. `message` is optional (NULL). The proof
// is checked with dleq_verify before it is returned.
KERN_WARN_UNUSED_RESULT bool
dleq_prove(const unsigned char *secret, const secp256k1_pubkey *base,
           const unsigned char *aux, const secp256k1_pubkey *generator,
           const unsigned char *message, unsigned char *proof_out);

// True if `proof` shows that `public` (secret*generator) and `shared_secret`
// (secret*base) share the same discrete log. `message` is optional (NULL).
KERN_WARN_UNUSED_RESULT bool
dleq_verify(const secp256k1_pubkey *public, const secp256k1_pubkey *base,
            const secp256k1_pubkey *shared_secret, const unsigned char *proof,
            const secp256k1_pubkey *generator, const unsigned char *message);

#endif // DLEQ_H
