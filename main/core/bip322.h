#ifndef BIP322_H
#define BIP322_H

#include "../utils/attributes.h"
#include <stdbool.h>

struct wally_psbt;

typedef struct {
  char *message; // UTF-8 message being signed (may be empty)
  char *address; // Address being proven, from the input's witness_utxo
} bip322_request_t;

// True if the PSBT is a BIP322 message-signing request by the rules BIP322
// gives a signer: the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) global field,
// a first input spending output 0 and a single 0-value OP_RETURN output.
// Anything else is an ordinary PSBT. A request must then pass bip322_parse:
// one this signer does not support is refused, never signed as a transaction.
KERN_WARN_UNUSED_RESULT bool bip322_detect(const struct wally_psbt *psbt);

// Validates a BIP322 to_sign PSBT: structure (v0 PSBT, version-0 tx with no
// locktime, single input at vout 0 with sequence 0, single 0-value OP_RETURN
// output), and that the input spends the to_spend transaction committing to
// the message and the proven script.
// On success fills `out` with the message and proven address.
KERN_WARN_UNUSED_RESULT bool bip322_parse(const struct wally_psbt *psbt,
                                          bool is_testnet,
                                          bip322_request_t *out);

void bip322_request_free(bip322_request_t *req);

#endif // BIP322_H
