#ifndef BIP322_H
#define BIP322_H

#include <stdbool.h>

struct wally_psbt;

typedef struct {
  char *message; // UTF-8 message being signed (may be empty)
  char *address; // Address being proven, from the input's witness_utxo
} bip322_request_t;

// True if the PSBT carries the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09)
// global field, marking it as a BIP322 message-signing request.
bool bip322_detect(const struct wally_psbt *psbt);

// Validates a BIP322 to_sign PSBT: structure (version-0 tx, single input at
// vout 0, single 0-value OP_RETURN output), and that the input spends the
// to_spend transaction committing to the message and the proven script.
// On success fills `out` with the message and proven address.
bool bip322_parse(const struct wally_psbt *psbt, bool is_testnet,
                  bip322_request_t *out);

void bip322_request_free(bip322_request_t *req);

#endif // BIP322_H
