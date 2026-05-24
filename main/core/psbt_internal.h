#ifndef PSBT_INTERNAL_H
#define PSBT_INTERNAL_H

#include "psbt.h"

typedef struct {
  uint8_t spk[34];
  size_t spk_len;
  uint8_t redeem[256];
  size_t redeem_len;
  uint8_t witness[256];
  size_t witness_len;
} expected_scripts_t;

#ifdef PSBT_TESTING
bool claim_regenerate(const claim_t *claim, bool is_testnet,
                      expected_scripts_t *out);
#endif

#endif // PSBT_INTERNAL_H
