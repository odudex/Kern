#ifndef PSBT_INTERNAL_H
#define PSBT_INTERNAL_H

#include "psbt.h"
#include <wally_script.h>

/* Largest redeem/witness script the wallet regenerates and compares.
 * libwally's script generation enforces this same 520-byte bound
 * (MAX_SCRIPT_ELEMENT_SIZE) on sh()/wsh() inner scripts, including witness
 * scripts (an upstream limitation: P2WSH standardness allows 3600). Descriptor
 * validation trial-generates scripts at load time against this limit, so
 * anything registered is regenerable here. */
#define PSBT_MAX_INNER_SCRIPT_LEN WALLY_SCRIPTSIG_MAX_LEN

typedef struct {
  uint8_t spk[34];
  size_t spk_len;
  uint8_t redeem[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t redeem_len;
  uint8_t witness[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t witness_len;
} expected_scripts_t;

#ifdef PSBT_TESTING
bool claim_regenerate(const claim_t *claim, bool is_testnet,
                      expected_scripts_t *out);
#endif

#endif // PSBT_INTERNAL_H
