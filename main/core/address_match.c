#include "address_match.h"
#include "psbt_internal.h"
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

bool address_match_decode(const char *address, bool is_testnet, uint8_t *spk,
                          size_t spk_cap, size_t *spk_len) {
  if (!address || !spk || !spk_len)
    return false;
  size_t written = 0;
  if (wally_addr_segwit_to_bytes(address, is_testnet ? "tb" : "bc", 0, spk,
                                 spk_cap, &written) != WALLY_OK &&
      wally_address_to_scriptpubkey(address,
                                    is_testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                               : WALLY_NETWORK_BITCOIN_MAINNET,
                                    spk, spk_cap, &written) != WALLY_OK)
    return false;
  if (written == 0 || written > spk_cap)
    return false;
  *spk_len = written;
  return true;
}

static bool spk_equal(const uint8_t *a, size_t a_len, const uint8_t *b,
                      size_t b_len) {
  return a_len == b_len && memcmp(a, b, a_len) == 0;
}

bool address_match_singlesig(ss_script_type_t script, uint32_t account,
                             bool is_testnet, const uint8_t *spk,
                             size_t spk_len, uint32_t start, uint32_t limit,
                             address_match_t *out) {
  if (!spk || !out)
    return false;
  for (uint32_t chain = 0; chain <= 1; chain++) {
    for (uint32_t i = start; i < limit; i++) {
      uint8_t candidate[34];
      size_t len = 0;
      if (ss_scriptpubkey(script, account, chain, i, is_testnet, candidate,
                          &len) &&
          spk_equal(candidate, len, spk, spk_len)) {
        out->chain = chain;
        out->index = i;
        return true;
      }
    }
  }
  return false;
}

bool address_match_descriptor(const struct wally_descriptor *desc,
                              size_t num_paths, const uint8_t *spk,
                              size_t spk_len, uint32_t start, uint32_t limit,
                              address_match_t *out) {
  if (!desc || !spk || !out)
    return false;
  uint32_t chains = num_paths <= 1 ? 1 : 2;
  for (uint32_t chain = 0; chain < chains; chain++) {
    for (uint32_t i = start; i < limit; i++) {
      /* Depth 0 builds the inner script in this buffer before hashing it, so
       * it must hold the largest script a registered descriptor generates. */
      uint8_t candidate[PSBT_MAX_INNER_SCRIPT_LEN];
      size_t len = 0;
      if (wally_descriptor_to_script(desc, 0, 0, 0, chain, i, 0, candidate,
                                     sizeof(candidate), &len) == WALLY_OK &&
          len <= sizeof(candidate) && spk_equal(candidate, len, spk, spk_len)) {
        out->chain = chain;
        out->index = i;
        return true;
      }
    }
  }
  return false;
}
