#include "dice_mnemonic.h"
#include "../utils/secure_mem.h"
#include "kern_wally.h"
#include <wally_core.h>
#include <wally_crypto.h>

bool dice_mnemonic_from_rolls(const char *rolls, size_t rolls_len,
                              int word_count, char **mnemonic_out) {
  if (mnemonic_out)
    *mnemonic_out = NULL;
  if (!rolls || rolls_len == 0 || !mnemonic_out ||
      (word_count != 12 && word_count != 24))
    return false;

  unsigned char hash[SHA256_LEN];
  bool ok =
      wally_sha256((const unsigned char *)rolls, rolls_len, hash,
                   sizeof(hash)) == WALLY_OK &&
      kern_bip39_mnemonic_from_bytes(NULL, hash, word_count == 12 ? 16 : 32,
                                     mnemonic_out) == WALLY_OK &&
      *mnemonic_out;
  secure_memzero(hash, sizeof(hash));
  return ok;
}
