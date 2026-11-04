#include "crypto_init.h"
#include "crypto_utils.h"
#include "secp_hardening.h"
#include <kern_wally.h>
#include <wally_core.h>

bool crypto_init(void) {
  if (wally_init(0) != WALLY_OK)
    return false;
  secp_blind_refresh();
  kern_set_bip39_pbkdf2(crypto_pbkdf2_sha512);
  return true;
}
