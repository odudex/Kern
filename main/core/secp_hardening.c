#include "secp_hardening.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include <esp_log.h>
#include <stddef.h>
#include <wally_core.h>

static const char *TAG = "secp_hardening";

bool secp_blind_refresh(void) {
  unsigned char seed[WALLY_SECP_RANDOMIZE_LEN];
  bool ok = crypto_random_bytes(seed, sizeof(seed)) == CRYPTO_OK &&
            wally_secp_randomize(seed, sizeof(seed)) == WALLY_OK;
  secure_memzero(seed, sizeof(seed));
  if (!ok)
    ESP_LOGW(TAG, "secp256k1 blinding not refreshed");
  return ok;
}
