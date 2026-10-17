/* Stand-in for descriptor_validate_keyed() in tests that link registry.c but
 * not the validator: every descriptor that parses counts as validated, with
 * its first key carrying the wallet's fingerprint as our key. */

#include "core/descriptor_validator.h"
#include "core/key.h"
#include "core/wallet.h"
#include <string.h>
#include <wally_descriptor.h>

descriptor_validation_result_t
descriptor_validate_keyed_parsed(const char *descriptor_str,
                                 struct wally_descriptor **descriptor_out,
                                 int *key_index_out) {
  *descriptor_out = NULL;
  unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
  uint32_t num_keys = 0;
  struct wally_descriptor *desc = NULL;
  if (!descriptor_str || !key_get_fingerprint(fp) ||
      wallet_descriptor_parse(descriptor_str, NULL, wallet_wally_network(),
                              &desc) != WALLY_OK ||
      wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK) {
    wally_descriptor_free(desc);
    return VALIDATION_PARSE_ERROR;
  }
  for (uint32_t i = 0; i < num_keys; i++) {
    unsigned char kfp[BIP32_KEY_FINGERPRINT_LEN];
    if (wally_descriptor_get_key_origin_fingerprint(desc, i, kfp,
                                                    sizeof(kfp)) == WALLY_OK &&
        memcmp(kfp, fp, sizeof(fp)) == 0) {
      *descriptor_out = desc;
      if (key_index_out)
        *key_index_out = (int)i;
      return VALIDATION_SUCCESS;
    }
  }
  wally_descriptor_free(desc);
  return VALIDATION_FINGERPRINT_NOT_FOUND;
}

descriptor_validation_result_t
descriptor_validate_keyed(const char *descriptor_str, int *key_index_out) {
  struct wally_descriptor *desc = NULL;
  descriptor_validation_result_t r =
      descriptor_validate_keyed_parsed(descriptor_str, &desc, key_index_out);
  wally_descriptor_free(desc);
  return r;
}
