/* Descriptor text, as a QR, setup file or flash backup delivers it:
 * registration, keyed validation and the policy renderers. */
#include "core/descriptor_validator.h"
#include "core/key.h"
#include "core/miniscript_policy.h"
#include "core/registry.h"
#include "core/wallet.h"
#include "fuzz.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

void fuzz_load_test_key(void) {
  static bool done;
  if (done)
    return;
  done = true;
  if (wally_init(0) != WALLY_OK ||
      !key_load_from_mnemonic("abandon abandon abandon abandon abandon "
                              "abandon abandon abandon abandon abandon "
                              "abandon about",
                              "", false) ||
      !wallet_init(WALLET_NETWORK_MAINNET))
    abort();
}

/* Results are thrown away; this keeps them from being optimised out. */
static volatile int sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_load_test_key();
  if (size > 8192)
    return 0;
  char *text = malloc(size + 1);
  if (!text)
    return 0;
  memcpy(text, data, size);
  text[size] = '\0';

  registry_clear();
  sink += registry_add_from_string("f", text, STORAGE_FLASH, false);
  sink += registry_session_has_duplicate(text, NULL, 0);
  registry_clear();
  sink += descriptor_validate_keyed(text, NULL);

  struct wally_descriptor *desc = NULL;
  if (wallet_descriptor_parse(text, NULL, WALLY_NETWORK_BITCOIN_MAINNET,
                              &desc) == WALLY_OK) {
    char *policy = miniscript_policy_string(desc);
    if (policy) {
      free(miniscript_policy_indent(policy, 24));
      ms_policy_view_t view;
      if (miniscript_policy_view_build(policy, 24, &view))
        miniscript_policy_view_free(&view);
      free(policy);
    }
    wally_descriptor_free(desc);
  }
  free(text);
  return 0;
}
