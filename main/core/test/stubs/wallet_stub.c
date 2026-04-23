#include "core/registry.h"
#include "core/wallet.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint32_t wallet_get_account(void) { return 0; }
wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }
bool wallet_has_descriptor(void) { return false; }
bool wallet_get_multisig_receive_address(uint32_t i, char **a) {
  (void)i;
  (void)a;
  return false;
}
bool wallet_get_multisig_change_address(uint32_t i, char **a) {
  (void)i;
  (void)a;
  return false;
}
registry_entry_t *registry_match_keypath(const uint8_t *kp, size_t kp_len,
                                         size_t *cursor) {
  (void)kp;
  (void)kp_len;
  (void)cursor;
  return NULL;
}
