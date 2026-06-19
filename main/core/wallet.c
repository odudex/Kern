#include "wallet.h"
#include "key.h"
#include "registry.h"

static bool wallet_initialized = false;
static bool wallet_watch_only = false;
static wallet_network_t wallet_network = WALLET_NETWORK_MAINNET;

bool wallet_init(wallet_network_t network) {
  /* Module-enforced invariant: wallet_is_initialized() implies a master key
   * is loaded. Callers must call key_load_from_mnemonic() first. */
  if (!key_is_loaded())
    return false;
  wallet_network = network;
  wallet_initialized = true;
  return true;
}

bool wallet_is_initialized(void) { return wallet_initialized; }

wallet_network_t wallet_get_network(void) { return wallet_network; }

void wallet_cleanup(void) {
  wallet_initialized = false;
  registry_clear();
}

void wallet_unload(void) {
  key_unload();
  wallet_cleanup();
}

void wallet_set_watch_only(wallet_network_t network) {
  wallet_watch_only = true;
  wallet_network = network;
}

bool wallet_is_watch_only(void) { return wallet_watch_only; }

void wallet_clear_watch_only(void) {
  wallet_watch_only = false;
  registry_clear();
}
