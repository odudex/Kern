#include "wallet.h"
#include "key.h"
#include "registry.h"

static bool wallet_initialized = false;
static wallet_network_t wallet_network = WALLET_NETWORK_MAINNET;

bool wallet_init(wallet_network_t network) {
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
