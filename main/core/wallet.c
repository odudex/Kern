#include "wallet.h"
#include "key.h"
#include <esp_log.h>
#include <stdio.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_script.h>

static const char *TAG = "wallet";

static bool wallet_initialized = false;
static wallet_type_t wallet_type = WALLET_TYPE_NATIVE_SEGWIT;
static wallet_network_t wallet_network = WALLET_NETWORK_MAINNET;
static wallet_policy_t wallet_policy = WALLET_POLICY_SINGLESIG;
static struct ext_key *account_key = NULL;
static uint32_t wallet_account = 0;
static char derivation_path_buffer[48];

// Descriptor for multisig wallets
static struct wally_descriptor *loaded_descriptor = NULL;

int wallet_format_derivation_path(char *buf, size_t buf_size,
                                  wallet_policy_t policy,
                                  wallet_network_t network, uint32_t account) {
  uint32_t coin = (network == WALLET_NETWORK_MAINNET) ? 0 : 1;
  if (policy == WALLET_POLICY_MULTISIG) {
    return snprintf(buf, buf_size, "m/48'/%u'/%u'/2'", coin, account);
  }
  return snprintf(buf, buf_size, "m/84'/%u'/%u'", coin, account);
}

int wallet_format_derivation_compact(char *buf, size_t buf_size,
                                     wallet_policy_t policy,
                                     wallet_network_t network,
                                     uint32_t account) {
  uint32_t coin = (network == WALLET_NETWORK_MAINNET) ? 0 : 1;
  if (policy == WALLET_POLICY_MULTISIG) {
    return snprintf(buf, buf_size, "48h/%uh/%uh/2h", coin, account);
  }
  return snprintf(buf, buf_size, "84h/%uh/%uh", coin, account);
}

bool wallet_init(wallet_network_t network) {
  if (wallet_initialized) {
    return true;
  }

  if (!key_is_loaded()) {
    return false;
  }

  wallet_network = network;

  wallet_format_derivation_path(derivation_path_buffer,
                                sizeof(derivation_path_buffer), wallet_policy,
                                network, wallet_account);

  if (!key_get_derived_key(derivation_path_buffer, &account_key)) {
    return false;
  }

  wallet_initialized = true;
  wallet_type = WALLET_TYPE_NATIVE_SEGWIT;

  return true;
}

bool wallet_is_initialized(void) { return wallet_initialized; }

wallet_type_t wallet_get_type(void) { return wallet_type; }

wallet_network_t wallet_get_network(void) { return wallet_network; }

const char *wallet_get_derivation(void) {
  if (!wallet_initialized)
    return NULL;
  return derivation_path_buffer;
}

bool wallet_get_account_xpub(char **xpub_out) {
  if (!wallet_initialized || !account_key || !xpub_out) {
    return false;
  }

  int ret = bip32_key_to_base58(account_key, BIP32_FLAG_KEY_PUBLIC, xpub_out);
  return (ret == WALLY_OK);
}

// chain: 0 = receive, 1 = change
static bool derive_address(uint32_t chain, uint32_t index, char **address_out) {
  if (!wallet_initialized || !account_key || chain > 1) {
    return false;
  }

  uint32_t chain_path[1] = {chain};
  struct ext_key *chain_key = NULL;
  int ret = bip32_key_from_parent_path_alloc(
      account_key, chain_path, 1, BIP32_FLAG_KEY_PRIVATE, &chain_key);
  if (ret != WALLY_OK) {
    return false;
  }

  uint32_t addr_path[1] = {index};
  struct ext_key *addr_key = NULL;
  ret = bip32_key_from_parent_path_alloc(chain_key, addr_path, 1,
                                         BIP32_FLAG_KEY_PUBLIC, &addr_key);
  bip32_key_free(chain_key);

  if (ret != WALLY_OK) {
    return false;
  }

  unsigned char script[WALLY_WITNESSSCRIPT_MAX_LEN];
  size_t script_len;

  ret = wally_witness_program_from_bytes(addr_key->pub_key, EC_PUBLIC_KEY_LEN,
                                         WALLY_SCRIPT_HASH160, script,
                                         sizeof(script), &script_len);
  bip32_key_free(addr_key);

  if (ret != WALLY_OK) {
    return false;
  }

  const char *hrp = (wallet_network == WALLET_NETWORK_MAINNET) ? "bc" : "tb";
  ret = wally_addr_segwit_from_bytes(script, script_len, hrp, 0, address_out);
  return (ret == WALLY_OK);
}

bool wallet_get_receive_address(uint32_t index, char **address_out) {
  if (!address_out) {
    return false;
  }
  return derive_address(0, index, address_out);
}

bool wallet_get_change_address(uint32_t index, char **address_out) {
  if (!address_out) {
    return false;
  }
  return derive_address(1, index, address_out);
}

// Get scriptPubKey for a wallet address
// is_change: false = receive (chain 0), true = change (chain 1)
bool wallet_get_scriptpubkey(bool is_change, uint32_t index,
                             unsigned char *script_out,
                             size_t *script_len_out) {
  if (!wallet_initialized || !account_key || !script_out || !script_len_out) {
    return false;
  }

  uint32_t chain = is_change ? 1 : 0;
  uint32_t chain_path[1] = {chain};
  struct ext_key *chain_key = NULL;
  int ret = bip32_key_from_parent_path_alloc(
      account_key, chain_path, 1, BIP32_FLAG_KEY_PRIVATE, &chain_key);
  if (ret != WALLY_OK) {
    return false;
  }

  uint32_t addr_path[1] = {index};
  struct ext_key *addr_key = NULL;
  ret = bip32_key_from_parent_path_alloc(chain_key, addr_path, 1,
                                         BIP32_FLAG_KEY_PUBLIC, &addr_key);
  bip32_key_free(chain_key);

  if (ret != WALLY_OK) {
    return false;
  }

  ret = wally_witness_program_from_bytes(
      addr_key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, script_out,
      WALLY_WITNESSSCRIPT_MAX_LEN, script_len_out);
  bip32_key_free(addr_key);

  return (ret == WALLY_OK);
}

uint32_t wallet_get_account(void) { return wallet_account; }

bool wallet_set_account(uint32_t account) {
  wallet_account = account;
  return true;
}

void wallet_cleanup(void) {
  if (account_key) {
    bip32_key_free(account_key);
    account_key = NULL;
  }
  if (loaded_descriptor) {
    wally_descriptor_free(loaded_descriptor);
    loaded_descriptor = NULL;
  }
  wallet_initialized = false;
  wallet_account = 0;
}

// Policy management
wallet_policy_t wallet_get_policy(void) { return wallet_policy; }

bool wallet_set_policy(wallet_policy_t policy) {
  wallet_policy = policy;
  return true;
}

// Descriptor management
bool wallet_has_descriptor(void) { return loaded_descriptor != NULL; }

bool wallet_load_descriptor(const char *descriptor_str) {
  if (!descriptor_str) {
    return false;
  }

  // Clear existing descriptor
  if (loaded_descriptor) {
    wally_descriptor_free(loaded_descriptor);
    loaded_descriptor = NULL;
  }

  // Determine network for descriptor parsing
  uint32_t network = (wallet_network == WALLET_NETWORK_MAINNET)
                         ? WALLY_NETWORK_BITCOIN_MAINNET
                         : WALLY_NETWORK_BITCOIN_TESTNET;

  int ret = wally_descriptor_parse(descriptor_str, NULL, network, 0,
                                   &loaded_descriptor);
  if (ret != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to parse descriptor: %d", ret);
    return false;
  }

  return true;
}

void wallet_clear_descriptor(void) {
  if (loaded_descriptor) {
    wally_descriptor_free(loaded_descriptor);
    loaded_descriptor = NULL;
  }
}

// Multisig address generation using loaded descriptor
// multi_index: 0 = receive, 1 = change (for descriptors with <0;1> multipath)
static bool derive_multisig_address(uint32_t multi_index, uint32_t child_num,
                                    char **address_out) {
  if (!loaded_descriptor || !address_out) {
    return false;
  }

  // Check how many paths the descriptor has
  uint32_t num_paths = 0;
  int ret = wally_descriptor_get_num_paths(loaded_descriptor, &num_paths);
  if (ret != WALLY_OK) {
    return false;
  }

  // If descriptor only has 1 path (no multipath), force multi_index to 0
  uint32_t actual_multi_index = (num_paths <= 1) ? 0 : multi_index;

  ret = wally_descriptor_to_address(loaded_descriptor, 0, actual_multi_index,
                                    child_num, 0, address_out);
  return (ret == WALLY_OK);
}

bool wallet_get_multisig_receive_address(uint32_t index, char **address_out) {
  if (!address_out) {
    return false;
  }
  return derive_multisig_address(0, index, address_out);
}

bool wallet_get_multisig_change_address(uint32_t index, char **address_out) {
  if (!address_out) {
    return false;
  }
  return derive_multisig_address(1, index, address_out);
}
