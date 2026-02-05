#ifndef WALLET_H
#define WALLET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  WALLET_TYPE_NATIVE_SEGWIT = 0,
} wallet_type_t;

typedef enum {
  WALLET_NETWORK_MAINNET = 0,
  WALLET_NETWORK_TESTNET = 1,
} wallet_network_t;

typedef enum {
  WALLET_POLICY_SINGLESIG = 0,
  WALLET_POLICY_MULTISIG = 1,
} wallet_policy_t;

// Format derivation path: "m/84'/0'/0'" or "m/48'/0'/0'/2'"
int wallet_format_derivation_path(char *buf, size_t buf_size,
                                  wallet_policy_t policy,
                                  wallet_network_t network, uint32_t account);

// Format compact derivation: "84h/0h/0h" or "48h/0h/0h/2h"
int wallet_format_derivation_compact(char *buf, size_t buf_size,
                                     wallet_policy_t policy,
                                     wallet_network_t network,
                                     uint32_t account);

bool wallet_init(wallet_network_t network);
bool wallet_is_initialized(void);
wallet_type_t wallet_get_type(void);
wallet_network_t wallet_get_network(void);
const char *wallet_get_derivation(void);
bool wallet_get_account_xpub(char **xpub_out);
bool wallet_get_receive_address(uint32_t index, char **address_out);
bool wallet_get_change_address(uint32_t index, char **address_out);
bool wallet_get_scriptpubkey(bool is_change, uint32_t index,
                             unsigned char *script_out, size_t *script_len_out);
uint32_t wallet_get_account(void);
bool wallet_set_account(uint32_t account);
void wallet_cleanup(void);

// Policy management
wallet_policy_t wallet_get_policy(void);
bool wallet_set_policy(wallet_policy_t policy);

// Descriptor management (for multisig)
bool wallet_has_descriptor(void);
bool wallet_load_descriptor(const char *descriptor_str);
void wallet_clear_descriptor(void);

// Multisig address generation (requires loaded descriptor)
bool wallet_get_multisig_receive_address(uint32_t index, char **address_out);
bool wallet_get_multisig_change_address(uint32_t index, char **address_out);

#endif // WALLET_H
