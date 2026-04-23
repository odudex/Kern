#ifndef PSBT_H
#define PSBT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_psbt.h>

#include "registry.h"
#include "ss_whitelist.h"

typedef enum {
  CLAIM_WHITELIST,
  CLAIM_REGISTRY,
} claim_kind_t;

typedef struct {
  claim_kind_t kind;
  union {
    struct {
      ss_script_type_t script;
      uint32_t account;
      uint32_t chain;
      uint32_t index;
      uint32_t purpose;
      uint32_t coin;
    } whitelist;
    struct {
      registry_entry_t *entry;
      uint32_t multi_index;
      uint32_t child_num;
    } registry;
  };
  uint32_t derived_path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t derived_path_len;
} claim_t;

typedef struct {
  uint8_t spk[34];
  size_t spk_len;
  uint8_t redeem[256];
  size_t redeem_len;
  uint8_t witness[256];
  size_t witness_len;
} expected_scripts_t;

typedef struct {
  bool owned;
  bool verified;
  claim_t claim;
  bool requires_ack;
  uint8_t raw_keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
  size_t raw_keypath_len;
} input_ownership_t;

typedef struct {
  bool owned;
  claim_t source;
} output_ownership_t;

input_ownership_t psbt_classify_input(const struct wally_psbt *psbt, size_t i,
                                      bool is_testnet);

output_ownership_t psbt_classify_output(const struct wally_psbt *psbt, size_t i,
                                        bool is_testnet);

bool claim_regenerate(const claim_t *claim, bool is_testnet,
                      expected_scripts_t *out);

bool psbt_input_utxo_script(const struct wally_psbt *psbt, size_t input_i,
                            unsigned char *out, size_t out_cap,
                            size_t *out_len);

bool try_match_whitelist(const unsigned char *keypath, size_t keypath_len,
                         bool is_testnet, claim_t *claim_out);

bool try_match_registry(const unsigned char *keypath, size_t keypath_len,
                        size_t *cursor, claim_t *claim_out);

// Get input value in satoshis
uint64_t psbt_get_input_value(const struct wally_psbt *psbt, size_t index);

// Detect network from derivation paths (returns true if testnet)
bool psbt_detect_network(const struct wally_psbt *psbt);

// Detect account from derivation paths
// Returns the account number from PSBT derivation paths
// Returns -1 if no derivation info found or inconsistent accounts
int32_t psbt_detect_account(const struct wally_psbt *psbt);

// Convert scriptPubKey to address string (caller must free)
char *psbt_scriptpubkey_to_address(const unsigned char *script,
                                   size_t script_len, bool is_testnet);

// Callback for permissive-signing ACK (settings_get_permissive_signing() path).
// Called when an input carries our fingerprint but no verifiable claim.
// Return true to allow signing with the raw keypath; false to skip.
typedef bool (*psbt_sign_ack_fn_t)(size_t input_i, const uint8_t *raw_keypath,
                                   size_t raw_keypath_len);

// Sign PSBT inputs with loaded key.
// Returns number of signatures added (0 if none).
// ack_fn: callback for requires_ack inputs; NULL treats them as denied.
size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet,
                 psbt_sign_ack_fn_t ack_fn);

// Create a trimmed PSBT containing only signatures and minimal validation data
// Returns new PSBT on success (caller must free), NULL on failure
struct wally_psbt *psbt_trim(const struct wally_psbt *psbt);

#endif // PSBT_H
