#ifndef PSBT_H
#define PSBT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_psbt.h>

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

// Verify output belongs to our wallet and extract derivation info
bool psbt_get_output_derivation(const struct wally_psbt *psbt,
                                size_t output_index, bool is_testnet,
                                bool *is_change, uint32_t *address_index);

// Sign PSBT inputs with loaded key
// Returns number of signatures added (0 if none)
size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet);

// Create a trimmed PSBT containing only signatures and minimal validation data
// Returns new PSBT on success (caller must free), NULL on failure
struct wally_psbt *psbt_trim(const struct wally_psbt *psbt);

#endif // PSBT_H
