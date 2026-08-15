#ifndef PSBT_H
#define PSBT_H

#include "../utils/attributes.h"
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
      const registry_entry_t *entry;
      uint32_t multi_index;
      uint32_t child_num;
    } registry;
  };
  uint32_t derived_path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t derived_path_len;
} claim_t;

typedef enum {
  /* fp doesn't match our master key (or no derivation info present) */
  PSBT_OWNERSHIP_EXTERNAL,
  /* fp + derive(path) reproduces the spk + path matches a whitelist or
   * registry claim — safe to sign without further opt-in */
  PSBT_OWNERSHIP_OWNED_SAFE,
  /* fp + derive(path) reproduces the spk but path is non-standard;
   * gated by `permissive_signing` setting */
  PSBT_OWNERSHIP_OWNED_UNSAFE,
  /* fp matches but derivation could not be verified (no path supplied,
   * derived spk differs from the spk in the PSBT, or derivation failed);
   * gated by `expected_owned_signing` setting (harness against
   * software-wallet derivation bugs and UTXO-swap attacks) */
  PSBT_OWNERSHIP_EXPECTED_OWNED,
} psbt_ownership_t;

typedef struct {
  psbt_ownership_t ownership;
  claim_t claim;
  uint8_t raw_keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
  size_t raw_keypath_len;
} input_ownership_t;

typedef struct {
  psbt_ownership_t ownership;
  claim_t source;
  uint8_t raw_keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
  size_t raw_keypath_len;
} output_ownership_t;

input_ownership_t psbt_classify_input(const struct wally_psbt *psbt, size_t i,
                                      bool is_testnet);

output_ownership_t psbt_classify_output(const struct wally_psbt *psbt, size_t i,
                                        bool is_testnet);

KERN_WARN_UNUSED_RESULT bool
psbt_input_utxo_script(const struct wally_psbt *psbt, size_t input_i,
                       unsigned char *out, size_t out_cap, size_t *out_len);

// Format a raw keypath (4 fp bytes + N little-endian u32 components) into
// the "m/44'/0'/100'/0/0" form. Returns false if the buffer is too small or
// the input is malformed.
KERN_WARN_UNUSED_RESULT bool
psbt_format_keypath(const unsigned char *raw_keypath, size_t raw_keypath_len,
                    char *buf, size_t buf_size);

// How much an input's amount can be trusted. Only PROVEN ties the value to
// the prevout txid the transaction actually spends: the full previous
// transaction is present and hashes to it. Everything else is the PSBT's word,
// and since the BIP143 sighash commits only to the input's own amount, a
// coordinator can understate one input per signing session and harvest a valid
// signature for the other — two sessions reassemble a transaction whose real
// fee was never displayed.
typedef enum {
  PSBT_AMOUNT_PROVEN,   /* non_witness_utxo present and hashes to the prevout */
  PSBT_AMOUNT_ASSERTED, /* witness_utxo only — trusted, not verified */
  PSBT_AMOUNT_INVALID,  /* utxo data contradicts the prevout or itself */
  PSBT_AMOUNT_MISSING,  /* no utxo data at all */
} psbt_amount_status_t;

typedef struct {
  psbt_amount_status_t status;
  uint64_t value;
} psbt_input_amount_t;

typedef struct {
  size_t num_inputs;
  size_t proven;
  size_t asserted;
  size_t invalid;
  size_t missing;
  /* Index of the first input in each non-proven category, or num_inputs when
   * that category is empty. Used to name a concrete input in the warning. */
  size_t first_unproven;
  size_t first_invalid;
} psbt_amount_audit_t;

// Resolve an input's amount and how well it is backed. Prefers the value from
// a verified non_witness_utxo over a bare witness_utxo assertion.
psbt_input_amount_t psbt_get_input_amount(const struct wally_psbt *psbt,
                                          size_t index);

// Same, across every input.
void psbt_audit_input_amounts(const struct wally_psbt *psbt,
                              psbt_amount_audit_t *out);

// True when every input's amount is backed by its previous transaction, i.e.
// the displayed fee is arithmetic on verified numbers.
static inline bool psbt_amounts_are_proven(const psbt_amount_audit_t *audit) {
  return audit->num_inputs > 0 && audit->proven == audit->num_inputs;
}

// Get input value in satoshis
uint64_t psbt_get_input_value(const struct wally_psbt *psbt, size_t index);

// Sighash flags the review screen can honestly describe. SIGHASH_ALL (and the
// taproot SIGHASH_DEFAULT, which is 0 and also the "unset" encoding) commit to
// every input and output, so what was displayed is what gets mined. Under
// NONE, SINGLE or ANYONECANPAY the signature survives edits to the parts it
// does not cover, and the outputs and fee on screen mean nothing.
typedef struct {
  size_t num_inputs;
  size_t unsupported;
  size_t first_unsupported;
  uint32_t first_sighash;
} psbt_sighash_audit_t;

KERN_WARN_UNUSED_RESULT bool psbt_sighash_is_supported(uint32_t sighash);

// Short name for a sighash byte ("NONE", "SINGLE|ANYONECANPAY", ...).
KERN_WARN_UNUSED_RESULT const char *psbt_sighash_name(uint32_t sighash);

void psbt_audit_sighash(const struct wally_psbt *psbt,
                        psbt_sighash_audit_t *out);

// Fee as a whole-number percentage of the total input value; 0 when the total
// is 0. What counts as too high is the review screen's call, not this layer's.
KERN_WARN_UNUSED_RESULT uint32_t psbt_fee_percent(uint64_t fee,
                                                  uint64_t total_input);

// Detect network from derivation paths (returns true if testnet)
KERN_WARN_UNUSED_RESULT bool psbt_detect_network(const struct wally_psbt *psbt);

// Detect account from derivation paths
// Returns the account number from PSBT derivation paths
// Returns -1 if no derivation info found or inconsistent accounts
KERN_WARN_UNUSED_RESULT int32_t
psbt_detect_account(const struct wally_psbt *psbt);

// Convert scriptPubKey to address string (caller must free)
KERN_WARN_UNUSED_RESULT char *
psbt_scriptpubkey_to_address(const unsigned char *script, size_t script_len,
                             bool is_testnet);

// Per-call signing policy. Mirrors the user-facing settings toggles
// (Settings > Wallet) and is enforced inside `psbt_sign()` per-input,
// so a forgotten UI gate cannot leak signatures on UNSAFE/EXPECTED_OWNED
// inputs. EXTERNAL inputs are always skipped.
typedef struct {
  bool allow_unsafe;         // OWNED_UNSAFE — non-standard derivation path
  bool allow_expected_owned; // EXPECTED_OWNED — fp matches but derive doesn't
} psbt_sign_policy_t;

// Outcome of a signing pass. `attempted` counts inputs the policy cleared for
// signing; `signed_ok` counts those that actually gained a signature. A gap
// between the two means the PSBT carried inputs we recognise as ours but could
// not sign (bad utxo data, unsupported script) — the caller must surface it,
// since silently exporting a partly-signed PSBT is exactly what an attacker
// harvesting one signature per session wants.
//
// `blocked` counts inputs the policy refused that libwally signed anyway
// because they name a key used elsewhere in the transaction, and whose
// signature was therefore discarded. A PSBT arranged that way is not something
// an honest coordinator produces.
typedef struct {
  size_t attempted;
  size_t signed_ok;
  size_t blocked;
} psbt_sign_result_t;

// Sign PSBT inputs with loaded key.
// `policy` gates which non-SAFE ownership categories may be signed; see
// `psbt_sign_policy_t`. Callers must still check `partial_signing` upstream
// (it gates whether to proceed at all when external inputs exist), since
// that's a UX decision rather than a per-input one.
// `result` may be NULL. Returns number of signatures added (0 if none).
KERN_WARN_UNUSED_RESULT size_t psbt_sign(struct wally_psbt *psbt,
                                         bool is_testnet,
                                         psbt_sign_policy_t policy,
                                         psbt_sign_result_t *result);

// Create a trimmed PSBT containing only signatures and minimal validation data
// Returns new PSBT on success (caller must free), NULL on failure
KERN_WARN_UNUSED_RESULT struct wally_psbt *
psbt_trim(const struct wally_psbt *psbt);

#endif // PSBT_H
