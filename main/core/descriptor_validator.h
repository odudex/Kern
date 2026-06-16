#ifndef DESCRIPTOR_VALIDATOR_H
#define DESCRIPTOR_VALIDATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "miniscript_policy.h"
#include "storage.h"
#include "wallet.h"

typedef enum {
  VALIDATION_SUCCESS = 0,
  VALIDATION_FINGERPRINT_NOT_FOUND,
  VALIDATION_USER_DECLINED,
  VALIDATION_XPUB_MISMATCH,
  VALIDATION_PARSE_ERROR,
  VALIDATION_INTERNAL_ERROR,
  /* Descriptor parses on the other network only (wallet mainnet vs
   * descriptor tpub, or vice versa). */
  VALIDATION_NETWORK_MISMATCH,
  /* Same descriptor (h-normalized BIP-380 checksum match) is already loaded in
   * the current session. Use descriptor_validator_get_duplicate_id() to fetch
   * the name of the existing entry. */
  VALIDATION_DUPLICATE,
  /* Descriptor uses uppercase 'H' as the hardened-derivation marker. Only
   * '\'' and 'h' are accepted; coordinators emitting 'H' must be reconfigured.
   */
  VALIDATION_INVALID_HARDENED_NOTATION,
  /* Descriptor contains miniscript that is not wrapped in a plain wsh().
   * Only segwit v0 wsh(miniscript) is supported (no tapminiscript, no
   * sh(wsh()) wrapping, no bare miniscript). */
  VALIDATION_UNSUPPORTED_MINISCRIPT,
  /* Descriptor parses but libwally cannot generate its scripts: more than
   * 15 multi()/sortedmulti() keys, or an sh()/wsh() inner script over
   * PSBT_MAX_INNER_SCRIPT_LEN (520) bytes. Without this check the descriptor
   * would register but fail at address derivation and signing. */
  VALIDATION_UNSUPPORTED_SCRIPT,
} descriptor_validation_result_t;

typedef void (*validation_complete_cb)(descriptor_validation_result_t result,
                                       void *user_data);

/* UI-agnostic warning-confirmation callback: render `message` as a danger-style
 * confirmation (e.g. purpose/script binding mismatch) and call `proceed` with
 * the user's choice. NULL means auto-decline. */
typedef void (*validation_confirm_cb)(const char *message,
                                      void (*proceed)(bool confirmed,
                                                      void *user_data));

/* Descriptor info for confirmation display. One letter ID per key; the
 * script-size validation (VALIDATION_UNSUPPORTED_SCRIPT) guarantees loadable
 * descriptors stay well under this cap. */
#define DESCRIPTOR_INFO_MAX_KEYS MINISCRIPT_POLICY_MAX_KEYS
typedef struct {
  bool is_multisig;
  bool is_miniscript;
  uint32_t threshold;
  uint32_t num_keys;
  struct {
    char fingerprint_hex[9];
    char xpub[113];
    char derivation[64];
  } keys[DESCRIPTOR_INFO_MAX_KEYS];
  /* Miniscript only: descriptor with key expressions replaced by their
   * letter IDs (A, B, ...). Empty if unavailable. */
  char policy[512];
} descriptor_info_t;

// UI-agnostic info confirmation callback: show descriptor info, call proceed()
// with result.
typedef void (*validation_info_confirm_cb)(const descriptor_info_t *info,
                                           void (*proceed)(bool confirmed,
                                                           void *user_data));

// Future persistent-registration hook, used to collect the registry ID and
// storage location once descriptor registration is re-enabled with encrypted
// descriptor backups.
typedef void (*validation_id_loc_cb)(void (*proceed)(const char *id,
                                                     storage_location_t loc,
                                                     void *user_data),
                                     void *user_data);

// Validate descriptor against wallet key and load if valid.
// Checks fingerprint, derivation path attributes, and xpub match.
// On purpose/script binding mismatch, uses confirm_cb to prompt the user
// (NULL = auto-decline).
// After xpub match, uses info_confirm_cb to show descriptor info
// (NULL = auto-confirm).
// Calls callback with result (may be async if user confirmation needed).
void descriptor_validate_and_load(const char *descriptor_str,
                                  validation_complete_cb callback,
                                  validation_confirm_cb confirm_cb,
                                  validation_info_confirm_cb info_confirm_cb,
                                  validation_id_loc_cb id_loc_cb,
                                  void *user_data);

/* Infer a descriptor's network by trying to parse it as mainnet, then testnet.
 * Writes the network to *network_out and returns true on success; returns false
 * if the descriptor parses on neither (xpub keys parse only on mainnet, tpub
 * only on testnet, so the result is unambiguous for extended-key descriptors).
 */
bool descriptor_infer_network(const char *descriptor_str,
                              wallet_network_t *network_out);

/* Watch-only (keyless) variant of descriptor_validate_and_load: validates and
 * loads a descriptor for address viewing without a loaded master key. Skips the
 * key precondition, fingerprint match, and xpub verification; otherwise reuses
 * the same parse/script checks, the same "Load?" info dialog (info_confirm_cb),
 * and session dedup. The caller must have set the watch-only network first (via
 * wallet_set_watch_only). On confirm the descriptor is registered watch-only.
 */
void descriptor_validate_and_load_watch_only(
    const char *descriptor_str, wallet_network_t network,
    validation_complete_cb callback, validation_info_confirm_cb info_confirm_cb,
    void *user_data);

/* When a VALIDATION_DUPLICATE result has just been delivered, copy the ID of
 * the existing registry entry into `out` and return true. Returns false if no
 * duplicate ID is pending (e.g. result was not DUPLICATE, or the buffer is
 * too small). The pending ID is reset on the next descriptor_validate_and_load
 * call. */
bool descriptor_validator_get_duplicate_id(char *out, size_t out_len);

#endif // DESCRIPTOR_VALIDATOR_H
