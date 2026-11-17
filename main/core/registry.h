#ifndef REGISTRY_H
#define REGISTRY_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_descriptor.h>

#include "ss_whitelist.h"
#include "storage.h"
#include "wallet.h"

#define REGISTRY_MAX_ENTRIES 16
/* A 32-byte bipqr DESCRIPTOR_ALIAS and its NUL */
#define REGISTRY_ID_MAX_LEN 33
#define REGISTRY_LABEL_MAX_LEN 48
#define REGISTRY_MAX_OWN_KEYS 8
#define REGISTRY_CHILD_PATH_MAX_LEN 48

/* How a descriptor's scriptPubKey wraps its innermost script. */
typedef enum {
  REGISTRY_WRAP_NONE,   /* the scriptPubKey itself: pkh(), wpkh(), tr() */
  REGISTRY_WRAP_SH,     /* sh(X): P2SH of the redeem script */
  REGISTRY_WRAP_WSH,    /* wsh(X): P2WSH of the witness script */
  REGISTRY_WRAP_SH_WSH, /* sh(wsh(X)): P2SH of the P2WSH of the witness */
} registry_wrapper_t;

/* The wrapper, from the descriptor's top level. */
KERN_WARN_UNUSED_RESULT registry_wrapper_t
registry_descriptor_wrapper(const struct wally_descriptor *desc);
/* The script depth wally_descriptor_to_script needs for the innermost script
 * under `wrapper`: 0 for none, 1 for sh() or wsh(), 2 for sh(wsh()). */
KERN_WARN_UNUSED_RESULT uint32_t
registry_wrapper_depth(registry_wrapper_t wrapper);

/* A key expression carrying the wallet's fingerprint. */
typedef struct {
  size_t key_index;
  uint32_t origin_path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t origin_path_len;
  /* The path written after the key, wildcard included; empty for a raw
   * key. */
  char child_path[REGISTRY_CHILD_PATH_MAX_LEN];
} registry_own_key_t;
#define REGISTRY_FILENAME_MAX_LEN 48
/* Hex digits of the file id a registration is stored under */
#define REGISTRY_ALIAS_FILE_ID_LEN 16

typedef struct {
  char id[REGISTRY_ID_MAX_LEN];
  char label[REGISTRY_LABEL_MAX_LEN];
  storage_location_t loc;
  struct wally_descriptor *desc;
  /* First own key: an xpub, MAX_KEYPATH_ORIGIN_DEPTH steps deep at most. */
  size_t my_key_index;
  size_t num_paths;
  registry_wrapper_t wrapper;
  uint32_t origin_path[MAX_KEYPATH_ORIGIN_DEPTH];
  size_t origin_path_len;
  /* Every own key, the first included, up to REGISTRY_MAX_OWN_KEYS. */
  registry_own_key_t own_keys[REGISTRY_MAX_OWN_KEYS];
  size_t num_own_keys;
  /* What the descriptor pays, however it is written; see
   * registry_session_has_duplicate_scripts. */
  uint8_t script_id[32];
  bool has_script_id;
  bool persisted;
  /* The backup file of a persisted entry */
  char filename[REGISTRY_FILENAME_MAX_LEN];
  /* Named by the current request: matched before the other entries */
  bool preferred;
} registry_entry_t;

/* Where registry_match_keypath resumes; zero-initialise before the first
 * call. */
typedef struct {
  size_t entry;
  uint32_t multi_index;
} registry_match_cursor_t;

KERN_WARN_UNUSED_RESULT size_t registry_count(void);
KERN_WARN_UNUSED_RESULT const registry_entry_t *registry_get(size_t i);
KERN_WARN_UNUSED_RESULT const registry_entry_t *
registry_find_by_id(const char *id);
KERN_WARN_UNUSED_RESULT bool registry_set_label(const char *id,
                                                const char *label);
/* Removes only the session entry; a registered backup stays on flash. */
KERN_WARN_UNUSED_RESULT bool registry_remove_at(size_t index);
/* Deletes this entry's registered backup from flash and removes it from the
 * session. Failure leaves the entry intact. */
KERN_WARN_UNUSED_RESULT bool registry_deregister_at(size_t index);
KERN_WARN_UNUSED_RESULT bool
registry_add_from_string(const char *id, const char *descriptor_str,
                         storage_location_t loc, bool persist);
/* Same for a descriptor descriptor_validate_keyed_parsed accepted: takes
 * ownership of `desc`, parsed for the wallet's network, whose first own key
 * (an xpub with a 1 to MAX_KEYPATH_ORIGIN_DEPTH step origin) is `key_index`,
 * or its first participant carrying our fingerprint for a musig() key.
 * Frees `desc` on failure. */
KERN_WARN_UNUSED_RESULT bool
registry_add_parsed(const char *id, struct wally_descriptor *desc,
                    size_t key_index, storage_location_t loc, bool persist);
/* registry_add_parsed, persisting, unless an entry already holds `id`: then
 * that entry, when it pays the same scripts as `desc`, is persisted if it is
 * not yet. Takes ownership of `desc` either way. */
KERN_WARN_UNUSED_RESULT bool
registry_persist_or_add_parsed(const char *id, struct wally_descriptor *desc,
                               size_t key_index, storage_location_t loc);

/* Register a session entry: writes its BIP138 backup, `name` included, to a
 * flash file named after `name`, then renames and labels the entry.
 * Registered descriptors load automatically whenever a key of theirs is
 * loaded. Fails when no such session entry exists, the name is taken on
 * flash, or the backup cannot be written; the entry is left untouched on
 * failure. */
KERN_WARN_UNUSED_RESULT bool registry_persist(const char *id, const char *name);

/* True when a registration on flash already uses `name`, loaded or not. */
KERN_WARN_UNUSED_RESULT bool registry_name_registered(const char *name);

/* Silent payment account registrations: aliases naming the loaded seed's
 * BIP-352 spend key on the wallet network, with our scan key or the one not
 * ours it was registered with, always stored on flash and loaded by
 * registry_init. An alias names a descriptor or an account, not both. */
KERN_WARN_UNUSED_RESULT bool registry_sp_alias_exists(const char *alias);
/* `scan_key` is the 32-byte scan key of an account whose scan key is not
 * ours, NULL for ours. */
KERN_WARN_UNUSED_RESULT bool
registry_add_sp_alias(const char *alias, const unsigned char *scan_key);
/* The scan key `alias` was registered with when not ours, else NULL */
KERN_WARN_UNUSED_RESULT const unsigned char *
registry_sp_alias_scan_key(const char *alias);
KERN_WARN_UNUSED_RESULT size_t registry_sp_alias_count(void);
KERN_WARN_UNUSED_RESULT const char *registry_sp_alias_get(size_t i);
/* Deletes the alias's record from flash and forgets it. Failure leaves it
 * intact. */
KERN_WARN_UNUSED_RESULT bool registry_sp_alias_deregister_at(size_t i);
/* Removes the registration `alias` names, and only it: its descriptor entry
 * with its backup on flash when it has one, or its silent payment account
 * record. False for an unknown alias; failure leaves the registration
 * intact. */
KERN_WARN_UNUSED_RESULT bool registry_unregister(const char *alias);
/* Names a scan key not ours that the current request pairs with our spend
 * key, until registry_sp_clear_named_scan_keys(). False when there is no room
 * left. */
KERN_WARN_UNUSED_RESULT bool
registry_sp_name_scan_key(const unsigned char *scan_key);
void registry_sp_clear_named_scan_keys(void);
/* The scan keys not ours of our spend key's accounts: those registered, then
 * those the current request names. NULL past the last. */
KERN_WARN_UNUSED_RESULT const unsigned char *
registry_sp_scan_key_get(size_t pos);

/* True when `entry` pays the same scripts as `descriptor_str` (see
 * registry_session_has_duplicate_scripts). */
KERN_WARN_UNUSED_RESULT bool
registry_entry_is_descriptor(const registry_entry_t *entry,
                             const char *descriptor_str);

/* Watch-only (keyless) session add: registers a descriptor for address viewing
 * without requiring the loaded key's fingerprint to be present. `my_key_index`
 * is set to SIZE_MAX and the origin path is left empty. Never persisted. */
KERN_WARN_UNUSED_RESULT bool registry_add_watch_only(const char *id,
                                                     const char *descriptor_str,
                                                     wallet_network_t network);

/* Look up whether a descriptor paying the same scripts as `descriptor_str` is
 * already loaded in the in-memory session registry, and write its session id
 * to `out_id` if non-NULL. */
KERN_WARN_UNUSED_RESULT bool
registry_session_has_duplicate(const char *descriptor_str, char *out_id,
                               size_t out_id_size);
/* Same for a parsed descriptor. Entries match when they have the same number
 * of multipath groups and the same scriptPubKey at child 0 of each, so an
 * uppercase fingerprint, sortedmulti keys in another order or a key written
 * with or without its origin are one descriptor. */
KERN_WARN_UNUSED_RESULT bool
registry_session_has_duplicate_scripts(const struct wally_descriptor *desc,
                                       char *out_id, size_t out_id_size);

void registry_clear(void);
/* Clears the session and registers every flash backup the loaded key opens,
 * and the silent payment aliases of the loaded seed. */
void registry_init(bool is_testnet);
/* Backups registered on this device that the last registry_init skipped
 * because they no longer pass keyed validation (other-network ones aside). */
KERN_WARN_UNUSED_RESULT size_t registry_rejected_count(void);
/* Marks the entry `id` names as preferred, so a script several entries
 * generate is claimed by the entry a request names. No-op for an unknown id. */
void registry_prefer(const char *id);
void registry_clear_preferred(void);
/* The entry at `pos` in match order: the preferred entries, then the others,
 * both in registry order. NULL past the last entry. */
KERN_WARN_UNUSED_RESULT const registry_entry_t *
registry_match_order_get(size_t pos);
/* Next (entry, multipath group), entries in match order, under which
 * `keypath` (fingerprint, then path) is one of the entry's own keys: some own
 * key's origin followed by its child path expanded at that group and some
 * child number. Writes the group as `multi_index` and the wildcard's value as
 * `child_num`. Only the path is compared; the caller proves ownership by
 * regenerating the script. */
KERN_WARN_UNUSED_RESULT registry_entry_t *
registry_match_keypath(const uint8_t *keypath, size_t keypath_len,
                       registry_match_cursor_t *cursor, uint32_t *multi_index,
                       uint32_t *child_num);

/* The full path `key` takes in the script at (multi_index, child_num): its
 * origin, then its child path expanded. `path_out` holds
 * MAX_KEYPATH_TOTAL_DEPTH components. */
KERN_WARN_UNUSED_RESULT bool
registry_own_key_path(const registry_own_key_t *key, uint32_t multi_index,
                      uint32_t child_num, uint32_t *path_out, size_t *len_out);

#endif // REGISTRY_H
