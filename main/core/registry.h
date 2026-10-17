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
#define REGISTRY_ID_MAX_LEN 32
#define REGISTRY_LABEL_MAX_LEN 48
#define REGISTRY_MAX_OWN_KEYS 8
#define REGISTRY_CHILD_PATH_MAX_LEN 48

/* A key expression carrying the wallet's fingerprint. */
typedef struct {
  size_t key_index;
  uint32_t origin_path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t origin_path_len;
  /* The path written after the key, wildcard included; empty for a raw
   * key. */
  char child_path[REGISTRY_CHILD_PATH_MAX_LEN];
} registry_own_key_t;

typedef struct {
  char id[REGISTRY_ID_MAX_LEN];
  char label[REGISTRY_LABEL_MAX_LEN];
  storage_location_t loc;
  struct wally_descriptor *desc;
  /* First own key: an xpub, MAX_KEYPATH_ORIGIN_DEPTH steps deep at most. */
  size_t my_key_index;
  size_t num_paths;
  uint32_t origin_path[MAX_KEYPATH_ORIGIN_DEPTH];
  size_t origin_path_len;
  /* Every own key, the first included, up to REGISTRY_MAX_OWN_KEYS. */
  registry_own_key_t own_keys[REGISTRY_MAX_OWN_KEYS];
  size_t num_own_keys;
  bool persisted;
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
 * (an xpub with a 1 to MAX_KEYPATH_ORIGIN_DEPTH step origin) is `key_index`.
 * Frees `desc` on failure. */
KERN_WARN_UNUSED_RESULT bool
registry_add_parsed(const char *id, struct wally_descriptor *desc,
                    size_t key_index, storage_location_t loc, bool persist);

/* Register a session entry: writes its BIP138 backup to flash under `name`,
 * then renames and labels the entry. Registered descriptors load automatically
 * whenever a key of theirs is loaded. Fails when no such session entry
 * exists, the name is taken on flash, or the backup cannot be written; the
 * entry is left untouched on failure. */
KERN_WARN_UNUSED_RESULT bool registry_persist(const char *id, const char *name);

/* Watch-only (keyless) session add: registers a descriptor for address viewing
 * without requiring the loaded key's fingerprint to be present. `my_key_index`
 * is set to SIZE_MAX and the origin path is left empty. Never persisted. */
KERN_WARN_UNUSED_RESULT bool registry_add_watch_only(const char *id,
                                                     const char *descriptor_str,
                                                     wallet_network_t network);

/* Look up whether `descriptor_str` is already loaded in the in-memory
 * session registry. Compares h-normalized BIP-380 checksums and writes the
 * matching session id to `out_id` if non-NULL. */
KERN_WARN_UNUSED_RESULT bool
registry_session_has_duplicate(const char *descriptor_str, char *out_id,
                               size_t out_id_size);
/* Same lookup when the caller already has the h-normalized BIP-380 checksum. */
KERN_WARN_UNUSED_RESULT bool
registry_session_has_duplicate_checksum(const char checksum[9], char *out_id,
                                        size_t out_id_size);

void registry_clear(void);
/* Clears the session and registers every flash backup the loaded key opens. */
void registry_init(bool is_testnet);
/* Backups registered on this device that the last registry_init skipped
 * because they no longer pass keyed validation (other-network ones aside). */
KERN_WARN_UNUSED_RESULT size_t registry_rejected_count(void);
/* Next (entry, multipath group) under which `keypath` (fingerprint, then
 * path) is one of the entry's own keys: some own key's origin followed by its
 * child path expanded at that group and some child number. Writes the group
 * as `multi_index` and the wildcard's value as `child_num`. Only the path is
 * compared; the caller proves ownership by regenerating the script. */
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
