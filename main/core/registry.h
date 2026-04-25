#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_descriptor.h>

#include "ss_whitelist.h"
#include "storage.h"

#define REGISTRY_MAX_ENTRIES 16
#define REGISTRY_ID_MAX_LEN 32

typedef struct {
  char id[REGISTRY_ID_MAX_LEN];
  storage_location_t loc;
  struct wally_descriptor *desc;
  size_t my_key_index;
  size_t num_paths;
  uint32_t origin_path[MAX_KEYPATH_ORIGIN_DEPTH];
  size_t origin_path_len;
  bool persisted;
} registry_entry_t;

size_t registry_count(void);
const registry_entry_t *registry_get(size_t i);
const registry_entry_t *registry_find_by_id(const char *id);
bool registry_remove(const char *id);
bool registry_add_from_string(const char *id, const char *descriptor_str,
                              storage_location_t loc, bool persist);

/* Look up whether `descriptor_str` is already persisted on disk. Walks
 * STORAGE_FLASH + STORAGE_SD via storage_list_descriptors, parses each
 * stored descriptor, and compares BIP-380 checksums. Returns true if a
 * match is found; on match writes the existing entry's id (sanitized
 * filename minus the ".txt" extension) to `out_id` if non-NULL.
 * `out_id_size` is the buffer capacity. Storage is the source of
 * truth — the in-memory registry is just a cache populated at boot. */
bool registry_storage_has_duplicate(const char *descriptor_str, char *out_id,
                                    size_t out_id_size);
void registry_clear(void);
void registry_init(bool is_testnet);
registry_entry_t *registry_match_keypath(const uint8_t *keypath,
                                         size_t keypath_len, size_t *cursor);

#endif // REGISTRY_H
