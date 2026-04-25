#include "registry.h"
#include "key.h"
#include "wallet.h"
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_descriptor.h>

static const char *TAG = "registry";

static registry_entry_t registry_entries[REGISTRY_MAX_ENTRIES];
static size_t registry_len = 0;

size_t registry_count(void) { return registry_len; }

const registry_entry_t *registry_get(size_t i) {
  if (i >= registry_len)
    return NULL;
  return &registry_entries[i];
}

const registry_entry_t *registry_find_by_id(const char *id) {
  for (size_t i = 0; i < registry_len; i++) {
    if (strncmp(registry_entries[i].id, id, REGISTRY_ID_MAX_LEN) == 0) {
      return &registry_entries[i];
    }
  }
  return NULL;
}

bool registry_remove(const char *id) {
  if (!id)
    return false;
  size_t idx = registry_len; // sentinel: "not found"
  for (size_t i = 0; i < registry_len; i++) {
    if (strncmp(registry_entries[i].id, id, REGISTRY_ID_MAX_LEN) == 0) {
      idx = i;
      break;
    }
  }
  if (idx == registry_len) {
    ESP_LOGE(TAG, "registry_remove: id '%s' not found", id);
    return false;
  }

  if (registry_entries[idx].desc != NULL) {
    wally_descriptor_free(registry_entries[idx].desc);
    registry_entries[idx].desc = NULL;
  }

  esp_err_t err = ESP_OK;
  if (registry_entries[idx].persisted) {
    err = storage_delete_descriptor(registry_entries[idx].loc,
                                    registry_entries[idx].id);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "registry_remove: storage_delete_descriptor failed (%d)",
               err);
    }
  }

  if (idx < registry_len - 1) {
    memmove(&registry_entries[idx], &registry_entries[idx + 1],
            (registry_len - idx - 1) * sizeof(registry_entry_t));
  }

  memset(&registry_entries[registry_len - 1], 0, sizeof(registry_entry_t));
  registry_len--;

  return (err == ESP_OK);
}

void registry_clear(void) {
  for (size_t i = 0; i < registry_len; i++) {
    if (registry_entries[i].desc != NULL) {
      wally_descriptor_free(registry_entries[i].desc);
    }
  }
  memset(registry_entries, 0, sizeof registry_entries);
  registry_len = 0;
}

static void registry_init_scan(storage_location_t loc) {
  char **files = NULL;
  int count = 0;
  if (storage_list_descriptors(loc, &files, &count) != ESP_OK) {
    return;
  }
  for (int i = 0; i < count; i++) {
    const char *fname = files[i];
    size_t flen = strlen(fname);
    if (flen < 4 || strcmp(fname + flen - 4, ".txt") != 0) {
      continue;
    }
    uint8_t *data = NULL;
    size_t data_len = 0;
    bool encrypted = false;
    if (storage_load_descriptor(loc, fname, &data, &data_len, &encrypted) !=
        ESP_OK) {
      continue;
    }
    char *desc_str = malloc(data_len + 1);
    if (desc_str) {
      memcpy(desc_str, data, data_len);
      desc_str[data_len] = '\0';
      char id[REGISTRY_ID_MAX_LEN];
      size_t id_len = flen - 4;
      if (id_len >= REGISTRY_ID_MAX_LEN)
        id_len = REGISTRY_ID_MAX_LEN - 1;
      memcpy(id, fname, id_len);
      id[id_len] = '\0';
      registry_add_from_string(id, desc_str, loc, false);
      free(desc_str);
    }
    free(data);
  }
  storage_free_file_list(files, count);
}

void registry_init(bool is_testnet) {
  (void)is_testnet;
  registry_clear();
  registry_init_scan(STORAGE_FLASH);
  registry_init_scan(STORAGE_SD);
  ESP_LOGI(TAG, "Registry: %zu entries loaded", registry_len);
}

/* Compute the BIP-380 checksum of a descriptor string by parsing it on
 * either network. Caller frees via wally_free_string. NULL on failure. */
static char *descriptor_checksum_alloc(const char *descriptor_str) {
  if (!descriptor_str)
    return NULL;
  uint32_t net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                     ? WALLY_NETWORK_BITCOIN_MAINNET
                     : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  if (wally_descriptor_parse(descriptor_str, NULL, net, 0, &desc) != WALLY_OK) {
    net = (net == WALLY_NETWORK_BITCOIN_MAINNET)
              ? WALLY_NETWORK_BITCOIN_TESTNET
              : WALLY_NETWORK_BITCOIN_MAINNET;
    if (wally_descriptor_parse(descriptor_str, NULL, net, 0, &desc) != WALLY_OK)
      return NULL;
  }
  char *cksum = NULL;
  int ret = wally_descriptor_get_checksum(desc, 0, &cksum);
  wally_descriptor_free(desc);
  return (ret == WALLY_OK) ? cksum : NULL;
}

static bool storage_loc_has_descriptor_checksum(storage_location_t loc,
                                                const char *target_cksum,
                                                char *out_id,
                                                size_t out_id_size) {
  char **files = NULL;
  int count = 0;
  if (storage_list_descriptors(loc, &files, &count) != ESP_OK)
    return false;

  bool found = false;
  for (int i = 0; i < count && !found; i++) {
    const char *fname = files[i];
    size_t flen = strlen(fname);
    /* Mirror registry_init_scan's filter: only plaintext .txt entries
     * have parseable descriptor strings. */
    if (flen < 4 || strcmp(fname + flen - 4, ".txt") != 0)
      continue;

    uint8_t *data = NULL;
    size_t data_len = 0;
    bool encrypted = false;
    if (storage_load_descriptor(loc, fname, &data, &data_len, &encrypted) !=
        ESP_OK)
      continue;
    if (encrypted) {
      free(data);
      continue;
    }
    char *desc_str = malloc(data_len + 1);
    if (desc_str) {
      memcpy(desc_str, data, data_len);
      desc_str[data_len] = '\0';
      char *cksum = descriptor_checksum_alloc(desc_str);
      if (cksum) {
        if (strcmp(cksum, target_cksum) == 0) {
          found = true;
          if (out_id && out_id_size > 0) {
            size_t id_len = flen - 4;
            if (id_len >= out_id_size)
              id_len = out_id_size - 1;
            memcpy(out_id, fname, id_len);
            out_id[id_len] = '\0';
          }
        }
        wally_free_string(cksum);
      }
      free(desc_str);
    }
    free(data);
  }
  storage_free_file_list(files, count);
  return found;
}

bool registry_storage_has_duplicate(const char *descriptor_str, char *out_id,
                                    size_t out_id_size) {
  if (out_id && out_id_size > 0)
    out_id[0] = '\0';
  if (!descriptor_str)
    return false;

  char *target = descriptor_checksum_alloc(descriptor_str);
  if (!target)
    return false;

  bool found = storage_loc_has_descriptor_checksum(STORAGE_FLASH, target,
                                                   out_id, out_id_size) ||
               storage_loc_has_descriptor_checksum(STORAGE_SD, target, out_id,
                                                   out_id_size);
  wally_free_string(target);
  return found;
}

registry_entry_t *registry_match_keypath(const uint8_t *keypath,
                                         size_t keypath_len, size_t *cursor) {
  if (!keypath || !cursor)
    return NULL;
  if (keypath_len < 4)
    return NULL;
  size_t payload = keypath_len - 4;
  if (payload % 4 != 0)
    return NULL;
  size_t total_depth = payload / 4;
  if (total_depth > MAX_KEYPATH_TOTAL_DEPTH)
    return NULL;

  for (size_t i = *cursor; i < registry_len; i++) {
    registry_entry_t *e = &registry_entries[i];
    if (e->origin_path_len > total_depth)
      continue;
    if (memcmp(keypath + 4, e->origin_path, e->origin_path_len * 4) != 0)
      continue;
    size_t tail_depth = total_depth - e->origin_path_len;
    if (tail_depth != MAX_KEYPATH_TAIL_DEPTH)
      continue;
    const uint8_t *tail = keypath + 4 + e->origin_path_len * 4;
    uint32_t mp, ix;
    memcpy(&mp, tail, 4);
    memcpy(&ix, tail + 4, 4);
    if (mp & BIP32_INITIAL_HARDENED_CHILD)
      continue;
    if (ix & BIP32_INITIAL_HARDENED_CHILD)
      continue;
    if (mp > 1)
      continue;
    if (e->num_paths == 1 && mp != 0)
      continue;
    *cursor = i + 1;
    return e;
  }
  return NULL;
}

// Convert an origin path string like "84'/0'/0'" to uint32_t[]
// Returns false on overflow, invalid chars, or depth > max_depth.
static bool parse_origin_path_str(const char *path, uint32_t *out,
                                  size_t *depth_out, size_t max_depth) {
  if (!path || !out || !depth_out)
    return false;
  size_t depth = 0;
  const char *p = path;
  while (*p && depth < max_depth) {
    if (*p < '0' || *p > '9')
      return false;
    uint32_t v = 0;
    bool has_digit = false;
    while (*p >= '0' && *p <= '9') {
      uint32_t d = (uint32_t)(*p - '0');
      if (v > UINT32_MAX / 10 || (v == UINT32_MAX / 10 && d > UINT32_MAX % 10))
        return false;
      v = v * 10 + d;
      p++;
      has_digit = true;
    }
    if (!has_digit)
      return false;
    if (*p == '\'' || *p == 'h') {
      if (v >= BIP32_INITIAL_HARDENED_CHILD)
        return false;
      v |= BIP32_INITIAL_HARDENED_CHILD;
      p++;
    }
    out[depth++] = v;
    if (*p == '/') {
      p++;
      if (!*p)
        return false;
    } else if (*p == '\0')
      break;
    else
      return false;
  }
  if (*p != '\0')
    return false;
  *depth_out = depth;
  return true;
}

bool registry_add_from_string(const char *id, const char *descriptor_str,
                              storage_location_t loc, bool persist) {
  if (!id || !descriptor_str)
    return false;
  if (registry_len >= REGISTRY_MAX_ENTRIES) {
    ESP_LOGE(TAG, "registry full (%d entries)", REGISTRY_MAX_ENTRIES);
    return false;
  }

  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  int ret =
      wally_descriptor_parse(descriptor_str, NULL, wally_network, 0, &desc);
  if (ret != WALLY_OK) {
    wally_network = (wally_network == WALLY_NETWORK_BITCOIN_MAINNET)
                        ? WALLY_NETWORK_BITCOIN_TESTNET
                        : WALLY_NETWORK_BITCOIN_MAINNET;
    ret = wally_descriptor_parse(descriptor_str, NULL, wally_network, 0, &desc);
  }
  if (ret != WALLY_OK) {
    ESP_LOGE(TAG, "failed to parse descriptor: %d", ret);
    return false;
  }

  unsigned char wallet_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(wallet_fp)) {
    ESP_LOGE(TAG, "key_get_fingerprint failed");
    wally_descriptor_free(desc);
    return false;
  }
  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK) {
    wally_descriptor_free(desc);
    return false;
  }
  int key_index = -1;
  for (uint32_t i = 0; i < num_keys; i++) {
    unsigned char kfp[BIP32_KEY_FINGERPRINT_LEN];
    if (wally_descriptor_get_key_origin_fingerprint(
            desc, i, kfp, BIP32_KEY_FINGERPRINT_LEN) == WALLY_OK &&
        memcmp(wallet_fp, kfp, BIP32_KEY_FINGERPRINT_LEN) == 0) {
      key_index = (int)i;
      break;
    }
  }
  if (key_index < 0) {
    ESP_LOGW(TAG, "wallet fingerprint not found in descriptor '%s'", id);
    wally_descriptor_free(desc);
    return false;
  }

  char *path_str = NULL;
  uint32_t origin_path[MAX_KEYPATH_ORIGIN_DEPTH];
  size_t origin_path_len = 0;
  if (wally_descriptor_get_key_origin_path_str(desc, (uint32_t)key_index,
                                               &path_str) != WALLY_OK ||
      !path_str) {
    ESP_LOGE(TAG, "failed to get origin path for key %d", key_index);
    wally_descriptor_free(desc);
    return false;
  }
  bool path_ok = parse_origin_path_str(path_str, origin_path, &origin_path_len,
                                       MAX_KEYPATH_ORIGIN_DEPTH);
  wally_free_string(path_str);
  if (!path_ok) {
    ESP_LOGE(TAG, "failed to parse origin path for key %d", key_index);
    wally_descriptor_free(desc);
    return false;
  }

  uint32_t num_paths = 0;
  if (wally_descriptor_get_num_paths(desc, &num_paths) != WALLY_OK) {
    wally_descriptor_free(desc);
    return false;
  }

  registry_entry_t *e = &registry_entries[registry_len];
  memset(e, 0, sizeof *e);
  strncpy(e->id, id, REGISTRY_ID_MAX_LEN - 1);
  e->loc = loc;
  e->desc = desc;
  e->my_key_index = (size_t)key_index;
  e->num_paths = (size_t)num_paths;
  e->origin_path_len = origin_path_len;
  memcpy(e->origin_path, origin_path, origin_path_len * sizeof(uint32_t));
  registry_len++;

  if (persist) {
    esp_err_t err =
        storage_save_descriptor(loc, id, (const uint8_t *)descriptor_str,
                                strlen(descriptor_str), false);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "storage_save_descriptor failed (%d), rolling back", err);
      wally_descriptor_free(desc);
      memset(&registry_entries[registry_len - 1], 0, sizeof(registry_entry_t));
      registry_len--;
      return false;
    }
    e->persisted = true;
  }

  ESP_LOGI(TAG, "added '%s' (%zu entries total)", id, registry_len);
  return true;
}
