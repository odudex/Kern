#include "registry.h"
#include "bip138_crypto.h"
#include "bip32_path.h"
#include "descriptor_checksum.h"
#include "key.h"
#include "wallet.h"
#include <bip138.h>
#include <esp_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>

static const char *TAG = "registry";

static registry_entry_t registry_entries[REGISTRY_MAX_ENTRIES];
static size_t registry_len = 0;

#define REGISTRY_AUTOLOAD_DESCRIPTORS 1

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

bool registry_set_label(const char *id, const char *label) {
  if (!id || !label)
    return false;
  for (size_t i = 0; i < registry_len; i++) {
    if (strncmp(registry_entries[i].id, id, REGISTRY_ID_MAX_LEN) == 0) {
      strncpy(registry_entries[i].label, label, REGISTRY_LABEL_MAX_LEN - 1);
      registry_entries[i].label[REGISTRY_LABEL_MAX_LEN - 1] = '\0';
      return true;
    }
  }
  return false;
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
    char sanitized[STORAGE_MAX_SANITIZED_ID_LEN + 1];
    storage_sanitize_id(registry_entries[idx].id, sanitized, sizeof(sanitized));
    char filename[STORAGE_MAX_SANITIZED_ID_LEN + 8];
    if (registry_entries[idx].loc == STORAGE_FLASH)
      snprintf(filename, sizeof(filename), "%s%s%s", STORAGE_DESCRIPTOR_PREFIX,
               sanitized, STORAGE_DESCRIPTOR_EXT_KEF);
    else
      snprintf(filename, sizeof(filename), "%s%s", sanitized,
               STORAGE_DESCRIPTOR_EXT_KEF);
    err = storage_delete_descriptor(registry_entries[idx].loc, filename);
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

static bool registry_bip138_key(uint8_t out[EC_XONLY_PUBLIC_KEY_LEN]) {
  char *xpub = NULL;
  struct ext_key *key = NULL;
  bool ok = false;
  if (key_get_master_xpub(&xpub) && xpub &&
      bip32_key_from_base58_alloc(xpub, &key) == WALLY_OK && key) {
    memcpy(out, key->pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN);
    ok = wally_ec_xonly_public_key_verify(out, EC_XONLY_PUBLIC_KEY_LEN) ==
         WALLY_OK;
  }
  if (key)
    bip32_key_free(key);
  if (xpub)
    wally_free_string(xpub);
  return ok;
}

static bool registry_save_bip138(const char *id, const char *descriptor_str,
                                 storage_location_t loc) {
  uint8_t key[EC_XONLY_PUBLIC_KEY_LEN];
  if (!registry_bip138_key(key))
    return false;

  bip138_buf encrypted = {0};
  const char *err = NULL;
  int32_t ret = bip138_encrypt(kern_bip138_crypto_vtable(), key, 1, NULL, 0,
                               BIP138_CONTENT_BIP380, 0, NULL, 0,
                               (const uint8_t *)descriptor_str,
                               strlen(descriptor_str), BIP138_PADDING_NONE,
                               &encrypted, &err);
  if (ret != BIP138_OK) {
    ESP_LOGE(TAG, "bip138_encrypt failed: %s", err ? err : "unknown");
    return false;
  }
  esp_err_t save_err =
      storage_save_descriptor(loc, id, encrypted.ptr, encrypted.len, true);
  bip138_buf_free(encrypted);
  if (save_err != ESP_OK) {
    ESP_LOGE(TAG, "storage_save_descriptor(.kef) failed (%d)", save_err);
    return false;
  }
  return true;
}

static bool registry_decrypt_bip138(const uint8_t *encrypted, size_t encrypted_len,
                                    char **descriptor_out) {
  *descriptor_out = NULL;
  uint8_t key[EC_XONLY_PUBLIC_KEY_LEN];
  if (!registry_bip138_key(key))
    return false;

  bip138_decrypt_result *result = NULL;
  const char *err = NULL;
  int32_t ret = bip138_decrypt(kern_bip138_crypto_vtable(), key, encrypted,
                               encrypted_len, &result, &err);
  if (ret != BIP138_OK) {
    ESP_LOGW(TAG, "bip138_decrypt failed: %s", err ? err : "unknown");
    return false;
  }

  bool ok = false;
  size_t items = bip138_decrypt_len(result);
  for (size_t i = 0; i < items; i++) {
    bip138_item item = {0};
    if (bip138_decrypt_item(result, i, &item, &err) != BIP138_OK)
      continue;
    if (item.content_type != BIP138_CONTENT_BIP380 || item.plaintext.len == 0)
      continue;
    char *descriptor = malloc(item.plaintext.len + 1);
    if (!descriptor)
      break;
    memcpy(descriptor, item.plaintext.ptr, item.plaintext.len);
    descriptor[item.plaintext.len] = '\0';
    *descriptor_out = descriptor;
    ok = true;
    break;
  }
  bip138_decrypt_free(result);
  return ok;
}

static bool descriptor_id_from_filename(storage_location_t loc, const char *fname,
                                        const char *ext, char *out,
                                        size_t out_size) {
  if (!fname || !ext || !out || out_size == 0)
    return false;
  size_t flen = strlen(fname);
  size_t elen = strlen(ext);
  if (flen <= elen || strcmp(fname + flen - elen, ext) != 0)
    return false;
  const char *start = fname;
  if (loc == STORAGE_FLASH) {
    size_t prefix_len = strlen(STORAGE_DESCRIPTOR_PREFIX);
    if (flen <= prefix_len + elen ||
        strncmp(fname, STORAGE_DESCRIPTOR_PREFIX, prefix_len) != 0)
      return false;
    start += prefix_len;
  }
  size_t id_len = flen - (size_t)(start - fname) - elen;
  if (id_len >= out_size)
    id_len = out_size - 1;
  memcpy(out, start, id_len);
  out[id_len] = '\0';
  return true;
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
    bool is_kef = flen > strlen(STORAGE_DESCRIPTOR_EXT_KEF) &&
                  strcmp(fname + flen - strlen(STORAGE_DESCRIPTOR_EXT_KEF),
                         STORAGE_DESCRIPTOR_EXT_KEF) == 0;
    bool is_txt = flen > strlen(STORAGE_DESCRIPTOR_EXT_TXT) &&
                  strcmp(fname + flen - strlen(STORAGE_DESCRIPTOR_EXT_TXT),
                         STORAGE_DESCRIPTOR_EXT_TXT) == 0;
    if (!is_kef && !is_txt) {
      continue;
    }
    uint8_t *data = NULL;
    size_t data_len = 0;
    bool encrypted = false;
    if (storage_load_descriptor(loc, fname, &data, &data_len, &encrypted) !=
        ESP_OK) {
      continue;
    }
    char *desc_str = NULL;
    if (encrypted) {
      registry_decrypt_bip138(data, data_len, &desc_str);
    } else {
      desc_str = malloc(data_len + 1);
      if (desc_str) {
        memcpy(desc_str, data, data_len);
        desc_str[data_len] = '\0';
      }
    }
    if (desc_str) {
      char id[REGISTRY_ID_MAX_LEN];
      if (!descriptor_id_from_filename(
              loc, fname,
              encrypted ? STORAGE_DESCRIPTOR_EXT_KEF : STORAGE_DESCRIPTOR_EXT_TXT,
              id, sizeof(id))) {
        free(desc_str);
        free(data);
        continue;
      }
      if (!registry_add_from_string(id, desc_str, loc, false))
        ESP_LOGW(TAG, "Skipping stored descriptor '%s': failed to register",
                 id);
      free(desc_str);
    }
    free(data);
  }
  storage_free_file_list(files, count);
}

void registry_init(bool is_testnet) {
  (void)is_testnet;
  registry_clear();
  if (REGISTRY_AUTOLOAD_DESCRIPTORS) {
    registry_init_scan(STORAGE_FLASH);
    registry_init_scan(STORAGE_SD);
  }
  ESP_LOGI(TAG, "Registry: %zu entries loaded", registry_len);
}

/* Compute the h-normalized BIP-380 checksum of a descriptor string by parsing
 * it on either network. Caller frees via free. NULL on failure. */
static char *descriptor_checksum_alloc(const char *descriptor_str) {
  if (!descriptor_str)
    return NULL;
  uint32_t net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                     ? WALLY_NETWORK_BITCOIN_MAINNET
                     : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  if (wallet_descriptor_parse(descriptor_str, NULL, net, &desc) != WALLY_OK) {
    net = (net == WALLY_NETWORK_BITCOIN_MAINNET)
              ? WALLY_NETWORK_BITCOIN_TESTNET
              : WALLY_NETWORK_BITCOIN_MAINNET;
    if (wallet_descriptor_parse(descriptor_str, NULL, net, &desc) != WALLY_OK)
      return NULL;
  }
  char checksum[9];
  bool ok = descriptor_checksum_from_descriptor(desc, checksum);
  wally_descriptor_free(desc);
  return ok ? strdup(checksum) : NULL;
}

bool registry_session_has_duplicate(const char *descriptor_str, char *out_id,
                                    size_t out_id_size) {
  if (out_id && out_id_size > 0)
    out_id[0] = '\0';
  if (!descriptor_str)
    return false;

  char *target = descriptor_checksum_alloc(descriptor_str);
  if (!target)
    return false;

  bool found =
      registry_session_has_duplicate_checksum(target, out_id, out_id_size);
  free(target);
  return found;
}

bool registry_session_has_duplicate_checksum(const char checksum[9],
                                             char *out_id, size_t out_id_size) {
  if (out_id && out_id_size > 0)
    out_id[0] = '\0';
  if (!checksum || checksum[0] == '\0')
    return false;

  bool found = false;
  for (size_t i = 0; i < registry_len; i++) {
    char entry_cksum[9];
    if (registry_entries[i].desc &&
        descriptor_checksum_from_descriptor(registry_entries[i].desc,
                                            entry_cksum)) {
      if (strcmp(entry_cksum, checksum) == 0) {
        found = true;
        if (out_id && out_id_size > 0) {
          strncpy(out_id, registry_entries[i].id, out_id_size - 1);
          out_id[out_id_size - 1] = '\0';
        }
      }
      if (found)
        break;
    }
  }

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
    bool origin_matches = true;
    for (size_t j = 0; j < e->origin_path_len; j++) {
      if (bip32_path_u32_le(keypath + 4 + j * 4) != e->origin_path[j]) {
        origin_matches = false;
        break;
      }
    }
    if (!origin_matches)
      continue;
    size_t tail_depth = total_depth - e->origin_path_len;
    if (tail_depth != MAX_KEYPATH_TAIL_DEPTH)
      continue;
    const uint8_t *tail = keypath + 4 + e->origin_path_len * 4;
    uint32_t mp = bip32_path_u32_le(tail);
    uint32_t ix = bip32_path_u32_le(tail + 4);
    if (bip32_path_is_hardened(mp))
      continue;
    if (bip32_path_is_hardened(ix))
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

bool registry_add_from_string(const char *id, const char *descriptor_str,
                              storage_location_t loc, bool persist) {
  if (!id || !descriptor_str)
    return false;
  if (descriptor_text_has_uppercase_hardened(descriptor_str)) {
    ESP_LOGE(TAG, "descriptor uses 'H' hardened marker (not accepted)");
    return false;
  }
  if (registry_len >= REGISTRY_MAX_ENTRIES) {
    ESP_LOGE(TAG, "registry full (%d entries)", REGISTRY_MAX_ENTRIES);
    return false;
  }

  /* Wallet's network only. Wrong-network descriptors are skipped on
   * boot scan; the validator blocks them on the user load path. */
  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  int ret = wallet_descriptor_parse(descriptor_str, NULL, wally_network, &desc);
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
  bool path_ok = bip32_path_parse(path_str, origin_path, &origin_path_len,
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
    if (!registry_save_bip138(id, descriptor_str, loc)) {
      ESP_LOGE(TAG, "registry_save_bip138 failed, rolling back");
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

bool registry_persist_or_add_from_string(const char *id,
                                         const char *descriptor_str,
                                         storage_location_t loc) {
  if (!id || !descriptor_str)
    return false;

  for (size_t i = 0; i < registry_len; i++) {
    if (strncmp(registry_entries[i].id, id, REGISTRY_ID_MAX_LEN) != 0)
      continue;
    struct wally_descriptor *desc = NULL;
    uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                                 ? WALLY_NETWORK_BITCOIN_MAINNET
                                 : WALLY_NETWORK_BITCOIN_TESTNET;
    if (wallet_descriptor_parse(descriptor_str, NULL, wally_network, &desc) !=
        WALLY_OK)
      return false;
    char existing_checksum[9];
    char new_checksum[9];
    bool same = registry_entries[i].desc &&
                descriptor_checksum_from_descriptor(registry_entries[i].desc,
                                                    existing_checksum) &&
                descriptor_checksum_from_descriptor(desc, new_checksum) &&
                strcmp(existing_checksum, new_checksum) == 0;
    wally_descriptor_free(desc);
    if (!same)
      return false;
    if (!registry_save_bip138(id, descriptor_str, loc))
      return false;
    registry_entries[i].loc = loc;
    registry_entries[i].persisted = true;
    return true;
  }

  return registry_add_from_string(id, descriptor_str, loc, true);
}

bool registry_add_watch_only(const char *id, const char *descriptor_str,
                             wallet_network_t network) {
  if (!id || !descriptor_str)
    return false;
  if (descriptor_text_has_uppercase_hardened(descriptor_str)) {
    ESP_LOGE(TAG, "descriptor uses 'H' hardened marker (not accepted)");
    return false;
  }
  if (registry_len >= REGISTRY_MAX_ENTRIES) {
    ESP_LOGE(TAG, "registry full (%d entries)", REGISTRY_MAX_ENTRIES);
    return false;
  }

  uint32_t wally_network = (network == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  if (wallet_descriptor_parse(descriptor_str, NULL, wally_network, &desc) !=
      WALLY_OK) {
    ESP_LOGE(TAG, "failed to parse watch-only descriptor");
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
  e->loc = STORAGE_FLASH;
  e->desc = desc;
  e->my_key_index = SIZE_MAX; // no key in watch-only mode
  e->num_paths = (size_t)num_paths;
  e->origin_path_len = 0;
  registry_len++;

  ESP_LOGI(TAG, "added watch-only '%s' (%zu entries total)", id, registry_len);
  return true;
}
