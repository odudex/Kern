#include "core/storage.h"
#include "core/wallet.h"
#include "esp_err.h"
#include <bip138.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

void debug_logf(const char *fmt, ...) { (void)fmt; }

#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"

static int storage_save_descriptor_call_count = 0;
static int storage_delete_descriptor_call_count = 0;
static int storage_list_descriptors_call_count = 0;
static int storage_load_descriptor_call_count = 0;

void registry_stub_reset_storage_counters(void) {
  storage_save_descriptor_call_count = 0;
  storage_delete_descriptor_call_count = 0;
  storage_list_descriptors_call_count = 0;
  storage_load_descriptor_call_count = 0;
}

int registry_stub_storage_save_calls(void) {
  return storage_save_descriptor_call_count;
}

int registry_stub_storage_delete_calls(void) {
  return storage_delete_descriptor_call_count;
}

int registry_stub_storage_list_calls(void) {
  return storage_list_descriptors_call_count;
}

int registry_stub_storage_load_calls(void) {
  return storage_load_descriptor_call_count;
}

bool key_get_fingerprint(unsigned char *fp) {
  if (fp)
    memset(fp, 0, BIP32_KEY_FINGERPRINT_LEN);
  return true;
}

bool key_is_loaded(void) { return true; }

bool key_get_xpub(const char *path, char **xpub_out) {
  (void)path;
  if (!xpub_out)
    return false;
  char *xpub = wally_strdup(XPUB_84);
  if (!xpub)
    return false;
  *xpub_out = xpub;
  return true;
}

bool key_get_derived_key_components(const uint32_t *path, size_t path_depth,
                                    struct ext_key **key_out) {
  (void)path;
  (void)path_depth;
  if (key_out)
    *key_out = NULL;
  return false;
}

bool key_get_master_xpub(char **xpub_out) {
  if (!xpub_out)
    return false;
  *xpub_out = strdup(XPUB_84);
  return *xpub_out != NULL;
}

const bip138_crypto_vtable *kern_bip138_crypto_vtable(void) { return NULL; }

int32_t bip138_encrypt(const bip138_crypto_vtable *vtable, const uint8_t *keys,
                       size_t n_keys, const bip138_u32_list *paths,
                       size_t n_paths, uint32_t content_type, uint16_t bip,
                       const uint8_t *tag, size_t tag_len,
                       const uint8_t *payload, size_t payload_len,
                       uint32_t padding, bip138_buf *out, const char **err) {
  (void)vtable;
  (void)keys;
  (void)n_keys;
  (void)paths;
  (void)n_paths;
  (void)content_type;
  (void)bip;
  (void)tag;
  (void)tag_len;
  if (!out)
    return 1;
  (void)padding;
  out->ptr = malloc(payload_len ? payload_len : 1);
  if (!out->ptr)
    return 1;
  if (payload_len)
    memcpy(out->ptr, payload, payload_len);
  out->len = payload_len;
  if (err)
    *err = NULL;
  return BIP138_OK;
}

int32_t bip138_decrypt(const bip138_crypto_vtable *vtable, const uint8_t *key,
                       const uint8_t *encrypted, size_t encrypted_len,
                       bip138_decrypt_result **out, const char **err) {
  (void)vtable;
  (void)key;
  (void)encrypted;
  (void)encrypted_len;
  if (out)
    *out = NULL;
  if (err)
    *err = "stub";
  return 1;
}

size_t bip138_decrypt_len(const bip138_decrypt_result *result) {
  (void)result;
  return 0;
}

int32_t bip138_decrypt_item(const bip138_decrypt_result *result, size_t index,
                            bip138_item *out, const char **err) {
  (void)result;
  (void)index;
  (void)out;
  if (err)
    *err = "stub";
  return 1;
}

void bip138_buf_free(bip138_buf buf) { free((void *)buf.ptr); }
void bip138_decrypt_free(bip138_decrypt_result *result) { (void)result; }

wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

bool wallet_is_initialized(void) { return true; }

int wallet_descriptor_parse(const char *descriptor,
                            const struct wally_map *vars_in, uint32_t network,
                            struct wally_descriptor **output) {
  uint32_t flags = KERN_DESCRIPTOR_MAX_DEPTH << WALLY_MINISCRIPT_DEPTH_SHIFT;
  return wally_descriptor_parse(descriptor, vars_in, network, flags, output);
}

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
  storage_save_descriptor_call_count++;
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)encrypted;
  return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  storage_delete_descriptor_call_count++;
  (void)loc;
  (void)filename;
  return ESP_OK;
}

esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  storage_list_descriptors_call_count++;
  (void)loc;
  if (filenames_out)
    *filenames_out = NULL;
  if (count_out)
    *count_out = 0;
  return ESP_OK;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  bool *encrypted_out) {
  storage_load_descriptor_call_count++;
  (void)loc;
  (void)filename;
  if (data_out)
    *data_out = NULL;
  if (len_out)
    *len_out = 0;
  if (encrypted_out)
    *encrypted_out = false;
  return -1;
}

void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

void storage_sanitize_id(const char *raw_id, char *out, size_t out_size) {
  if (!out || out_size == 0)
    return;
  if (!raw_id) {
    out[0] = '\0';
    return;
  }
  strncpy(out, raw_id, out_size - 1);
  out[out_size - 1] = '\0';
}
