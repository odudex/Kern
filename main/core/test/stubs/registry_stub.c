#include "core/storage.h"
#include "core/wallet.h"
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wally_bip32.h>

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
wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

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
