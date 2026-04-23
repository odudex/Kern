#include "core/storage.h"
#include "core/wallet.h"
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wally_bip32.h>

bool key_get_fingerprint(unsigned char *fp) {
  if (fp)
    memset(fp, 0, BIP32_KEY_FINGERPRINT_LEN);
  return true;
}
wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)encrypted;
  return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  (void)loc;
  (void)filename;
  return ESP_OK;
}

esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
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
