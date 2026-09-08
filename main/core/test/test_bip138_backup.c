/*
 * BIP138 descriptor backups (core/bip138_backup.c) against the real key and
 * wallet modules with the BIP39 test mnemonic loaded.
 */

#include "../bip138_backup.h"
#include "../key.h"
#include "../storage.h"
#include "../wallet.h"
#include "esp_err.h"
#include <bip138.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- storage stubs (registry persistence is never reached) ----------
 */

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
  *filenames_out = NULL;
  *count_out = 0;
  return ESP_OK;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  bool *encrypted_out) {
  (void)loc;
  (void)filename;
  *data_out = NULL;
  *len_out = 0;
  *encrypted_out = false;
  return -1;
}

void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

/* ---------- fixtures ---------- */

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

#define FOREIGN_KEY                                                            \
  "[58b7f8dc/48'/1'/0'/2']"                                                    \
  "tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52M"  \
  "BoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw"

static bool build_wpkh(const char *path, char *out, size_t out_size) {
  char fp[9];
  char *xpub = NULL;
  if (!key_get_fingerprint_hex(fp) || !key_get_xpub(path, &xpub))
    return false;
  int n =
      snprintf(out, out_size, "wpkh([%s/%s]%s/<0;1>/*)", fp, path + 2, xpub);
  wally_free_string(xpub);
  return n > 0 && (size_t)n < out_size;
}

static void test_common_account(void) {
  char descriptor[256];
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  char *recovered = NULL;
  bip138_container cont;

  check("descriptor builds",
        build_wpkh("m/84'/0'/0'", descriptor, sizeof(descriptor)));
  check("encrypt", bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("is container", bip138_backup_is_container(blob, blob_len));
  check("parses", bip138_parse(blob, blob_len, &cont) == BIP138_OK);
  check("origin is stored as a recovery hint", cont.path_count == 1);
  check("one key padded to five secrets", cont.secret_count == 5);
  check("decrypt", bip138_backup_decrypt(blob, blob_len, &recovered, NULL));
  check("descriptor round-trips",
        recovered && strcmp(recovered, descriptor) == 0);
  free(recovered);

  uint8_t *again = NULL;
  size_t again_len = 0;
  check("encrypt again", bip138_backup_encrypt(descriptor, &again, &again_len));
  check("fresh nonce each time",
        again_len == blob_len && memcmp(again, blob, blob_len) != 0);
  free(again);

  blob[blob_len - 1] ^= 0x01;
  check("tampered blob fails",
        !bip138_backup_decrypt(blob, blob_len, &recovered, NULL));
  check("truncated blob fails",
        !bip138_backup_decrypt(blob, blob_len - 20, &recovered, NULL));
  free(blob);
}

static void test_uncommon_account(void) {
  char descriptor[256];
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  char *recovered = NULL;
  bip138_container cont;
  uint32_t child[8];
  size_t depth = 0;

  check("account 10' descriptor builds",
        build_wpkh("m/84'/0'/10'", descriptor, sizeof(descriptor)));
  check("encrypt", bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("parses", bip138_parse(blob, blob_len, &cont) == BIP138_OK);
  check("uncommon origin is stored", cont.path_count == 1);
  check("stored path is 84'/0'/10'",
        bip138_path_at(&cont, 0, child, 8, &depth) == BIP138_OK && depth == 3 &&
            child[2] == (10 | 0x80000000u));
  check("decrypt via stored path",
        bip138_backup_decrypt(blob, blob_len, &recovered, NULL));
  check("descriptor round-trips",
        recovered && strcmp(recovered, descriptor) == 0);
  free(recovered);
  free(blob);
}

static void test_foreign_key(void) {
  const char *descriptor = "wpkh(" FOREIGN_KEY "/<0;1>/*)";
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  char *recovered = NULL;
  check("foreign descriptor encrypts",
        bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("foreign backup cannot be decrypted",
        !bip138_backup_decrypt(blob, blob_len, &recovered, NULL));
  free(blob);
}

static void test_text_form(void) {
  char descriptor[256];
  char *text = NULL;
  char *recovered = NULL;
  check("descriptor builds",
        build_wpkh("m/86'/0'/1'", descriptor, sizeof(descriptor)));
  check("encrypt text", bip138_backup_encrypt_text(descriptor, &text));
  check("base64 starts with the magic",
        text && strncmp(text, "QklQMTM4", 8) == 0);
  check("text is not a binary container",
        !bip138_backup_is_container((const uint8_t *)text, strlen(text)));
  check("decrypt_any accepts text",
        bip138_backup_decrypt_any((const uint8_t *)text, strlen(text),
                                  &recovered, NULL) &&
            strcmp(recovered, descriptor) == 0);
  free(recovered);
  recovered = NULL;

  uint8_t *blob = NULL;
  size_t blob_len = 0;
  check("encrypt binary", bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("decrypt_any accepts binary",
        bip138_backup_decrypt_any(blob, blob_len, &recovered, NULL) &&
            strcmp(recovered, descriptor) == 0);
  free(recovered);
  free(blob);
  check("decrypt_any rejects garbage",
        !bip138_backup_decrypt_any((const uint8_t *)"not a backup", 12,
                                   &recovered, NULL));
  free(text);
}

static void test_rejections(void) {
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  check("bare xpub descriptor is rejected",
        !bip138_backup_encrypt("wpkh(" FOREIGN_KEY ")", &blob, &blob_len));
  check("garbage descriptor is rejected",
        !bip138_backup_encrypt("wpkh(", &blob, &blob_len));
  check("NULL descriptor is rejected",
        !bip138_backup_encrypt(NULL, &blob, &blob_len));
}

int main(void) {
  check("key module initialises", key_init());
  check("test mnemonic loads",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false));
  check("wallet initialises", wallet_init(WALLET_NETWORK_MAINNET));
  test_common_account();
  test_uncommon_account();
  test_foreign_key();
  test_text_form();
  test_rejections();
  key_unload();
  printf("\n%d tests, %d failed\n", tests_run, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
