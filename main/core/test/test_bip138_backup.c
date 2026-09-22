/*
 * BIP138 descriptor backups (core/bip138_backup.c) against the real key and
 * wallet modules with the BIP39 test mnemonic loaded.
 */

#include "../bip138_backup.h"
#include "../bip138_crypto.h"
#include "../bip138_keys.h"
#include "../descriptor_validator.h"
#include "../key.h"
#include "../registry.h"
#include "../storage.h"
#include "../wallet.h"
#include "esp_err.h"
#include <bip138.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- storage stubs: one captured file per location ---------- */

typedef struct {
  bool present;
  char filename[64];
  storage_descriptor_format_t format;
  uint8_t *data;
  size_t len;
} stub_file_t;

static stub_file_t stub_files[2];
static int stub_saves;
static int stub_deletes;
static bool stub_delete_fail;
static char stub_last_deleted[64];

static void stub_storage_reset(void) {
  for (int i = 0; i < 2; i++) {
    free(stub_files[i].data);
    memset(&stub_files[i], 0, sizeof(stub_files[i]));
  }
  stub_saves = 0;
  stub_deletes = 0;
  stub_delete_fail = false;
  stub_last_deleted[0] = '\0';
}

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  storage_descriptor_format_t format) {
  stub_file_t *f = &stub_files[loc == STORAGE_SD];
  free(f->data);
  f->data = malloc(len);
  if (!f->data)
    return ESP_FAIL;
  memcpy(f->data, data, len);
  f->len = len;
  f->format = format;
  f->present = true;
  storage_descriptor_filename(loc, id, format, f->filename,
                              sizeof(f->filename));
  stub_saves++;
  return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  stub_file_t *f = &stub_files[loc == STORAGE_SD];
  stub_deletes++;
  snprintf(stub_last_deleted, sizeof(stub_last_deleted), "%s", filename);
  if (stub_delete_fail || !f->present || strcmp(f->filename, filename) != 0)
    return ESP_FAIL;
  free(f->data);
  memset(f, 0, sizeof(*f));
  return ESP_OK;
}

esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  stub_file_t *f = &stub_files[loc == STORAGE_SD];
  *filenames_out = NULL;
  *count_out = 0;
  if (!f->present)
    return ESP_OK;
  char **list = malloc(sizeof(char *));
  if (!list)
    return ESP_ERR_NO_MEM;
  list[0] = strdup(f->filename);
  *filenames_out = list;
  *count_out = 1;
  return ESP_OK;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  storage_descriptor_format_t *format_out) {
  stub_file_t *f = &stub_files[loc == STORAGE_SD];
  if (!f->present || strcmp(f->filename, filename) != 0)
    return ESP_FAIL;
  *data_out = malloc(f->len);
  if (!*data_out)
    return ESP_ERR_NO_MEM;
  memcpy(*data_out, f->data, f->len);
  *len_out = f->len;
  if (format_out)
    *format_out = f->format;
  return ESP_OK;
}

void storage_free_file_list(char **files, int count) {
  for (int i = 0; i < count; i++)
    free(files[i]);
  free(files);
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               storage_descriptor_format_t format) {
  stub_file_t *f = &stub_files[loc == STORAGE_SD];
  char filename[64];
  storage_descriptor_filename(loc, id, format, filename, sizeof(filename));
  return f->present && strcmp(f->filename, filename) == 0;
}

/* The real storage layer builds the same names; keep the stub honest. */
void storage_descriptor_filename(storage_location_t loc, const char *id,
                                 storage_descriptor_format_t format, char *out,
                                 size_t out_size) {
  const char *ext = format == STORAGE_DESCRIPTOR_BIP138
                        ? (loc == STORAGE_SD ? STORAGE_DESCRIPTOR_EXT_BIP138_SD
                                             : STORAGE_DESCRIPTOR_EXT_BIP138)
                        : STORAGE_DESCRIPTOR_EXT_TXT;
  snprintf(out, out_size, "%s%s%s",
           loc == STORAGE_FLASH ? STORAGE_DESCRIPTOR_PREFIX : "", id, ext);
}

storage_descriptor_format_t storage_descriptor_format(const char *filename) {
  size_t len = strlen(filename);
  if (len > 7 && strcmp(filename + len - 7, ".bip138") == 0)
    return STORAGE_DESCRIPTOR_BIP138;
  if (len > 11 && strcmp(filename + len - 11, ".bip138.txt") == 0)
    return STORAGE_DESCRIPTOR_BIP138;
  return STORAGE_DESCRIPTOR_TXT;
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
  check("is container", bip138_is_container(blob, blob_len));
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
  size_t ct_off = (size_t)(cont.ciphertext - blob);
  blob[ct_off - 1] = 0;
  check("empty ciphertext parses but does not decrypt",
        cont.ciphertext_len < 0xfd &&
            bip138_parse(blob, ct_off, &cont) == BIP138_OK &&
            bip138_plaintext_max(&cont) == 0 &&
            !bip138_backup_decrypt(blob, ct_off, &recovered, NULL));
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
  size_t text_len = 0;
  char *recovered = NULL;
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  check("descriptor builds",
        build_wpkh("m/86'/0'/1'", descriptor, sizeof(descriptor)));
  check("encrypt binary", bip138_backup_encrypt(descriptor, &blob, &blob_len));
  text = blob ? malloc(BIP138_BASE64_LEN(blob_len)) : NULL;
  check("encode text", text && bip138_base64_encode(blob, blob_len, text,
                                                    BIP138_BASE64_LEN(blob_len),
                                                    &text_len) == BIP138_OK);
  check("base64 starts with the magic",
        text && strncmp(text, "QklQMTM4", 8) == 0);
  check("text is not a binary container",
        text && !bip138_is_container((const uint8_t *)text, strlen(text)));
  check("decrypt_any accepts text",
        text &&
            bip138_backup_decrypt_any((const uint8_t *)text, strlen(text),
                                      &recovered, NULL) &&
            strcmp(recovered, descriptor) == 0);
  free(recovered);
  recovered = NULL;

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

static void test_registry_persistence(void) {
  char descriptor[256];
  char *recovered = NULL;
  const registry_entry_t *entry = NULL;

  stub_storage_reset();
  registry_clear();
  check("descriptor builds",
        build_wpkh("m/84'/0'/2'", descriptor, sizeof(descriptor)));
  check("persisting registration succeeds",
        registry_add_from_string("ColdVault", descriptor, STORAGE_FLASH, true));
  check("one file written as BIP138",
        stub_saves == 1 && stub_files[0].present &&
            stub_files[0].format == STORAGE_DESCRIPTOR_BIP138 &&
            strcmp(stub_files[0].filename, "d_ColdVault.bip138") == 0);
  check("stored bytes are a container",
        bip138_is_container(stub_files[0].data, stub_files[0].len));
  check("stored container opens with the loaded key",
        bip138_backup_decrypt(stub_files[0].data, stub_files[0].len, &recovered,
                              NULL) &&
            registry_session_has_duplicate(recovered, NULL, 0));
  free(recovered);

  registry_init(false);
  check("boot scan registers the stored descriptor",
        registry_count() == 1 && (entry = registry_get(0)) != NULL &&
            strcmp(entry->id, "ColdVault") == 0 && entry->persisted);

  check("another seed loads",
        key_load_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
                               "zoo wrong",
                               "", false) &&
            wallet_init(WALLET_NETWORK_MAINNET));
  registry_init(false);
  check("boot scan skips a backup addressed to another seed",
        registry_count() == 0 && stub_files[0].present);

  check("original seed reloads",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false) &&
            wallet_init(WALLET_NETWORK_MAINNET));
  registry_init(false);
  check("boot scan finds it again", registry_count() == 1);
  check("session removal keeps the registered backup",
        registry_remove_at(0) && stub_deletes == 0 && registry_count() == 0 &&
            stub_files[0].present);
  registry_init(false);
  check("session removal does not prevent automatic recovery",
        registry_count() == 1);
  check("de-registration deletes the file and the session entry",
        registry_deregister_at(0) && registry_count() == 0 &&
            stub_deletes == 1 &&
            strcmp(stub_last_deleted, "d_ColdVault.bip138") == 0 &&
            !stub_files[0].present);
  registry_init(false);
  check("nothing left to load", registry_count() == 0);

  registry_clear();
  stub_storage_reset();

  check("session entry adds",
        registry_add_from_string("desc_abcdefgh", descriptor, STORAGE_FLASH,
                                 false) &&
            registry_set_label("desc_abcdefgh", "Single-sig"));
  check("persist refuses an unknown session id",
        !registry_persist("nope", "Named") && stub_saves == 0);
  check("persist promotes the entry",
        registry_persist("desc_abcdefgh", "NamedVault") && stub_saves == 1 &&
            strcmp(stub_files[0].filename, "d_NamedVault.bip138") == 0);
  entry = registry_find_by_id("NamedVault");
  check("entry is renamed, labelled and persisted",
        entry && entry->persisted && entry->loc == STORAGE_FLASH &&
            strcmp(entry->label, "NamedVault") == 0 &&
            !registry_find_by_id("desc_abcdefgh"));
  check("persist refuses an already persisted entry",
        !registry_persist("NamedVault", "Other") && stub_saves == 1);
  check("promoted backup opens with the loaded key",
        bip138_backup_decrypt(stub_files[0].data, stub_files[0].len, &recovered,
                              NULL));
  free(recovered);
  registry_init(false);
  check("promoted entry survives a boot scan",
        registry_count() == 1 && registry_find_by_id("NamedVault") != NULL);
  check("second session entry adds",
        registry_add_from_string("desc_second", descriptor, STORAGE_FLASH,
                                 false));
  check("persist refuses a taken name",
        !registry_persist("desc_second", "NamedVault") && stub_saves == 1);
  registry_clear();
  stub_storage_reset();
}

/* A container written by the library alone, without Kern's approval mark:
 * what another wallet, or an attacker holding only our xpub, can produce. */
static bool forge_backup(const char *descriptor, uint8_t **blob_out,
                         size_t *blob_len) {
  uint8_t keys[BIP138_KEYS_MAX * 32];
  size_t count = 0;
  if (!bip138_keys_from_descriptor(descriptor, WALLY_NETWORK_BITCOIN_MAINNET,
                                   keys, NULL, BIP138_KEYS_MAX, &count))
    return false;
  bip138_item item = {{BIP138_CONTENT_BIP, BIP138_BIP_DESCRIPTOR, NULL, 0},
                      (const uint8_t *)descriptor,
                      strlen(descriptor)};
  size_t pt_len = bip138_plaintext_size(&item, 1, 0);
  size_t cap =
      bip138_encrypt_size(bip138_secret_bucket(count), NULL, 0, pt_len);
  uint8_t *pt = malloc(pt_len);
  uint8_t *blob = malloc(cap);
  bool ok =
      pt && blob &&
      bip138_plaintext_encode(&item, 1, 0, pt, pt_len, &pt_len) == BIP138_OK &&
      bip138_encrypt(kern_bip138_crypto(), keys, count, NULL, 0, pt, pt_len,
                     blob, cap, blob_len) == BIP138_OK;
  free(pt);
  if (!ok) {
    free(blob);
    return false;
  }
  *blob_out = blob;
  return true;
}

static void test_approval_and_forgery(void) {
  char descriptor[256];
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  char *recovered = NULL;
  bool approved = false;

  check("descriptor builds",
        build_wpkh("m/84'/0'/3'", descriptor, sizeof(descriptor)));
  check("own backup encrypts",
        bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("own backup is approved",
        bip138_backup_decrypt(blob, blob_len, &recovered, &approved) &&
            approved && strcmp(recovered, descriptor) == 0);
  free(recovered);
  free(blob);

  check("forged backup builds", forge_backup(descriptor, &blob, &blob_len));
  approved = true;
  check("forged backup decrypts but is not approved",
        bip138_backup_decrypt(blob, blob_len, &recovered, &approved) &&
            !approved);
  free(recovered);

  stub_storage_reset();
  registry_clear();
  stub_files[0].present = true;
  stub_files[0].data = blob;
  stub_files[0].len = blob_len;
  stub_files[0].format = STORAGE_DESCRIPTOR_BIP138;
  snprintf(stub_files[0].filename, sizeof(stub_files[0].filename),
           "d_forged.bip138");
  registry_init(false);
  check("boot scan ignores a backup without the approval mark",
        registry_count() == 0);
  recovered = NULL;
  check("an old unmarked backup still supports explicit import",
        bip138_backup_decrypt(blob, blob_len, &recovered, &approved) &&
            !approved &&
            descriptor_validate_keyed(recovered, NULL) == VALIDATION_SUCCESS);
  /* Simulate the explicit confirmation and registration path. The fixture
   * holds one flash file, so the unmarked one is replaced by the new one. */
  stub_storage_reset();
  check(
      "confirmed old descriptor can be registered with a new approval mark",
      registry_add_from_string("confirmed", recovered, STORAGE_FLASH, false) &&
          registry_persist("confirmed", "Recovered"));
  free(recovered);
  registry_init(false);
  check("confirmed replacement auto-loads on the next scan",
        registry_count() == 1 && registry_find_by_id("Recovered") != NULL);
  registry_clear();
  stub_storage_reset();

  check("another seed loads",
        key_load_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
                               "wrong",
                               "", false) &&
            wallet_init(WALLET_NETWORK_MAINNET));
  check("another seed can still write a backup for this descriptor",
        bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("original seed reloads",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false) &&
            wallet_init(WALLET_NETWORK_MAINNET));
  approved = true;
  check("a backup marked by another seed decrypts but is not approved",
        bip138_backup_decrypt(blob, blob_len, &recovered, &approved) &&
            !approved);
  free(recovered);
  free(blob);
}

static void test_private_key_rejected(void) {
  struct ext_key *key = NULL;
  char *xprv = NULL;
  char fp[9];
  char descriptor[256];
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  check(
      "private key derives",
      key_get_derived_key("m/84'/0'/0'", &key) && key_get_fingerprint_hex(fp) &&
          bip32_key_to_base58(key, BIP32_FLAG_KEY_PRIVATE, &xprv) == WALLY_OK);
  if (key)
    bip32_key_free(key);
  snprintf(descriptor, sizeof(descriptor), "wpkh([%s/84'/0'/0']%s/<0;1>/*)", fp,
           xprv ? xprv : "");
  wally_free_string(xprv);
  check("backup refuses a descriptor with a private key",
        !bip138_backup_encrypt(descriptor, &blob, &blob_len));
  check("keyed validation refuses it too",
        descriptor_validate_keyed(descriptor, NULL) == VALIDATION_PRIVATE_KEY);
}

static void test_overwrite_and_duplicates(void) {
  char descriptor[256];
  char other[256];
  uint8_t *blob = NULL;
  size_t blob_len = 0;

  stub_storage_reset();
  registry_clear();
  check("descriptors build",
        build_wpkh("m/84'/0'/4'", descriptor, sizeof(descriptor)) &&
            build_wpkh("m/84'/0'/5'", other, sizeof(other)));
  /* A file under this name already on flash, e.g. from another seed. */
  check("foreign file staged", forge_backup(other, &blob, &blob_len));
  stub_files[0].present = true;
  stub_files[0].data = blob;
  stub_files[0].len = blob_len;
  stub_files[0].format = STORAGE_DESCRIPTOR_BIP138;
  snprintf(stub_files[0].filename, sizeof(stub_files[0].filename),
           "d_Shared.bip138");
  check("session entry adds",
        registry_add_from_string("desc_x", descriptor, STORAGE_FLASH, false));
  check("persist refuses to overwrite an existing file",
        !registry_persist("desc_x", "Shared") && stub_saves == 0 &&
            stub_files[0].len == blob_len);
  check("direct persistent add also refuses an existing file",
        !registry_add_from_string("Shared", descriptor, STORAGE_FLASH, true) &&
            stub_saves == 0 && registry_count() == 1 &&
            stub_files[0].data == blob && stub_files[0].len == blob_len);
  check("persist under another name is fine",
        registry_persist("desc_x", "Shared2") && stub_saves == 1);

  /* A BIP138 file on the SD card is a backup, never a registration. */
  registry_clear();
  stub_storage_reset();
  check("flash registration",
        registry_add_from_string("Same", descriptor, STORAGE_FLASH, true));
  check("SD backup of another descriptor saved under the same name",
        bip138_backup_encrypt(other, &blob, &blob_len) &&
            storage_save_descriptor(STORAGE_SD, "Same", blob, blob_len,
                                    STORAGE_DESCRIPTOR_BIP138) == ESP_OK);
  free(blob);
  registry_clear();
  registry_init(false);
  check("boot scan loads flash only",
        registry_count() == 1 && registry_get(0)->loc == STORAGE_FLASH);
  check("de-registration by index deletes the right file",
        registry_deregister_at(0) && registry_count() == 0 &&
            stub_deletes == 1 &&
            strcmp(stub_last_deleted, "d_Same.bip138") == 0 &&
            stub_files[1].present);
  check("removal by bad index fails", !registry_remove_at(5));
  registry_clear();
  stub_storage_reset();
}

static void test_deregister(void) {
  char descriptor[256];
  registry_clear();
  stub_storage_reset();
  check("delete fixture builds",
        build_wpkh("m/84'/0'/2'", descriptor, sizeof(descriptor)));
  check("session-only descriptor loads",
        registry_add_from_string("Session", descriptor, STORAGE_FLASH, false));
  check("de-register rejects a session-only entry without deleting files",
        !registry_deregister_at(0) && stub_deletes == 0 &&
            registry_count() == 1);
  check("session-only entry can be removed", registry_remove_at(0));
  check("descriptor registers",
        registry_add_from_string("Shared", descriptor, STORAGE_FLASH, true));
  const struct wally_descriptor *selected = registry_get(0)->desc;
  stub_delete_fail = true;
  check("failed deletion retains the registration and descriptor",
        !registry_deregister_at(0) && registry_count() == 1 &&
            registry_get(0)->desc == selected && registry_get(0)->persisted &&
            stub_files[0].present);
  stub_delete_fail = false;
  check("de-registration removes the file and the session entry",
        registry_deregister_at(0) && registry_count() == 0 &&
            !stub_files[0].present &&
            strcmp(stub_last_deleted, "d_Shared.bip138") == 0);
  registry_init(false);
  check("deleted registrations do not return on restart",
        registry_count() == 0);
  int deletes = stub_deletes;
  check("invalid selection does not delete anything",
        !registry_deregister_at(0) && stub_deletes == deletes);
  stub_storage_reset();
}

static void test_many_origins(void) {
  registry_clear();
  stub_storage_reset();
  char expressions[17][256], many[8192], fp[9];
  key_unload();
  if (!key_load_from_mnemonic(TEST_MNEMONIC, "foreign", false))
    abort();
  if (!key_get_fingerprint_hex(fp))
    abort();
  for (int i = 0; i < 16; i++) {
    char path[64];
    char *xpub = NULL;
    snprintf(path, sizeof(path), "m/84'/0'/%d'", 10 + i);
    if (!key_get_xpub(path, &xpub))
      abort();
    snprintf(expressions[i], sizeof(expressions[i]), "[%s/%s]%s/<0;1>/*", fp,
             path + 2, xpub);
    wally_free_string(xpub);
  }
  key_unload();
  if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false))
    abort();
  if (!key_get_fingerprint_hex(fp))
    abort();
  char *our_xpub = NULL;
  if (!key_get_xpub("m/84'/0'/26'", &our_xpub))
    abort();
  snprintf(expressions[16], sizeof(expressions[16]),
           "[%s/84'/0'/26']%s/<0;1>/*", fp, our_xpub);
  wally_free_string(our_xpub);
  strcpy(many, "wsh(");
  for (int i = 0; i < 16; i++) {
    strcat(many, "or_d(pkh(");
    strcat(many, expressions[i]);
    strcat(many, "),");
  }
  strcat(many, "pkh(");
  strcat(many, expressions[16]);
  strcat(many, ")");
  for (int i = 0; i < 17; i++)
    strcat(many, ")");
  uint8_t *many_blob = NULL;
  size_t many_len = 0;
  char *many_out = NULL;
  int validation = descriptor_validate_keyed(many, NULL);
  int encrypted = bip138_backup_encrypt(many, &many_blob, &many_len);
  bip138_container many_cont;
  memset(&many_cont, 0, sizeof(many_cont));
  if (encrypted)
    bip138_parse(many_blob, many_len, &many_cont);
  int decrypted =
      encrypted && bip138_backup_decrypt(many_blob, many_len, &many_out, NULL);
  check("17-key miniscript is supported and recovers the 17th origin",
        validation == VALIDATION_SUCCESS && encrypted &&
            many_cont.path_count == 17 && decrypted &&
            strcmp(many_out, many) == 0);
  int session_added =
      registry_add_from_string("desc_many", many, STORAGE_FLASH, false);
  int persisted = session_added && registry_persist("desc_many", "Many");
  registry_clear();
  registry_init(false);
  check("17-key backup survives registry restart",
        session_added && persisted && registry_count() == 1);
  registry_clear();
  stub_storage_reset();
  free(many_out);
  free(many_blob);
}

int main(void) {
  check("test mnemonic loads",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false));
  check("wallet initialises", wallet_init(WALLET_NETWORK_MAINNET));
  test_common_account();
  test_uncommon_account();
  test_foreign_key();
  test_text_form();
  test_rejections();
  test_registry_persistence();
  test_approval_and_forgery();
  test_private_key_rejected();
  test_overwrite_and_duplicates();
  test_deregister();
  test_many_origins();
  key_unload();
  printf("\n%d tests, %d failed\n", tests_run, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
