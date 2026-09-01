/*
 * Storage tests (core/storage.c).
 *
 * storage.c is compiled unchanged with stubs/storage_host_hooks.h force-
 * included, which redirects its POSIX file calls here so /spiffs and /sdcard
 * land under a temporary directory. SPIFFS mount, partition erase and the SD
 * card component are faked below with call counting and failure injection,
 * so both locations and every error path can be driven on the host.
 */

#include "../crypto_utils.h"
#include "../kef.h"
#include "../storage.h"
#include <dirent.h>
#include <esp_partition.h>
#include <esp_spiffs.h>
#include <mbedtls/base64.h>
#include <sd_card.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* For calls whose result the test deliberately ignores (warn_unused_result). */
#define IGNORE(call)                                                           \
  do {                                                                         \
    if ((call) != 0) {                                                         \
    }                                                                          \
  } while (0)

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- temp root and path rebasing ---------- */

static char root[256];

static const char *rebase(const char *path, char *buf, size_t n) {
  if (path &&
      (strncmp(path, "/spiffs", 7) == 0 || strncmp(path, "/sdcard", 7) == 0)) {
    snprintf(buf, n, "%s%s", root, path);
    return buf;
  }
  return path;
}

FILE *host_storage_fopen(const char *path, const char *mode) {
  char b[512];
  return fopen(rebase(path, b, sizeof(b)), mode);
}

DIR *host_storage_opendir(const char *path) {
  char b[512];
  return opendir(rebase(path, b, sizeof(b)));
}

int host_storage_unlink(const char *path) {
  char b[512];
  return unlink(rebase(path, b, sizeof(b)));
}

int host_storage_stat(const char *path, struct stat *st) {
  char b[512];
  return stat(rebase(path, b, sizeof(b)), st);
}

int host_storage_mkdir(const char *path, mode_t mode) {
  char b[512];
  return mkdir(rebase(path, b, sizeof(b)), mode);
}

static void remove_tree(const char *path) {
  DIR *dir = opendir(path);
  if (!dir)
    return;
  struct dirent *e;
  while ((e = readdir(dir)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char child[512];
    snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
    struct stat st;
    if (lstat(child, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      remove_tree(child);
    else
      unlink(child);
  }
  closedir(dir);
  rmdir(path);
}

static bool host_file_equals(const char *rel, const void *data, size_t len) {
  char b[512];
  FILE *f = fopen(rebase(rel, b, sizeof(b)), "rb");
  if (!f)
    return false;
  uint8_t *buf = malloc(len + 1);
  size_t n = fread(buf, 1, len + 1, f);
  fclose(f);
  bool eq = n == len && memcmp(buf, data, len) == 0;
  free(buf);
  return eq;
}

static bool host_exists(const char *rel) {
  char b[512];
  struct stat st;
  return stat(rebase(rel, b, sizeof(b)), &st) == 0;
}

static void host_write(const char *rel, const void *data, size_t len) {
  char b[512];
  FILE *f = fopen(rebase(rel, b, sizeof(b)), "wb");
  if (!f)
    return;
  fwrite(data, 1, len, f);
  fclose(f);
}

static void host_mkdir_p(const char *rel) {
  char b[512];
  rebase(rel, b, sizeof(b));
  for (char *p = b + strlen(root) + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(b, 0700);
      *p = '/';
    }
  }
  mkdir(b, 0700);
}

/* ---------- SPIFFS / partition fakes ---------- */

static int spiffs_register_calls, spiffs_unregister_calls, erase_calls;
static esp_err_t spiffs_register_ret;
static bool partition_missing;
static char op_log[32];
static esp_partition_t spiffs_part = {.type = ESP_PARTITION_TYPE_DATA,
                                      .subtype =
                                          ESP_PARTITION_SUBTYPE_DATA_SPIFFS,
                                      .address = 0xC20000,
                                      .size = 0x3E0000,
                                      .label = "storage"};

static void log_op(char c) {
  size_t n = strlen(op_log);
  if (n + 1 < sizeof(op_log)) {
    op_log[n] = c;
    op_log[n + 1] = '\0';
  }
}

esp_err_t esp_vfs_spiffs_register(const esp_vfs_spiffs_conf_t *conf) {
  spiffs_register_calls++;
  log_op('R');
  if (strcmp(conf->base_path, "/spiffs") != 0 ||
      strcmp(conf->partition_label, "storage") != 0)
    return ESP_ERR_INVALID_ARG;
  if (spiffs_register_ret != ESP_OK)
    return spiffs_register_ret;
  host_mkdir_p("/spiffs");
  return ESP_OK;
}

esp_err_t esp_vfs_spiffs_unregister(const char *partition_label) {
  (void)partition_label;
  spiffs_unregister_calls++;
  log_op('U');
  return ESP_OK;
}

bool esp_spiffs_check(const char *partition_label) {
  (void)partition_label;
  return true;
}

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype,
                                                const char *label) {
  if (partition_missing || type != ESP_PARTITION_TYPE_DATA ||
      subtype != ESP_PARTITION_SUBTYPE_DATA_SPIFFS ||
      strcmp(label, "storage") != 0)
    return NULL;
  return &spiffs_part;
}

esp_err_t esp_partition_erase_range(const esp_partition_t *partition,
                                    size_t offset, size_t size) {
  erase_calls++;
  log_op('E');
  if (partition != &spiffs_part || offset != 0 || size != spiffs_part.size)
    return ESP_ERR_INVALID_ARG;
  char b[512];
  remove_tree(rebase("/spiffs", b, sizeof(b)));
  return ESP_OK;
}

esp_err_t esp_partition_read(const esp_partition_t *p, size_t o, void *d,
                             size_t s) {
  (void)p;
  (void)o;
  (void)d;
  (void)s;
  return ESP_FAIL;
}

esp_err_t esp_partition_write(const esp_partition_t *p, size_t o, const void *d,
                              size_t s) {
  (void)p;
  (void)o;
  (void)d;
  (void)s;
  return ESP_FAIL;
}

/* ---------- SD card fake ---------- */

static bool sd_mounted;
static esp_err_t sd_init_ret;
static int sd_init_calls, sd_write_calls;

esp_err_t sd_card_init(void) {
  sd_init_calls++;
  if (sd_init_ret != ESP_OK)
    return sd_init_ret;
  sd_mounted = true;
  host_mkdir_p("/sdcard");
  return ESP_OK;
}

esp_err_t sd_card_deinit(void) {
  sd_mounted = false;
  return ESP_OK;
}

esp_err_t sd_card_remount(void) { return sd_card_init(); }

bool sd_card_is_mounted(void) { return sd_mounted; }

esp_err_t sd_card_write_file(const char *path, const uint8_t *data,
                             size_t len) {
  sd_write_calls++;
  if (!sd_mounted)
    return ESP_ERR_INVALID_STATE;
  char b[512];
  FILE *f = fopen(rebase(path, b, sizeof(b)), "wb");
  if (!f)
    return ESP_FAIL;
  size_t n = fwrite(data, 1, len, f);
  fclose(f);
  return n == len ? ESP_OK : ESP_FAIL;
}

esp_err_t sd_card_read_file(const char *path, uint8_t **data_out,
                            size_t *len_out) {
  if (!sd_mounted)
    return ESP_ERR_INVALID_STATE;
  char b[512];
  FILE *f = fopen(rebase(path, b, sizeof(b)), "rb");
  if (!f)
    return ESP_ERR_NOT_FOUND;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *buf = malloc(sz > 0 ? (size_t)sz : 1);
  size_t n = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  *data_out = buf;
  *len_out = n;
  return ESP_OK;
}

esp_err_t sd_card_file_size(const char *path, size_t *size_out) {
  (void)path;
  (void)size_out;
  return ESP_FAIL;
}

esp_err_t sd_card_file_exists(const char *path, bool *exists) {
  *exists = host_exists(path);
  return ESP_OK;
}

esp_err_t sd_card_delete_file(const char *path) {
  if (!sd_mounted)
    return ESP_ERR_INVALID_STATE;
  char b[512];
  return unlink(rebase(path, b, sizeof(b))) == 0 ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out,
                             int *count_out) {
  if (!sd_mounted)
    return ESP_ERR_INVALID_STATE;
  char b[512];
  DIR *dir = opendir(rebase(dir_path, b, sizeof(b)));
  if (!dir)
    return ESP_ERR_NOT_FOUND;
  char **files = NULL;
  int count = 0;
  struct dirent *e;
  while ((e = readdir(dir)) != NULL) {
    if (e->d_name[0] == '.' || e->d_type != DT_REG)
      continue;
    files = realloc(files, (size_t)(count + 1) * sizeof(char *));
    files[count++] = strdup(e->d_name);
  }
  closedir(dir);
  *files_out = files;
  *count_out = count;
  return ESP_OK;
}

esp_err_t sd_card_list_entries(const char *d, char ***n, bool **i, int *c) {
  (void)d;
  (void)n;
  (void)i;
  (void)c;
  return ESP_FAIL;
}

void sd_card_free_file_list(char **files, int count) {
  for (int i = 0; i < count; i++)
    free(files[i]);
  free(files);
}

/* ---------- helpers ---------- */

static void fakes_reset(void) {
  spiffs_register_calls = spiffs_unregister_calls = erase_calls = 0;
  spiffs_register_ret = ESP_OK;
  partition_missing = false;
  op_log[0] = '\0';
  sd_mounted = false;
  sd_init_ret = ESP_OK;
  sd_init_calls = sd_write_calls = 0;
}

static bool list_has(char **files, int count, const char *name) {
  for (int i = 0; i < count; i++)
    if (strcmp(files[i], name) == 0)
      return true;
  return false;
}

static bool sanitized_is(const char *raw, const char *expect) {
  char out[STORAGE_MAX_SANITIZED_ID_LEN + 1];
  memset(out, 'X', sizeof(out));
  storage_sanitize_id(raw, out, sizeof(out));
  return strcmp(out, expect) == 0;
}

static const uint8_t BLOB[] = {0x00, 0xFF, 0x10, 0x20, 0x7F, 0x80,
                               0x01, 0x02, 0x03, 0x04, 0x05};

/* ---------- tests ---------- */

static void test_sanitize(void) {
  check("sanitize: plain id unchanged", sanitized_is("MyWallet", "MyWallet"));
  check("sanitize: spaces become underscores",
        sanitized_is("My Wallet", "My_Wallet"));
  check("sanitize: every unsafe character replaced",
        sanitized_is("a\\b/c:d*e?f\"g<h>i|j", "a_b_c_d_e_f_g_h_i_j"));
  check("sanitize: consecutive unsafe characters collapse",
        sanitized_is("a  / :b", "a_b"));
  check("sanitize: leading whitespace and dots stripped",
        sanitized_is(" \t..hidden", "hidden"));
  check("sanitize: trailing underscores and dots stripped",
        sanitized_is("name.. _ ", "name"));
  check("sanitize: interior dots kept", sanitized_is("v1.2.kef", "v1.2.kef"));
  check("sanitize: truncated to 24 characters",
        sanitized_is("abcdefghijklmnopqrstuvwxyz0123",
                     "abcdefghijklmnopqrstuvwx"));
  check("sanitize: truncation then trailing strip",
        sanitized_is("abcdefghijklmnopqrstuvw_x", "abcdefghijklmnopqrstuvw"));

  char small[6];
  storage_sanitize_id("abcdefgh", small, sizeof(small));
  check("sanitize: honours a smaller output buffer",
        strcmp(small, "abcde") == 0);

  uint8_t hash[CRYPTO_SHA256_SIZE];
  char expect[9];
  IGNORE(crypto_sha256((const uint8_t *)"///", 3, hash));
  snprintf(expect, sizeof(expect), "%02X%02X%02X%02X", hash[0], hash[1],
           hash[2], hash[3]);
  check("sanitize: all-unsafe id falls back to SHA-256 prefix",
        sanitized_is("///", expect));
  check("sanitize: dots-only id falls back to a hash",
        !sanitized_is("...", "") && !sanitized_is("...", expect));

  char tiny[5];
  storage_sanitize_id("///", tiny, sizeof(tiny));
  check("sanitize: hash fallback fits a tiny buffer",
        strlen(tiny) == 4 && strncmp(tiny, expect, 4) == 0);

  char out[8] = "junk";
  storage_sanitize_id(NULL, out, sizeof(out));
  check("sanitize: NULL id yields empty string", out[0] == '\0');
  storage_sanitize_id("x", NULL, 4);
  storage_sanitize_id("x", out, 0);
  check("sanitize: NULL or zero-size output tolerated", true);
  check("sanitize: empty id falls back to a hash", !sanitized_is("", ""));
}

static void test_descriptor_path(void) {
  char out[96];
  storage_descriptor_path(STORAGE_FLASH, "My Wallet", true, out, sizeof(out));
  check("path: flash kef", strcmp(out, "/spiffs/d_My_Wallet.kef") == 0);
  storage_descriptor_path(STORAGE_FLASH, "My Wallet", false, out, sizeof(out));
  check("path: flash txt", strcmp(out, "/spiffs/d_My_Wallet.txt") == 0);
  storage_descriptor_path(STORAGE_SD, "My Wallet", true, out, sizeof(out));
  check("path: sd kef",
        strcmp(out, "/sdcard/kern/descriptors/My_Wallet.kef") == 0);
  storage_descriptor_path(STORAGE_SD, "My Wallet", false, out, sizeof(out));
  check("path: sd txt",
        strcmp(out, "/sdcard/kern/descriptors/My_Wallet.txt") == 0);
  char shorty[12];
  storage_descriptor_path(STORAGE_SD, "My Wallet", true, shorty,
                          sizeof(shorty));
  check("path: short buffer is NUL-terminated and truncated",
        strlen(shorty) == 11 && strncmp(shorty, "/sdcard/ker", 11) == 0);
  storage_descriptor_path(STORAGE_FLASH, "x", true, NULL, 0);
  check("path: NULL output tolerated", true);
}

static void test_init_and_wipe(void) {
  fakes_reset();
  check("init mounts SPIFFS",
        storage_init() == ESP_OK && spiffs_register_calls == 1);
  check("init is idempotent",
        storage_init() == ESP_OK && spiffs_register_calls == 1);

  check("save before wipe", storage_save_mnemonic(STORAGE_FLASH, "A", BLOB,
                                                  sizeof(BLOB)) == ESP_OK);
  check("file present before wipe", host_exists("/spiffs/m_A.kef"));
  op_log[0] = '\0';
  check("wipe succeeds", storage_wipe_flash() == ESP_OK);
  check("wipe unmounts, erases, remounts in order", strcmp(op_log, "UER") == 0);
  check("wipe removed the files", !host_exists("/spiffs/m_A.kef"));
  char **files;
  int count;
  check("listing after wipe is empty",
        storage_list_mnemonics(STORAGE_FLASH, &files, &count) == ESP_OK &&
            count == 0);
  storage_free_file_list(files, count);

  partition_missing = true;
  op_log[0] = '\0';
  check("wipe without a partition fails",
        storage_wipe_flash() == ESP_ERR_NOT_FOUND && strcmp(op_log, "U") == 0);
  partition_missing = false;
  check("next flash access remounts after a failed wipe",
        storage_save_mnemonic(STORAGE_FLASH, "B", BLOB, sizeof(BLOB)) ==
                ESP_OK &&
            strcmp(op_log, "UR") == 0);

  check("wipe again", storage_wipe_flash() == ESP_OK);
  spiffs_register_ret = ESP_FAIL;
  /* mounted from the wipe: force an unmounted state via a failing wipe */
  partition_missing = true;
  IGNORE(storage_wipe_flash());
  partition_missing = false;
  check("mount failure propagates through save",
        storage_save_mnemonic(STORAGE_FLASH, "C", BLOB, sizeof(BLOB)) ==
            ESP_FAIL);
  check("mount failure propagates through list",
        storage_list_mnemonics(STORAGE_FLASH, &files, &count) == ESP_FAIL);
  check("exists is false when the mount fails",
        !storage_mnemonic_exists(STORAGE_FLASH, "A"));
  spiffs_register_ret = ESP_OK;
  check("mount recovers", storage_init() == ESP_OK);
}

static void test_flash_mnemonics(void) {
  fakes_reset();
  IGNORE(storage_wipe_flash());
  char **files = NULL;
  int count = 0;

  check("flash: invalid args rejected",
        storage_save_mnemonic(STORAGE_FLASH, NULL, BLOB, 1) ==
                ESP_ERR_INVALID_ARG &&
            storage_save_mnemonic(STORAGE_FLASH, "x", NULL, 1) ==
                ESP_ERR_INVALID_ARG &&
            storage_save_mnemonic(STORAGE_FLASH, "x", BLOB, 0) ==
                ESP_ERR_INVALID_ARG);

  check("flash: save mnemonic",
        storage_save_mnemonic(STORAGE_FLASH, "My Seed", BLOB, sizeof(BLOB)) ==
            ESP_OK);
  check("flash: stored raw under the sanitised name",
        host_file_equals("/spiffs/m_My_Seed.kef", BLOB, sizeof(BLOB)));
  check("flash: exists by raw id",
        storage_mnemonic_exists(STORAGE_FLASH, "My Seed") &&
            storage_mnemonic_exists(STORAGE_FLASH, "My  Seed "));
  check("flash: other id does not exist",
        !storage_mnemonic_exists(STORAGE_FLASH, "Other") &&
            !storage_mnemonic_exists(STORAGE_FLASH, NULL));

  uint8_t *data = NULL;
  size_t len = 0;
  check("flash: load round trip",
        storage_load_mnemonic(STORAGE_FLASH, "m_My_Seed.kef", &data, &len) ==
                ESP_OK &&
            len == sizeof(BLOB) && memcmp(data, BLOB, len) == 0);
  free(data);
  check("flash: load missing file",
        storage_load_mnemonic(STORAGE_FLASH, "m_Nope.kef", &data, &len) ==
                ESP_ERR_NOT_FOUND &&
            data == NULL && len == 0);
  check("flash: load invalid args",
        storage_load_mnemonic(STORAGE_FLASH, NULL, &data, &len) ==
                ESP_ERR_INVALID_ARG &&
            storage_load_mnemonic(STORAGE_FLASH, "m_x.kef", NULL, &len) ==
                ESP_ERR_INVALID_ARG);

  host_write("/spiffs/m_Empty.kef", "", 0);
  check("flash: empty file rejected",
        storage_load_mnemonic(STORAGE_FLASH, "m_Empty.kef", &data, &len) ==
            ESP_ERR_INVALID_SIZE);

  IGNORE(storage_save_mnemonic(STORAGE_FLASH, "Second", BLOB, 3));
  host_write("/spiffs/x_stray.kef", "x", 1);
  host_write("/spiffs/m_wrongext.txt", "x", 1);
  host_write("/spiffs/m_.kef", "x", 1);
  host_write("/spiffs/d_desc.kef", "x", 1);
  check("flash: list mnemonics",
        storage_list_mnemonics(STORAGE_FLASH, &files, &count) == ESP_OK);
  check("flash: listing has both saved files and the prefix-only stray",
        count == 4 && list_has(files, count, "m_My_Seed.kef") &&
            list_has(files, count, "m_Second.kef") &&
            list_has(files, count, "m_Empty.kef") &&
            list_has(files, count, "m_.kef"));
  check("flash: listing excludes other prefixes and extensions",
        !list_has(files, count, "x_stray.kef") &&
            !list_has(files, count, "m_wrongext.txt") &&
            !list_has(files, count, "d_desc.kef"));
  storage_free_file_list(files, count);

  check("flash: delete",
        storage_delete_mnemonic(STORAGE_FLASH, "m_My_Seed.kef") == ESP_OK);
  check("flash: deleted file gone",
        !storage_mnemonic_exists(STORAGE_FLASH, "My Seed") &&
            !host_exists("/spiffs/m_My_Seed.kef"));
  check("flash: delete missing fails",
        storage_delete_mnemonic(STORAGE_FLASH, "m_My_Seed.kef") == ESP_FAIL);
  check("flash: delete NULL rejected",
        storage_delete_mnemonic(STORAGE_FLASH, NULL) == ESP_ERR_INVALID_ARG);
  check("flash: SD card never touched", sd_init_calls == 0);
  storage_free_file_list(NULL, 0);
}

static void test_flash_descriptors(void) {
  fakes_reset();
  IGNORE(storage_wipe_flash());
  const char *txt = "wpkh([73c5da0a/84'/0'/0']xpub/0/*)";
  char **files = NULL;
  int count = 0;

  check("flash desc: save kef",
        storage_save_descriptor(STORAGE_FLASH, "Vault", BLOB, sizeof(BLOB),
                                true) == ESP_OK);
  check("flash desc: save txt",
        storage_save_descriptor(STORAGE_FLASH, "Plain One",
                                (const uint8_t *)txt, strlen(txt),
                                false) == ESP_OK);
  check("flash desc: files land where descriptor_path says",
        host_file_equals("/spiffs/d_Vault.kef", BLOB, sizeof(BLOB)) &&
            host_file_equals("/spiffs/d_Plain_One.txt", txt, strlen(txt)));
  char path[96];
  storage_descriptor_path(STORAGE_FLASH, "Plain One", false, path,
                          sizeof(path));
  check("flash desc: path helper matches the saved file", host_exists(path));

  check("flash desc: exists respects the extension",
        storage_descriptor_exists(STORAGE_FLASH, "Vault", true) &&
            !storage_descriptor_exists(STORAGE_FLASH, "Vault", false) &&
            storage_descriptor_exists(STORAGE_FLASH, "Plain One", false) &&
            !storage_descriptor_exists(STORAGE_FLASH, "Plain One", true));

  IGNORE(storage_save_mnemonic(STORAGE_FLASH, "Seed", BLOB, 2));
  host_write("/spiffs/d_stray.bak", "x", 1);
  check("flash desc: list",
        storage_list_descriptors(STORAGE_FLASH, &files, &count) == ESP_OK);
  check("flash desc: listing has kef and txt only",
        count == 2 && list_has(files, count, "d_Vault.kef") &&
            list_has(files, count, "d_Plain_One.txt"));
  storage_free_file_list(files, count);

  uint8_t *data = NULL;
  size_t len = 0;
  bool enc = false;
  check("flash desc: load kef flags encrypted",
        storage_load_descriptor(STORAGE_FLASH, "d_Vault.kef", &data, &len,
                                &enc) == ESP_OK &&
            enc && len == sizeof(BLOB) && memcmp(data, BLOB, len) == 0);
  free(data);
  enc = true;
  check("flash desc: load txt flags plaintext",
        storage_load_descriptor(STORAGE_FLASH, "d_Plain_One.txt", &data, &len,
                                &enc) == ESP_OK &&
            !enc && len == strlen(txt) && memcmp(data, txt, len) == 0);
  free(data);
  check("flash desc: NULL encrypted_out accepted",
        storage_load_descriptor(STORAGE_FLASH, "d_Vault.kef", &data, &len,
                                NULL) == ESP_OK);
  free(data);
  check("flash desc: load invalid args",
        storage_load_descriptor(STORAGE_FLASH, NULL, &data, &len, &enc) ==
                ESP_ERR_INVALID_ARG &&
            storage_load_descriptor(STORAGE_FLASH, "d_Vault.kef", &data, NULL,
                                    &enc) == ESP_ERR_INVALID_ARG);
  check("flash desc: delete",
        storage_delete_descriptor(STORAGE_FLASH, "d_Vault.kef") == ESP_OK &&
            !storage_descriptor_exists(STORAGE_FLASH, "Vault", true));
}

static void test_sd_mnemonics(void) {
  fakes_reset();
  char **files = NULL;
  int count = 0;

  sd_init_ret = ESP_ERR_NOT_FOUND;
  check("sd: card init failure propagates from save",
        storage_save_mnemonic(STORAGE_SD, "Seed", BLOB, sizeof(BLOB)) ==
                ESP_ERR_NOT_FOUND &&
            sd_write_calls == 0);
  check("sd: card init failure propagates from load and list",
        storage_load_mnemonic(STORAGE_SD, "Seed.kef", (uint8_t *[]){NULL},
                              (size_t[]){0}) == ESP_ERR_NOT_FOUND &&
            storage_list_mnemonics(STORAGE_SD, &files, &count) ==
                ESP_ERR_NOT_FOUND &&
            storage_delete_mnemonic(STORAGE_SD, "Seed.kef") ==
                ESP_ERR_NOT_FOUND);
  check("sd: exists is false while unmounted",
        !storage_mnemonic_exists(STORAGE_SD, "Seed"));
  sd_init_ret = ESP_OK;

  check("sd: save mnemonic", storage_save_mnemonic(STORAGE_SD, "My Seed", BLOB,
                                                   sizeof(BLOB)) == ESP_OK);
  check("sd: directories created",
        host_exists("/sdcard/kern") && host_exists("/sdcard/kern/mnemonics"));

  unsigned char b64[64];
  size_t b64_len = 0;
  mbedtls_base64_encode(b64, sizeof(b64), &b64_len, BLOB, sizeof(BLOB));
  check("sd: stored base64 without the flash prefix",
        host_file_equals("/sdcard/kern/mnemonics/My_Seed.kef", b64, b64_len) &&
            !host_exists("/sdcard/kern/mnemonics/m_My_Seed.kef"));
  check("sd: exists", storage_mnemonic_exists(STORAGE_SD, "My Seed") &&
                          !storage_mnemonic_exists(STORAGE_SD, "Other"));
  check("sd: every access re-probes the card", sd_init_calls >= 2);

  uint8_t *data = NULL;
  size_t len = 0;
  check("sd: load decodes base64",
        storage_load_mnemonic(STORAGE_SD, "My_Seed.kef", &data, &len) ==
                ESP_OK &&
            len == sizeof(BLOB) && memcmp(data, BLOB, len) == 0);
  free(data);
  check("sd: load missing", storage_load_mnemonic(STORAGE_SD, "Nope.kef", &data,
                                                  &len) == ESP_ERR_NOT_FOUND);

  host_write("/sdcard/kern/mnemonics/Bad.kef", "!!!not base64!!!", 16);
  check("sd: corrupt base64 rejected",
        storage_load_mnemonic(STORAGE_SD, "Bad.kef", &data, &len) ==
            ESP_ERR_INVALID_RESPONSE);

  host_write("/sdcard/kern/mnemonics/notes.txt", "x", 1);
  host_write("/sdcard/kern/mnemonics/.hidden.kef", "x", 1);
  check("sd: list mnemonics",
        storage_list_mnemonics(STORAGE_SD, &files, &count) == ESP_OK);
  check("sd: listing filters by extension",
        count == 2 && list_has(files, count, "My_Seed.kef") &&
            list_has(files, count, "Bad.kef"));
  storage_free_file_list(files, count);

  check("sd: delete",
        storage_delete_mnemonic(STORAGE_SD, "My_Seed.kef") == ESP_OK &&
            !storage_mnemonic_exists(STORAGE_SD, "My Seed"));
  check("sd: delete missing",
        storage_delete_mnemonic(STORAGE_SD, "My_Seed.kef") != ESP_OK);
  check("sd: flash never mounted", spiffs_register_calls == 0);
}

static void test_sd_descriptors(void) {
  fakes_reset();
  const char *txt = "wsh(sortedmulti(2,A,B,C))";
  char **files = NULL;
  int count = 0;

  check("sd desc: save kef",
        storage_save_descriptor(STORAGE_SD, "Vault", BLOB, sizeof(BLOB),
                                true) == ESP_OK);
  check("sd desc: save txt",
        storage_save_descriptor(STORAGE_SD, "Plain", (const uint8_t *)txt,
                                strlen(txt), false) == ESP_OK);
  unsigned char b64[64];
  size_t b64_len = 0;
  mbedtls_base64_encode(b64, sizeof(b64), &b64_len, BLOB, sizeof(BLOB));
  check("sd desc: kef is base64, txt is raw",
        host_file_equals("/sdcard/kern/descriptors/Vault.kef", b64, b64_len) &&
            host_file_equals("/sdcard/kern/descriptors/Plain.txt", txt,
                             strlen(txt)));

  uint8_t *data = NULL;
  size_t len = 0;
  bool enc = false;
  check("sd desc: load kef decodes",
        storage_load_descriptor(STORAGE_SD, "Vault.kef", &data, &len, &enc) ==
                ESP_OK &&
            enc && len == sizeof(BLOB) && memcmp(data, BLOB, len) == 0);
  free(data);
  check("sd desc: load txt is raw",
        storage_load_descriptor(STORAGE_SD, "Plain.txt", &data, &len, &enc) ==
                ESP_OK &&
            !enc && len == strlen(txt) && memcmp(data, txt, len) == 0);
  free(data);

  host_write("/sdcard/kern/descriptors/backup.bak", "x", 1);
  check("sd desc: list has kef and txt",
        storage_list_descriptors(STORAGE_SD, &files, &count) == ESP_OK &&
            count == 2 && list_has(files, count, "Vault.kef") &&
            list_has(files, count, "Plain.txt"));
  storage_free_file_list(files, count);
  check("sd desc: exists per extension",
        storage_descriptor_exists(STORAGE_SD, "Vault", true) &&
            !storage_descriptor_exists(STORAGE_SD, "Vault", false));
  check("sd desc: delete",
        storage_delete_descriptor(STORAGE_SD, "Plain.txt") == ESP_OK &&
            !storage_descriptor_exists(STORAGE_SD, "Plain", false));
}

static void test_display_name(void) {
  uint8_t *env = NULL;
  size_t env_len = 0;
  const char *id = "Wallet Name";
  check("kef envelope built",
        kef_encrypt((const uint8_t *)id, strlen(id), KEF_V1_CBC_NUL_H16,
                    (const uint8_t *)"pw", 2, 10000, BLOB, sizeof(BLOB), &env,
                    &env_len) == KEF_OK);
  char *name = storage_get_kef_display_name(env, env_len);
  check("display name from KEF header", name && strcmp(name, id) == 0);
  free(name);
  check("display name survives header-only input",
        (name = storage_get_kef_display_name(env, 1 + strlen(id) + 4)) !=
                NULL &&
            strcmp(name, id) == 0);
  free(name);
  free(env);

  char long_id[80];
  memset(long_id, 'L', sizeof(long_id) - 1);
  long_id[sizeof(long_id) - 1] = '\0';
  check("kef envelope with a long id",
        kef_encrypt((const uint8_t *)long_id, strlen(long_id),
                    KEF_V1_CBC_NUL_H16, (const uint8_t *)"pw", 2, 10000, BLOB,
                    sizeof(BLOB), &env, &env_len) == KEF_OK);
  name = storage_get_kef_display_name(env, env_len);
  check("display name capped at 63 characters",
        name && strlen(name) == 63 && strspn(name, "L") == 63);
  free(name);
  free(env);

  check("display name rejects NULL and empty",
        storage_get_kef_display_name(NULL, 4) == NULL &&
            storage_get_kef_display_name(BLOB, 0) == NULL);
  uint8_t junk[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  check("display name rejects a truncated header",
        storage_get_kef_display_name(junk, sizeof(junk)) == NULL);
}

int main(void) {
  printf("=== storage tests ===\n\n");
  snprintf(root, sizeof(root), "/tmp/kern_storage_test_XXXXXX");
  if (!mkdtemp(root)) {
    printf("cannot create temp root\n");
    return 1;
  }

  test_sanitize();
  test_descriptor_path();
  test_init_and_wipe();
  test_flash_mnemonics();
  test_flash_descriptors();
  test_sd_mnemonics();
  test_sd_descriptors();
  test_display_name();

  remove_tree(root);
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
