#include "core/storage.h"
#include "core/kef.h"
#include "sim_flash.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "storage_smoke failed: %s\n", msg);                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int mkdir_p(const char *path) {
  char tmp[512];
  size_t len = strlen(path);
  if (len >= sizeof(tmp))
    return -1;
  memcpy(tmp, path, len + 1);
  for (size_t i = 1; i < len; i++) {
    if (tmp[i] == '/') {
      tmp[i] = '\0';
      mkdir(tmp, 0700);
      tmp[i] = '/';
    }
  }
  return mkdir(tmp, 0700);
}

static void remove_tree(const char *path) {
  DIR *dir = opendir(path);
  if (!dir) {
    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    char child[512];
    snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

    struct stat st;
    if (lstat(child, &st) != 0)
      continue;

    if (S_ISDIR(st.st_mode)) {
      remove_tree(child);
      rmdir(child);
    } else {
      unlink(child);
    }
  }

  closedir(dir);
  rmdir(path);
}

static bool list_has(char **files, int count, const char *name) {
  for (int i = 0; i < count; i++) {
    if (strcmp(files[i], name) == 0)
      return true;
  }
  return false;
}

static int expect_loaded(const uint8_t *expected, size_t expected_len,
                         const uint8_t *actual, size_t actual_len,
                         const char *label) {
  if (actual_len != expected_len || memcmp(actual, expected, expected_len) != 0) {
    fprintf(stderr, "storage_smoke failed: %s bytes differ\n", label);
    return 1;
  }
  return 0;
}

int main(void) {
  char root[256];
  snprintf(root, sizeof(root), "/tmp/kern-sim-storage-smoke-%ld", (long)getpid());

  char flash_root[320];
  char nvs_root[320];
  char sentinel[384];
  snprintf(flash_root, sizeof(flash_root), "%s/spiffs", root);
  snprintf(nvs_root, sizeof(nvs_root), "%s/nvs", root);
  snprintf(sentinel, sizeof(sentinel), "%s/settings.nvs", nvs_root);

  remove_tree(root);
  mkdir_p(nvs_root);
  FILE *nf = fopen(sentinel, "wb");
  CHECK(nf != NULL, "create NVS sentinel");
  fputs("sentinel", nf);
  fclose(nf);

  sim_flash_set_data_dir(flash_root);
  CHECK(storage_init() == ESP_OK, "storage_init");

  uint8_t *kef_blob = NULL;
  size_t kef_blob_len = 0;
  const uint8_t password[] = "test";
  const uint8_t secret[] = "seed entropy bytes";
  CHECK(kef_encrypt((const uint8_t *)"SmokeName", 9, KEF_V15_CTR_H4,
                    password, strlen((const char *)password), 10000, secret,
                    sizeof(secret) - 1, &kef_blob, &kef_blob_len) == KEF_OK,
        "create KEF envelope");
  CHECK(kef_is_envelope(kef_blob, kef_blob_len), "valid KEF envelope");

  const char descriptor[] = "wpkh([00000000/84'/0'/0']xpub/0/*)#example";

  CHECK(storage_save_mnemonic(STORAGE_FLASH, "Smoke Name", kef_blob,
                              kef_blob_len) == ESP_OK,
        "save flash mnemonic");
  CHECK(storage_mnemonic_exists(STORAGE_FLASH, "Smoke Name"),
        "mnemonic exists");

  char **files = NULL;
  int count = 0;
  CHECK(storage_list_mnemonics(STORAGE_FLASH, &files, &count) == ESP_OK,
        "list flash mnemonics");
  CHECK(list_has(files, count, "m_Smoke_Name.kef"), "mnemonic filename");
  storage_free_file_list(files, count);

  uint8_t *loaded = NULL;
  size_t loaded_len = 0;
  CHECK(storage_load_mnemonic(STORAGE_FLASH, "m_Smoke_Name.kef", &loaded,
                              &loaded_len) == ESP_OK,
        "load flash mnemonic");
  CHECK(expect_loaded(kef_blob, kef_blob_len, loaded, loaded_len,
                      "mnemonic") == 0,
        "mnemonic round-trip");

  char *display_name = storage_get_kef_display_name(loaded, loaded_len);
  CHECK(display_name != NULL && strcmp(display_name, "SmokeName") == 0,
        "KEF display name");
  free(display_name);

  uint8_t *decrypted = NULL;
  size_t decrypted_len = 0;
  CHECK(kef_decrypt(loaded, loaded_len, password,
                    strlen((const char *)password), &decrypted,
                    &decrypted_len) == KEF_OK,
        "decrypt loaded KEF");
  CHECK(expect_loaded(secret, sizeof(secret) - 1, decrypted, decrypted_len,
                      "decrypted KEF payload") == 0,
        "KEF decrypt round-trip");
  free(decrypted);
  free(loaded);

  CHECK(storage_save_descriptor(STORAGE_FLASH, "Desc Kef", kef_blob,
                                kef_blob_len, true) == ESP_OK,
        "save encrypted descriptor");
  CHECK(storage_descriptor_exists(STORAGE_FLASH, "Desc Kef", true),
        "encrypted descriptor exists");

  CHECK(storage_save_descriptor(STORAGE_FLASH, "Plain Desc",
                                (const uint8_t *)descriptor,
                                strlen(descriptor), false) == ESP_OK,
        "save plaintext descriptor");
  CHECK(storage_descriptor_exists(STORAGE_FLASH, "Plain Desc", false),
        "plaintext descriptor exists");

  CHECK(storage_list_descriptors(STORAGE_FLASH, &files, &count) == ESP_OK,
        "list flash descriptors");
  CHECK(list_has(files, count, "d_Desc_Kef.kef"),
        "encrypted descriptor filename");
  CHECK(list_has(files, count, "d_Plain_Desc.txt"),
        "plaintext descriptor filename");
  storage_free_file_list(files, count);

  bool encrypted = false;
  CHECK(storage_load_descriptor(STORAGE_FLASH, "d_Desc_Kef.kef", &loaded,
                                &loaded_len, &encrypted) == ESP_OK,
        "load encrypted descriptor");
  CHECK(encrypted, "encrypted flag");
  CHECK(expect_loaded(kef_blob, kef_blob_len, loaded, loaded_len,
                      "encrypted descriptor") == 0,
        "encrypted descriptor round-trip");
  free(loaded);

  CHECK(storage_load_descriptor(STORAGE_FLASH, "d_Plain_Desc.txt", &loaded,
                                &loaded_len, &encrypted) == ESP_OK,
        "load plaintext descriptor");
  CHECK(!encrypted, "plaintext flag");
  CHECK(expect_loaded((const uint8_t *)descriptor, strlen(descriptor), loaded,
                      loaded_len, "plaintext descriptor") == 0,
        "plaintext descriptor round-trip");
  free(loaded);

  CHECK(storage_delete_mnemonic(STORAGE_FLASH, "m_Smoke_Name.kef") == ESP_OK,
        "delete mnemonic");
  CHECK(!storage_mnemonic_exists(STORAGE_FLASH, "Smoke Name"),
        "mnemonic deleted");

  CHECK(storage_wipe_flash() == ESP_OK, "wipe flash");
  CHECK(storage_list_descriptors(STORAGE_FLASH, &files, &count) == ESP_OK,
        "list after wipe");
  CHECK(count == 0, "flash descriptors wiped");
  storage_free_file_list(files, count);

  struct stat st;
  CHECK(stat(sentinel, &st) == 0, "NVS sentinel preserved");

  free(kef_blob);
  remove_tree(root);
  puts("storage_smoke ok");
  return 0;
}
