// Persistent storage — mnemonics and descriptors on SPIFFS and SD card

#include "storage.h"
#include "crypto_utils.h"
#include "kef.h"

#include <dirent.h>
#include <esp_partition.h>
#include <esp_spiffs.h>
#include <mbedtls/base64.h>
#include <sd_card.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SPIFFS_PARTITION_LABEL "storage"

static bool spiffs_mounted = false;

/* ========== Low-level file helpers ========== */

static esp_err_t read_flash_file(const char *path, uint8_t **data_out,
                                 size_t *len_out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return ESP_ERR_NOT_FOUND;

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize <= 0) {
    fclose(f);
    return ESP_ERR_INVALID_SIZE;
  }

  uint8_t *data = malloc((size_t)fsize);
  if (!data) {
    fclose(f);
    return ESP_ERR_NO_MEM;
  }

  size_t nread = fread(data, 1, (size_t)fsize, f);
  fclose(f);

  *data_out = data;
  *len_out = nread;
  return ESP_OK;
}

static esp_err_t write_flash_file(const char *path, const uint8_t *data,
                                  size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f)
    return ESP_FAIL;
  size_t written = fwrite(data, 1, len, f);
  fclose(f);
  return (written == len) ? ESP_OK : ESP_FAIL;
}

static esp_err_t base64_encode_alloc(const uint8_t *in, size_t in_len,
                                     unsigned char **out, size_t *out_len) {
  size_t b64_len = 0;
  mbedtls_base64_encode(NULL, 0, &b64_len, in, in_len);

  unsigned char *buf = malloc(b64_len);
  if (!buf)
    return ESP_ERR_NO_MEM;

  if (mbedtls_base64_encode(buf, b64_len, &b64_len, in, in_len) != 0) {
    free(buf);
    return ESP_FAIL;
  }

  *out = buf;
  *out_len = b64_len;
  return ESP_OK;
}

static esp_err_t base64_decode_alloc(const uint8_t *in, size_t in_len,
                                     uint8_t **out, size_t *out_len) {
  size_t decoded_len = 0;
  if (mbedtls_base64_decode(NULL, 0, &decoded_len, in, in_len) !=
      MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    return ESP_ERR_INVALID_RESPONSE;

  uint8_t *buf = malloc(decoded_len);
  if (!buf)
    return ESP_ERR_NO_MEM;

  if (mbedtls_base64_decode(buf, decoded_len, &decoded_len, in, in_len) != 0) {
    free(buf);
    return ESP_ERR_INVALID_RESPONSE;
  }

  *out = buf;
  *out_len = decoded_len;
  return ESP_OK;
}

/* ========== Config-driven internal layer ========== */

typedef struct {
  const char *flash_prefix; /* "m_" or "d_" */
  const char *sd_dir;       /* "/sdcard/kern/mnemonics" or ".../descriptors" */
} storage_item_config_t;

static const storage_item_config_t mnemonic_config = {
    .flash_prefix = STORAGE_MNEMONIC_PREFIX,
    .sd_dir = STORAGE_SD_MNEMONICS_DIR,
};

static const storage_item_config_t descriptor_config = {
    .flash_prefix = STORAGE_DESCRIPTOR_PREFIX,
    .sd_dir = STORAGE_SD_DESCRIPTORS_DIR,
};

/* ========== Initialization ========== */

esp_err_t storage_init(void) {
  if (spiffs_mounted)
    return ESP_OK;

  esp_vfs_spiffs_conf_t conf = {
      .base_path = STORAGE_FLASH_BASE_PATH,
      .partition_label = SPIFFS_PARTITION_LABEL,
      .max_files = 5,
      .format_if_mount_failed = true,
  };

  esp_err_t ret = esp_vfs_spiffs_register(&conf);
  if (ret == ESP_OK)
    spiffs_mounted = true;
  return ret;
}

/* ========== ID sanitization ========== */

void storage_sanitize_id(const char *raw_id, char *out, size_t out_size) {
  if (!raw_id || !out || out_size == 0) {
    if (out && out_size > 0)
      out[0] = '\0';
    return;
  }

  const char *p = raw_id;

  /* Strip leading whitespace and dots */
  while (*p == ' ' || *p == '\t' || *p == '.')
    p++;

  size_t max_len = out_size - 1;
  if (max_len > STORAGE_MAX_SANITIZED_ID_LEN)
    max_len = STORAGE_MAX_SANITIZED_ID_LEN;

  size_t j = 0;
  bool last_underscore = false;

  for (size_t i = 0; p[i] && j < max_len; i++) {
    char c = p[i];

    /* Replace filesystem-unsafe characters with underscore */
    if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' ||
        c == '<' || c == '>' || c == '|' || c == ' ') {
      /* Collapse consecutive underscores */
      if (!last_underscore) {
        out[j++] = '_';
        last_underscore = true;
      }
    } else {
      out[j++] = c;
      last_underscore = false;
    }
  }

  /* Strip trailing underscores and dots */
  while (j > 0 && (out[j - 1] == '_' || out[j - 1] == '.'))
    j--;

  out[j] = '\0';

  /* Fallback: first 8 hex chars of SHA-256(raw_id) */
  if (j == 0) {
    uint8_t hash[CRYPTO_SHA256_SIZE];
    crypto_sha256((const uint8_t *)raw_id, strlen(raw_id), hash);
    for (size_t i = 0; i < 4 && (i * 2 + 1) < max_len; i++)
      snprintf(out + i * 2, 3, "%02X", hash[i]);
  }
}

/* ========== Generic path helpers ========== */

static void item_build_filename(const storage_item_config_t *cfg,
                                storage_location_t loc,
                                const char *sanitized_id, const char *ext,
                                char *out, size_t out_size) {
  if (loc == STORAGE_FLASH)
    snprintf(out, out_size, "%s%s%s", cfg->flash_prefix, sanitized_id, ext);
  else
    snprintf(out, out_size, "%s%s", sanitized_id, ext);
}

static void item_build_path(const storage_item_config_t *cfg,
                            storage_location_t loc, const char *filename,
                            char *out, size_t out_size) {
  if (loc == STORAGE_FLASH)
    snprintf(out, out_size, "%s/%s", STORAGE_FLASH_BASE_PATH, filename);
  else
    snprintf(out, out_size, "%s/%s", cfg->sd_dir, filename);
}

static esp_err_t item_init_location(const storage_item_config_t *cfg,
                                    storage_location_t loc) {
  if (loc == STORAGE_FLASH)
    return storage_init();

  /* Call unconditionally: sd_card_init() reuses a live mount but re-probes a
   * stale handle (a card swapped since the last op, with no card-detect line).
   */
  esp_err_t ret = sd_card_init();
  if (ret != ESP_OK)
    return ret;
  mkdir("/sdcard/kern", 0775);
  mkdir(cfg->sd_dir, 0775);
  return ESP_OK;
}

static bool filename_has_ext(const char *filename, const char *ext) {
  size_t flen = strlen(filename);
  size_t elen = strlen(ext);
  return flen >= elen && strcmp(filename + flen - elen, ext) == 0;
}

/* ========== Generic file operations ========== */

static esp_err_t item_save(const storage_item_config_t *cfg,
                           storage_location_t loc, const char *id,
                           const uint8_t *data, size_t len, const char *ext,
                           bool base64_on_sd) {
  if (!id || !data || len == 0)
    return ESP_ERR_INVALID_ARG;

  esp_err_t ret = item_init_location(cfg, loc);
  if (ret != ESP_OK)
    return ret;

  char sanitized[STORAGE_MAX_SANITIZED_ID_LEN + 1];
  storage_sanitize_id(id, sanitized, sizeof(sanitized));

  char filename[48];
  item_build_filename(cfg, loc, sanitized, ext, filename, sizeof(filename));

  char path[96];
  item_build_path(cfg, loc, filename, path, sizeof(path));

  if (loc == STORAGE_FLASH)
    return write_flash_file(path, data, len);

  if (base64_on_sd) {
    unsigned char *b64 = NULL;
    size_t b64_len = 0;
    ret = base64_encode_alloc(data, len, &b64, &b64_len);
    if (ret != ESP_OK)
      return ret;

    ret = sd_card_write_file(path, b64, b64_len);
    free(b64);
    return ret;
  }

  return sd_card_write_file(path, data, len);
}

static esp_err_t item_load_file(const storage_item_config_t *cfg,
                                storage_location_t loc, const char *filename,
                                uint8_t **data_out, size_t *len_out,
                                bool base64_decode) {
  if (!filename || !data_out || !len_out)
    return ESP_ERR_INVALID_ARG;

  *data_out = NULL;
  *len_out = 0;

  esp_err_t ret = item_init_location(cfg, loc);
  if (ret != ESP_OK)
    return ret;

  char path[96];
  item_build_path(cfg, loc, filename, path, sizeof(path));

  if (loc == STORAGE_FLASH)
    return read_flash_file(path, data_out, len_out);

  /* SD card */
  uint8_t *raw = NULL;
  size_t raw_len = 0;

  ret = sd_card_read_file(path, &raw, &raw_len);
  if (ret != ESP_OK)
    return ret;

  if (!base64_decode) {
    *data_out = raw;
    *len_out = raw_len;
    return ESP_OK;
  }

  uint8_t *decoded = NULL;
  size_t decoded_len = 0;
  ret = base64_decode_alloc(raw, raw_len, &decoded, &decoded_len);
  free(raw);
  if (ret != ESP_OK)
    return ret;

  *data_out = decoded;
  *len_out = decoded_len;
  return ESP_OK;
}

static esp_err_t item_list(const storage_item_config_t *cfg,
                           storage_location_t loc, const char **extensions,
                           int ext_count, char ***filenames_out,
                           int *count_out) {
  if (!filenames_out || !count_out)
    return ESP_ERR_INVALID_ARG;

  *filenames_out = NULL;
  *count_out = 0;

  esp_err_t ret = item_init_location(cfg, loc);
  if (ret != ESP_OK)
    return ret;

  if (loc == STORAGE_SD) {
    char **all_files = NULL;
    int all_count = 0;

    ret = sd_card_list_files(cfg->sd_dir, &all_files, &all_count);
    if (ret != ESP_OK)
      return ret;

    char **filtered = NULL;
    int filtered_count = 0;

    for (int i = 0; i < all_count; i++) {
      bool match = false;
      for (int e = 0; e < ext_count; e++) {
        if (filename_has_ext(all_files[i], extensions[e])) {
          match = true;
          break;
        }
      }
      if (!match)
        continue;

      char **tmp =
          realloc(filtered, (size_t)(filtered_count + 1) * sizeof(char *));
      if (!tmp) {
        storage_free_file_list(filtered, filtered_count);
        sd_card_free_file_list(all_files, all_count);
        return ESP_ERR_NO_MEM;
      }
      filtered = tmp;
      filtered[filtered_count] = strdup(all_files[i]);
      if (!filtered[filtered_count]) {
        storage_free_file_list(filtered, filtered_count);
        sd_card_free_file_list(all_files, all_count);
        return ESP_ERR_NO_MEM;
      }
      filtered_count++;
    }

    sd_card_free_file_list(all_files, all_count);
    *filenames_out = filtered;
    *count_out = filtered_count;
    return ESP_OK;
  }

  /* Flash: enumerate SPIFFS directory */
  DIR *dir = opendir(STORAGE_FLASH_BASE_PATH);
  if (!dir)
    return ESP_FAIL;

  char **files = NULL;
  int count = 0;
  struct dirent *entry;
  size_t prefix_len = strlen(cfg->flash_prefix);

  while ((entry = readdir(dir)) != NULL) {
    const char *name = entry->d_name;
    size_t nlen = strlen(name);

    /* Must start with the flash prefix */
    if (nlen < prefix_len + 4)
      continue;
    if (strncmp(name, cfg->flash_prefix, prefix_len) != 0)
      continue;

    /* Must end with one of the accepted extensions */
    bool match = false;
    for (int e = 0; e < ext_count; e++) {
      if (filename_has_ext(name, extensions[e])) {
        match = true;
        break;
      }
    }
    if (!match)
      continue;

    char **tmp = realloc(files, (size_t)(count + 1) * sizeof(char *));
    if (!tmp) {
      storage_free_file_list(files, count);
      closedir(dir);
      return ESP_ERR_NO_MEM;
    }
    files = tmp;
    files[count] = strdup(name);
    if (!files[count]) {
      storage_free_file_list(files, count);
      closedir(dir);
      return ESP_ERR_NO_MEM;
    }
    count++;
  }

  closedir(dir);
  *filenames_out = files;
  *count_out = count;
  return ESP_OK;
}

static esp_err_t item_delete(const storage_item_config_t *cfg,
                             storage_location_t loc, const char *filename) {
  if (!filename)
    return ESP_ERR_INVALID_ARG;

  esp_err_t ret = item_init_location(cfg, loc);
  if (ret != ESP_OK)
    return ret;

  char path[96];
  item_build_path(cfg, loc, filename, path, sizeof(path));

  if (loc == STORAGE_FLASH)
    return (unlink(path) == 0) ? ESP_OK : ESP_FAIL;

  return sd_card_delete_file(path);
}

static bool item_exists(const storage_item_config_t *cfg,
                        storage_location_t loc, const char *id,
                        const char *ext) {
  if (!id)
    return false;

  char sanitized[STORAGE_MAX_SANITIZED_ID_LEN + 1];
  storage_sanitize_id(id, sanitized, sizeof(sanitized));

  char filename[48];
  item_build_filename(cfg, loc, sanitized, ext, filename, sizeof(filename));

  char path[96];
  item_build_path(cfg, loc, filename, path, sizeof(path));

  if (loc == STORAGE_FLASH) {
    if (storage_init() != ESP_OK)
      return false;
    struct stat st;
    return (stat(path, &st) == 0);
  }

  if (!sd_card_is_mounted())
    return false;
  bool exists = false;
  sd_card_file_exists(path, &exists);
  return exists;
}

/* ========== Mnemonic public API (thin wrappers) ========== */

esp_err_t storage_save_mnemonic(storage_location_t loc, const char *id,
                                const uint8_t *kef_envelope, size_t len) {
  return item_save(&mnemonic_config, loc, id, kef_envelope, len,
                   STORAGE_MNEMONIC_EXT, true);
}

esp_err_t storage_load_mnemonic(storage_location_t loc, const char *filename,
                                uint8_t **kef_envelope_out, size_t *len_out) {
  return item_load_file(&mnemonic_config, loc, filename, kef_envelope_out,
                        len_out, loc == STORAGE_SD);
}

esp_err_t storage_list_mnemonics(storage_location_t loc, char ***filenames_out,
                                 int *count_out) {
  const char *exts[] = {STORAGE_MNEMONIC_EXT};
  return item_list(&mnemonic_config, loc, exts, 1, filenames_out, count_out);
}

esp_err_t storage_delete_mnemonic(storage_location_t loc,
                                  const char *filename) {
  return item_delete(&mnemonic_config, loc, filename);
}

bool storage_mnemonic_exists(storage_location_t loc, const char *id) {
  return item_exists(&mnemonic_config, loc, id, STORAGE_MNEMONIC_EXT);
}

/* ========== Descriptor public API (thin wrappers) ========== */

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
  const char *ext =
      encrypted ? STORAGE_DESCRIPTOR_EXT_KEF : STORAGE_DESCRIPTOR_EXT_TXT;
  return item_save(&descriptor_config, loc, id, data, len, ext,
                   encrypted /* only base64-encode .kef on SD */);
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  bool *encrypted_out) {
  if (!filename || !data_out || !len_out)
    return ESP_ERR_INVALID_ARG;

  bool is_kef = filename_has_ext(filename, STORAGE_DESCRIPTOR_EXT_KEF);
  if (encrypted_out)
    *encrypted_out = is_kef;

  /* base64 decode only for .kef files on SD card */
  bool decode = is_kef && (loc == STORAGE_SD);
  return item_load_file(&descriptor_config, loc, filename, data_out, len_out,
                        decode);
}

esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  const char *exts[] = {STORAGE_DESCRIPTOR_EXT_KEF, STORAGE_DESCRIPTOR_EXT_TXT};
  return item_list(&descriptor_config, loc, exts, 2, filenames_out, count_out);
}

esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  return item_delete(&descriptor_config, loc, filename);
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               bool encrypted) {
  const char *ext =
      encrypted ? STORAGE_DESCRIPTOR_EXT_KEF : STORAGE_DESCRIPTOR_EXT_TXT;
  return item_exists(&descriptor_config, loc, id, ext);
}

void storage_descriptor_path(storage_location_t loc, const char *id,
                             bool encrypted, char *out, size_t out_size) {
  if (!out || out_size == 0)
    return;

  char sanitized[STORAGE_MAX_SANITIZED_ID_LEN + 1];
  storage_sanitize_id(id, sanitized, sizeof(sanitized));

  const char *ext =
      encrypted ? STORAGE_DESCRIPTOR_EXT_KEF : STORAGE_DESCRIPTOR_EXT_TXT;
  char filename[STORAGE_MAX_SANITIZED_ID_LEN + 8];
  item_build_filename(&descriptor_config, loc, sanitized, ext, filename,
                      sizeof(filename));
  item_build_path(&descriptor_config, loc, filename, out, out_size);
}

/* ========== Shared utilities ========== */

char *storage_get_kef_display_name(const uint8_t *data, size_t len) {
  if (!data || len == 0)
    return NULL;

  const uint8_t *id_ptr = NULL;
  size_t id_len = 0;
  if (kef_parse_header(data, len, &id_ptr, &id_len, NULL, NULL) != KEF_OK)
    return NULL;

  size_t copy_len = id_len < 63 ? id_len : 63;
  char *name = malloc(copy_len + 1);
  if (name) {
    memcpy(name, id_ptr, copy_len);
    name[copy_len] = '\0';
  }
  return name;
}

esp_err_t storage_wipe_flash(void) {
  if (spiffs_mounted) {
    esp_vfs_spiffs_unregister(SPIFFS_PARTITION_LABEL);
    spiffs_mounted = false;
  }

  const esp_partition_t *part = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS,
      SPIFFS_PARTITION_LABEL);
  if (!part)
    return ESP_ERR_NOT_FOUND;

  esp_err_t ret = esp_partition_erase_range(part, 0, part->size);
  if (ret != ESP_OK)
    return ret;

  /* Remount — format_if_mount_failed creates a fresh filesystem */
  return storage_init();
}

void storage_free_file_list(char **files, int count) {
  if (!files)
    return;
  for (int i = 0; i < count; i++)
    free(files[i]);
  free(files);
}
