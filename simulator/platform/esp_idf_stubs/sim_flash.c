/*
 * File-backed flash/SPIFFS simulator.
 *
 * Firmware paths under /spiffs are mapped to a host directory:
 *   default: simulator/sim_data/spiffs
 *   custom:  <data-dir>/spiffs
 */

#include "sim_flash.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIM_FLASH_DEFAULT_ROOT "simulator/sim_data/spiffs"
#define SIM_FLASH_MOUNT_POINT  "/spiffs"
#define SIM_FLASH_LABEL        "storage"
#define SIM_FLASH_SIZE         (4U * 1024U * 1024U)

static char *s_flash_root_override = NULL;
static bool s_flash_mounted = false;

static esp_partition_t s_flash_partition = {
    .type = ESP_PARTITION_TYPE_DATA,
    .subtype = ESP_PARTITION_SUBTYPE_DATA_SPIFFS,
    .address = 0,
    .size = SIM_FLASH_SIZE,
    .label = SIM_FLASH_LABEL,
    .encrypted = false,
};

void sim_flash_set_data_dir(const char *dir) {
  free(s_flash_root_override);
  s_flash_root_override = dir ? strdup(dir) : NULL;
}

static const char *flash_root(void) {
  return s_flash_root_override ? s_flash_root_override : SIM_FLASH_DEFAULT_ROOT;
}

static esp_err_t mkdir_p(const char *path) {
  if (!path || path[0] == '\0')
    return ESP_ERR_INVALID_ARG;

  char tmp[512];
  size_t len = strlen(path);
  if (len >= sizeof(tmp))
    return ESP_ERR_INVALID_ARG;

  memcpy(tmp, path, len + 1);
  for (size_t i = 1; i < len; i++) {
    if (tmp[i] == '/') {
      tmp[i] = '\0';
      if (tmp[0] != '\0')
        mkdir(tmp, 0700);
      tmp[i] = '/';
    }
  }
  mkdir(tmp, 0700);

  struct stat st;
  return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? ESP_OK : ESP_FAIL;
}

static bool path_is_safe(const char *path) {
  if (!path)
    return false;

  const char *p = path;
  while (*p) {
    if (p[0] == '.' && p[1] == '.' &&
        (p[2] == '\0' || p[2] == '/') &&
        (p == path || p[-1] == '/')) {
      return false;
    }
    p++;
  }
  return true;
}

bool sim_flash_is_path(const char *path) {
  if (!path)
    return false;

  size_t mount_len = strlen(SIM_FLASH_MOUNT_POINT);
  if (strncmp(path, SIM_FLASH_MOUNT_POINT, mount_len) == 0 &&
      (path[mount_len] == '\0' || path[mount_len] == '/')) {
    return true;
  }

  size_t root_len = strlen(flash_root());
  return strncmp(path, flash_root(), root_len) == 0 &&
         (path[root_len] == '\0' || path[root_len] == '/');
}

const char *sim_flash_resolve_path(const char *path, char *buf,
                                   size_t buf_size) {
  if (!path || !buf || buf_size == 0 || !path_is_safe(path))
    return NULL;

  size_t mount_len = strlen(SIM_FLASH_MOUNT_POINT);
  if (strncmp(path, SIM_FLASH_MOUNT_POINT, mount_len) == 0 &&
      (path[mount_len] == '\0' || path[mount_len] == '/')) {
    int n = snprintf(buf, buf_size, "%s%s", flash_root(), path + mount_len);
    if (n < 0 || (size_t)n >= buf_size)
      return NULL;
    return buf;
  }

  size_t root_len = strlen(flash_root());
  if (strncmp(path, flash_root(), root_len) == 0 &&
      (path[root_len] == '\0' || path[root_len] == '/')) {
    return path;
  }

  return NULL;
}

static esp_err_t remove_tree_contents(const char *dir_path) {
  DIR *dir = opendir(dir_path);
  if (!dir) {
    return (errno == ENOENT) ? ESP_OK : ESP_FAIL;
  }

  esp_err_t ret = ESP_OK;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    char child[1024];
    int n = snprintf(child, sizeof(child), "%s/%s", dir_path, entry->d_name);
    if (n < 0 || (size_t)n >= sizeof(child)) {
      ret = ESP_ERR_INVALID_ARG;
      continue;
    }

    struct stat st;
    if (lstat(child, &st) != 0) {
      ret = ESP_FAIL;
      continue;
    }

    if (S_ISDIR(st.st_mode)) {
      if (remove_tree_contents(child) != ESP_OK || rmdir(child) != 0)
        ret = ESP_FAIL;
    } else if (unlink(child) != 0) {
      ret = ESP_FAIL;
    }
  }

  closedir(dir);
  return ret;
}

esp_err_t sim_flash_spiffs_register(const esp_vfs_spiffs_conf_t *conf) {
  if (!conf || !conf->base_path)
    return ESP_ERR_INVALID_ARG;

  if (strcmp(conf->base_path, SIM_FLASH_MOUNT_POINT) != 0)
    return ESP_ERR_NOT_SUPPORTED;

  esp_err_t ret = mkdir_p(flash_root());
  if (ret == ESP_OK)
    s_flash_mounted = true;
  return ret;
}

esp_err_t sim_flash_spiffs_unregister(const char *partition_label) {
  if (partition_label && strcmp(partition_label, SIM_FLASH_LABEL) != 0)
    return ESP_ERR_NOT_FOUND;

  s_flash_mounted = false;
  return ESP_OK;
}

bool sim_flash_spiffs_check(const char *partition_label) {
  if (partition_label && strcmp(partition_label, SIM_FLASH_LABEL) != 0)
    return false;

  struct stat st;
  return s_flash_mounted && stat(flash_root(), &st) == 0 &&
         S_ISDIR(st.st_mode);
}

const esp_partition_t *sim_flash_partition_find_first(
    esp_partition_type_t type, esp_partition_subtype_t subtype,
    const char *label) {
  if (type != ESP_PARTITION_TYPE_DATA ||
      subtype != ESP_PARTITION_SUBTYPE_DATA_SPIFFS)
    return NULL;

  if (label && strcmp(label, SIM_FLASH_LABEL) != 0)
    return NULL;

  return &s_flash_partition;
}

esp_err_t sim_flash_partition_erase_range(const esp_partition_t *partition,
                                          size_t offset, size_t size) {
  if (partition != &s_flash_partition || offset != 0 ||
      size > s_flash_partition.size) {
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t ret = mkdir_p(flash_root());
  if (ret != ESP_OK)
    return ret;

  ret = remove_tree_contents(flash_root());
  if (ret != ESP_OK)
    return ret;

  return mkdir_p(flash_root());
}

const esp_partition_t *esp_partition_find_first(
    esp_partition_type_t type, esp_partition_subtype_t subtype,
    const char *label) {
  return sim_flash_partition_find_first(type, subtype, label);
}

esp_err_t esp_partition_erase_range(const esp_partition_t *partition,
                                    size_t offset, size_t size) {
  return sim_flash_partition_erase_range(partition, offset, size);
}

esp_err_t esp_partition_read(const esp_partition_t *partition,
                             size_t src_offset, void *dst, size_t size) {
  (void)partition;
  (void)src_offset;
  (void)dst;
  (void)size;
  return ESP_ERR_NOT_FOUND;
}

esp_err_t esp_partition_write(const esp_partition_t *partition,
                              size_t dst_offset, const void *src,
                              size_t size) {
  (void)partition;
  (void)dst_offset;
  (void)src;
  (void)size;
  return ESP_ERR_NOT_SUPPORTED;
}
