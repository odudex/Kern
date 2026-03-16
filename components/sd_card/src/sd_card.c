#include "sd_card.h"

#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#include "driver/sdmmc_host.h"
#include "esp_ldo_regulator.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

static const char *TAG = "sd_card";

static sdmmc_card_t *s_card = NULL;
static bool s_mounted = false;

static esp_err_t sd_card_enable_power(void) {
  static esp_ldo_channel_handle_t s_ldo_chan = NULL;
  if (s_ldo_chan)
    return ESP_OK;

  esp_ldo_channel_config_t ldo_cfg = {.chan_id = 4, .voltage_mv = 3300};
  esp_err_t ret = esp_ldo_acquire_channel(&ldo_cfg, &s_ldo_chan);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to enable LDO VO4: %s", esp_err_to_name(ret));
  }
  return ret;
}

esp_err_t sd_card_init(void) {
  if (s_mounted)
    return ESP_OK;

  ESP_LOGI(TAG, "Initializing SD card");

  esp_err_t ret = sd_card_enable_power();
  if (ret != ESP_OK)
    return ret;

  esp_vfs_fat_sdmmc_mount_config_t mount_config = {
      .format_if_mount_failed = false,
      .max_files = 5,
      .allocation_unit_size = 16 * 1024,
  };

  sdmmc_host_t host = SDMMC_HOST_DEFAULT();
  host.slot = SDMMC_HOST_SLOT_0;
  host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;

  sdmmc_slot_config_t slot_config = {
      .cd = SDMMC_SLOT_NO_CD,
      .wp = SDMMC_SLOT_NO_WP,
      .width = 4,
      .flags = 0,
  };

  ret = esp_vfs_fat_sdmmc_mount(SD_CARD_MOUNT_POINT, &host, &slot_config,
                                &mount_config, &s_card);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Mount failed: %s", esp_err_to_name(ret));
    s_card = NULL;
    return ret;
  }

  s_mounted = true;
  ESP_LOGI(TAG, "SD card mounted at %s", SD_CARD_MOUNT_POINT);
  sdmmc_card_print_info(stdout, s_card);
  return ESP_OK;
}

esp_err_t sd_card_deinit(void) {
  if (!s_mounted || !s_card)
    return ESP_OK;

  esp_err_t ret = esp_vfs_fat_sdcard_unmount(SD_CARD_MOUNT_POINT, s_card);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Unmount failed: %s", esp_err_to_name(ret));
    return ret;
  }

  s_card = NULL;
  s_mounted = false;
  return ESP_OK;
}

bool sd_card_is_mounted(void) { return s_mounted; }

esp_err_t sd_card_write_file(const char *path, const uint8_t *data,
                             size_t len) {
  if (!path || !data)
    return ESP_ERR_INVALID_ARG;
  if (!s_mounted)
    return ESP_ERR_INVALID_STATE;

  FILE *f = fopen(path, "wb");
  if (!f) {
    ESP_LOGE(TAG, "Failed to open %s for writing", path);
    return ESP_FAIL;
  }

  size_t written = fwrite(data, 1, len, f);
  fclose(f);

  if (written != len) {
    ESP_LOGE(TAG, "Write incomplete: %zu/%zu bytes", written, len);
    return ESP_FAIL;
  }
  return ESP_OK;
}

esp_err_t sd_card_read_file(const char *path, uint8_t **data_out,
                            size_t *len_out) {
  if (!path || !data_out || !len_out)
    return ESP_ERR_INVALID_ARG;
  if (!s_mounted)
    return ESP_ERR_INVALID_STATE;

  *data_out = NULL;
  *len_out = 0;

  struct stat st;
  if (stat(path, &st) != 0)
    return ESP_ERR_NOT_FOUND;
  if (st.st_size == 0)
    return ESP_OK;

  uint8_t *buffer = malloc(st.st_size);
  if (!buffer)
    return ESP_ERR_NO_MEM;

  FILE *f = fopen(path, "rb");
  if (!f) {
    free(buffer);
    return ESP_FAIL;
  }

  size_t read_bytes = fread(buffer, 1, st.st_size, f);
  fclose(f);

  if (read_bytes != (size_t)st.st_size) {
    free(buffer);
    return ESP_FAIL;
  }

  *data_out = buffer;
  *len_out = st.st_size;
  return ESP_OK;
}

esp_err_t sd_card_file_exists(const char *path, bool *exists) {
  if (!path || !exists)
    return ESP_ERR_INVALID_ARG;
  if (!s_mounted)
    return ESP_ERR_INVALID_STATE;

  struct stat st;
  *exists = (stat(path, &st) == 0);
  return ESP_OK;
}

esp_err_t sd_card_delete_file(const char *path) {
  if (!path)
    return ESP_ERR_INVALID_ARG;
  if (!s_mounted)
    return ESP_ERR_INVALID_STATE;

  struct stat st;
  if (stat(path, &st) != 0)
    return ESP_ERR_NOT_FOUND;
  if (unlink(path) != 0)
    return ESP_FAIL;
  return ESP_OK;
}

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out,
                             int *count_out) {
  if (!dir_path || !files_out || !count_out)
    return ESP_ERR_INVALID_ARG;
  if (!s_mounted)
    return ESP_ERR_INVALID_STATE;

  *files_out = NULL;
  *count_out = 0;

  DIR *dir = opendir(dir_path);
  if (!dir)
    return ESP_FAIL;

  int count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_REG)
      count++;
  }

  if (count == 0) {
    closedir(dir);
    return ESP_OK;
  }

  char **files = calloc(count, sizeof(char *));
  if (!files) {
    closedir(dir);
    return ESP_ERR_NO_MEM;
  }

  rewinddir(dir);
  int idx = 0;
  while ((entry = readdir(dir)) != NULL && idx < count) {
    if (entry->d_type == DT_REG) {
      files[idx] = strdup(entry->d_name);
      if (!files[idx]) {
        for (int i = 0; i < idx; i++)
          free(files[i]);
        free(files);
        closedir(dir);
        return ESP_ERR_NO_MEM;
      }
      idx++;
    }
  }
  closedir(dir);

  *files_out = files;
  *count_out = idx;
  return ESP_OK;
}

void sd_card_free_file_list(char **files, int count) {
  if (!files)
    return;
  for (int i = 0; i < count; i++)
    free(files[i]);
  free(files);
}
