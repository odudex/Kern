#pragma once

#include "esp_err.h"
#include "esp_partition.h"
#include "esp_spiffs.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * Override the simulated flash/SPIFFS data directory at runtime.
 * Must be called before storage_init()/esp_vfs_spiffs_register().
 * dir should be the full path (e.g. "<data-dir>/spiffs").
 */
void sim_flash_set_data_dir(const char *dir);

bool sim_flash_is_path(const char *path);

/**
 * Resolve a firmware flash path such as "/spiffs/name.kef" to the host
 * filesystem path under the simulator data directory.
 *
 * Returns NULL for unsafe paths or buffer overflow.
 */
const char *sim_flash_resolve_path(const char *path, char *buf,
                                   size_t buf_size);

esp_err_t sim_flash_spiffs_register(const esp_vfs_spiffs_conf_t *conf);
esp_err_t sim_flash_spiffs_unregister(const char *partition_label);
bool sim_flash_spiffs_check(const char *partition_label);

const esp_partition_t *sim_flash_partition_find_first(
    esp_partition_type_t type, esp_partition_subtype_t subtype,
    const char *label);
esp_err_t sim_flash_partition_erase_range(const esp_partition_t *partition,
                                          size_t offset, size_t size);
