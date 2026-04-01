#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char *base_path;
    const char *partition_label;
    size_t      max_files;
    bool        format_if_mount_failed;
} esp_vfs_spiffs_conf_t;

esp_err_t esp_vfs_spiffs_register(const esp_vfs_spiffs_conf_t *conf);
esp_err_t esp_vfs_spiffs_unregister(const char *partition_label);
bool      esp_spiffs_check(const char *partition_label);
