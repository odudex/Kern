#pragma once
#include "esp_err.h"

typedef struct {
    int dummy;
} esp_video_init_csi_config_t;

static inline esp_err_t esp_video_init(const esp_video_init_csi_config_t *cfg) {
    (void)cfg;
    return ESP_OK;
}

static inline esp_err_t esp_video_deinit(void) {
    return ESP_OK;
}
