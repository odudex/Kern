#pragma once
#include "esp_lcd_touch.h"

typedef struct {
    void *dummy;
} bsp_touch_config_t;

esp_err_t bsp_touch_new(const bsp_touch_config_t *config, esp_lcd_touch_handle_t *ret_touch);
