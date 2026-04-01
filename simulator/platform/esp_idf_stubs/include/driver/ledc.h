#pragma once
#include "esp_err.h"
#include <stdint.h>

typedef int ledc_channel_t;
typedef int ledc_timer_t;
typedef int ledc_mode_t;
typedef int ledc_timer_bit_t;
typedef int ledc_clk_cfg_t;

static inline esp_err_t ledc_set_duty(ledc_mode_t m, ledc_channel_t c, uint32_t duty) {
    (void)m; (void)c; (void)duty; return ESP_OK;
}
static inline esp_err_t ledc_update_duty(ledc_mode_t m, ledc_channel_t c) {
    (void)m; (void)c; return ESP_OK;
}
