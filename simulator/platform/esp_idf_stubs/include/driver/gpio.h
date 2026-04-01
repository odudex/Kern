#pragma once
#include "esp_err.h"
#include <stdint.h>

typedef int gpio_num_t;
#define GPIO_NUM_NC  (-1)
#define GPIO_NUM_7   7
#define GPIO_NUM_8   8
#define GPIO_NUM_23  23
#define GPIO_NUM_26  26
#define GPIO_NUM_27  27

typedef int gpio_mode_t;
#define GPIO_MODE_OUTPUT 1
#define GPIO_MODE_INPUT  0

static inline esp_err_t gpio_set_direction(gpio_num_t n, gpio_mode_t m) {
    (void)n; (void)m; return ESP_OK;
}
static inline esp_err_t gpio_set_level(gpio_num_t n, uint32_t l) {
    (void)n; (void)l; return ESP_OK;
}
static inline int gpio_get_level(gpio_num_t n) {
    (void)n; return 0;
}
static inline esp_err_t gpio_reset_pin(gpio_num_t n) {
    (void)n; return ESP_OK;
}
