#pragma once

#include <stdio.h>

typedef enum {
    ESP_LOG_NONE = 0,
    ESP_LOG_ERROR,
    ESP_LOG_WARN,
    ESP_LOG_INFO,
    ESP_LOG_DEBUG,
    ESP_LOG_VERBOSE,
} esp_log_level_t;

#define LOG_COLOR_E "\033[31m"
#define LOG_COLOR_W "\033[33m"
#define LOG_COLOR_I "\033[32m"
#define LOG_COLOR_D "\033[34m"
#define LOG_COLOR_V "\033[37m"
#define LOG_RESET   "\033[0m"

#define ESP_LOGE(tag, fmt, ...) fprintf(stderr, LOG_COLOR_E "E (%s) " fmt LOG_RESET "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) fprintf(stderr, LOG_COLOR_W "W (%s) " fmt LOG_RESET "\n", tag, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) printf(LOG_COLOR_I "I (%s) " fmt LOG_RESET "\n", tag, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) printf(LOG_COLOR_D "D (%s) " fmt LOG_RESET "\n", tag, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) printf(LOG_COLOR_V "V (%s) " fmt LOG_RESET "\n", tag, ##__VA_ARGS__)

static inline void esp_log_level_set(const char *tag, esp_log_level_t level) {
    (void)tag; (void)level;
}
