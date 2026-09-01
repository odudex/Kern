#pragma once

/* Arguments are still evaluated so callers get no unused-variable warnings,
 * but nothing is printed. */
static inline void esp_log_stub_sink(const char *tag, const char *fmt, ...) {
  (void)tag;
  (void)fmt;
}

#define ESP_LOGE(tag, fmt, ...) esp_log_stub_sink(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) esp_log_stub_sink(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) esp_log_stub_sink(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) esp_log_stub_sink(tag, fmt, ##__VA_ARGS__)
