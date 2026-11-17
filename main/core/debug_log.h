#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include "esp_err.h"

#include <stddef.h>
#include <stdint.h>

#define DEBUG_LOG_FLASH_PATH "/spiffs/debug.log"

esp_err_t debug_log_init(void);
esp_err_t debug_log_clear(void);
void debug_log_event(const char *event);
void debug_logf(const char *fmt, ...);
void debug_log_hex_preview(const char *label, const uint8_t *data, size_t len,
                           size_t preview_len);

#endif /* DEBUG_LOG_H */
