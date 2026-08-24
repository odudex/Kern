#include "debug_log.h"

#include "storage.h"

#include <esp_log.h>
#include <esp_timer.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *TAG = "debug_log";
static const size_t DEBUG_LOG_MAX_BYTES = 8192;

static esp_err_t trim_if_needed(void) {
  struct stat st;
  if (stat(DEBUG_LOG_FLASH_PATH, &st) != 0 || st.st_size < 0 ||
      (size_t)st.st_size <= DEBUG_LOG_MAX_BYTES)
    return ESP_OK;

  FILE *f = fopen(DEBUG_LOG_FLASH_PATH, "rb");
  if (!f)
    return ESP_FAIL;

  size_t keep = DEBUG_LOG_MAX_BYTES / 2;
  if (fseek(f, st.st_size - (long)keep, SEEK_SET) != 0) {
    fclose(f);
    return ESP_FAIL;
  }

  char buf[4096];
  size_t nread = fread(buf, 1, sizeof(buf), f);
  fclose(f);

  f = fopen(DEBUG_LOG_FLASH_PATH, "wb");
  if (!f)
    return ESP_FAIL;

  const char *prefix = "--- debug log trimmed ---\n";
  size_t expected = strlen(prefix) + nread;
  size_t written = fwrite(prefix, 1, strlen(prefix), f);
  written += fwrite(buf, 1, nread, f);
  fclose(f);
  return written == expected ? ESP_OK : ESP_FAIL;
}

esp_err_t debug_log_init(void) { return storage_init(); }

esp_err_t debug_log_clear(void) {
  esp_err_t ret = storage_init();
  if (ret != ESP_OK)
    return ret;
  unlink(DEBUG_LOG_FLASH_PATH);
  return ESP_OK;
}

void debug_logf(const char *fmt, ...) {
  if (!fmt || storage_init() != ESP_OK)
    return;

  if (trim_if_needed() != ESP_OK)
    ESP_LOGW(TAG, "failed to trim debug log");

  FILE *f = fopen(DEBUG_LOG_FLASH_PATH, "ab");
  if (!f)
    return;

  fprintf(f, "%lld ", (long long)esp_timer_get_time());

  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
}

void debug_log_event(const char *event) { debug_logf("%s", event); }

void debug_log_hex_preview(const char *label, const uint8_t *data, size_t len,
                           size_t preview_len) {
  if (!label)
    return;

  char hex[65];
  size_t n = len < preview_len ? len : preview_len;
  if (n > sizeof(hex) / 2)
    n = sizeof(hex) / 2;

  for (size_t i = 0; i < n; i++)
    snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02X", data ? data[i] : 0);
  hex[n * 2] = '\0';

  debug_logf("%s len=%u preview=%s%s", label, (unsigned)len, hex,
             len > n ? "..." : "");
}
