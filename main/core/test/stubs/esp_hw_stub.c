/*
 * Host stubs for the ESP-IDF hardware entropy/timing calls that crypto_utils.c
 * and entropy_pool.c reach for.  The simulator's headers are reused (see the
 * Makefile's TEST_INCS); only the implementations live here.
 */

#include <freertos/task.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

void esp_fill_random(void *buf, size_t len) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (f) {
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got == len)
      return;
  }
  /* Fallback keeps the tests deterministic-ish rather than all-zero, which
   * crypto_random_bytes treats as a dead RNG. */
  uint8_t *p = buf;
  for (size_t i = 0; i < len; i++)
    p[i] = (uint8_t)(i * 31 + 7);
}

uint32_t esp_random(void) {
  uint32_t v;
  esp_fill_random(&v, sizeof(v));
  return v;
}

int64_t esp_timer_get_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int esp_reset_reason(void) { return 1; /* ESP_RST_POWERON */ }

/* Seeding jitter has no meaning on a host with no HW RNG refill window. */
void vTaskDelay(TickType_t ticks) { (void)ticks; }
