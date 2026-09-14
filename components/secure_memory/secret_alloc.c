#include "secure_memory.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(ESP_PLATFORM) || defined(SECRET_ALLOC_TEST)
#include "esp_heap_caps.h"
#endif

void *kern_secret_alloc(size_t size) {
  if (!size)
    return NULL;
#if defined(ESP_PLATFORM) || defined(SECRET_ALLOC_TEST)
  // Capabilities are requirements, not preferences. Never retry in PSRAM.
  return heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
#else
  return malloc(size);
#endif
}

char *kern_secret_strndup(const char *text, size_t limit) {
  if (!text)
    return NULL;
  size_t len = strnlen(text, limit);
  if (len == SIZE_MAX)
    return NULL;
  char *copy = kern_secret_alloc(len + 1);
  if (copy) {
    memcpy(copy, text, len);
    copy[len] = '\0';
  }
  return copy;
}

char *kern_secret_strdup(const char *text) {
  return kern_secret_strndup(text, SIZE_MAX);
}
