#include "secure_memory.h"

#include <stdint.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#include "esp_cache.h"
#include "esp_check.h"
#include "esp_memory_utils.h"
#include "sdkconfig.h"
#else
#define IRAM_ATTR
#endif

/* No allocation, logging or allocator locks in the clearing loop. This also
 * runs while releasing FreeRTOS stacks and internal, cache-off allocations. */
void IRAM_ATTR kern_memory_wipe(void *ptr, size_t size) {
  if (!ptr || !size)
    return;
  volatile unsigned char *bytes = ptr;
  size_t i = 0;
  while (i < size && ((uintptr_t)(bytes + i) & (sizeof(uint32_t) - 1)))
    bytes[i++] = 0;
  volatile uint32_t *words = (volatile uint32_t *)(bytes + i);
  for (; i + sizeof(uint32_t) <= size; i += sizeof(uint32_t))
    *words++ = 0;
  for (; i < size; ++i)
    bytes[i] = 0;
#ifdef ESP_PLATFORM
  if (esp_ptr_external_ram(ptr)) {
    /* Writeback only: invalidating shared, partially occupied cache lines can
     * discard another allocation's writes. The range is still owned here. */
    ESP_ERROR_CHECK(esp_cache_msync(ptr, size,
                                    ESP_CACHE_MSYNC_FLAG_DIR_C2M |
                                        ESP_CACHE_MSYNC_FLAG_UNALIGNED));
  }
#endif
}

#if defined(ESP_PLATFORM) || defined(SECURE_HEAP_TEST)
#include "multi_heap.h"

#ifdef CONFIG_HEAP_TASK_TRACKING
/* heap_caps_malloc_base prefixes each block with an owner header under task
 * tracking; the realloc replacement below is a raw multi_heap_malloc. */
#error "realloc wrapper does not support CONFIG_HEAP_TASK_TRACKING"
#endif

void __real_multi_heap_free(multi_heap_handle_t heap, void *ptr);
void *__real_multi_heap_realloc(multi_heap_handle_t heap, void *ptr,
                                size_t size);

void IRAM_ATTR __wrap_multi_heap_free(multi_heap_handle_t heap, void *ptr) {
  if (ptr)
    kern_memory_wipe(ptr, multi_heap_get_allocated_size(heap, ptr));
  __real_multi_heap_free(heap, ptr);
}

void IRAM_ATTR __wrap_multi_heap_aligned_free(multi_heap_handle_t heap,
                                              void *ptr) {
  __wrap_multi_heap_free(heap, ptr);
}

void *IRAM_ATTR __wrap_multi_heap_realloc(multi_heap_handle_t heap, void *ptr,
                                          size_t size) {
  if (!ptr)
    return multi_heap_malloc(heap, size);
  if (!size) {
    __wrap_multi_heap_free(heap, ptr);
    return NULL;
  }
  size_t old_size = multi_heap_get_allocated_size(heap, ptr);
  if (size <= old_size) {
    /* TLSF trims a shrinking block in place; the released tail never reaches
     * the free hook, so clear it first. */
    kern_memory_wipe((unsigned char *)ptr + size, old_size - size);
    return __real_multi_heap_realloc(heap, ptr, size);
  }
  /* Growth can move the block, and TLSF frees the old one internally,
   * bypassing the public free hook. Copy, then clear the old allocation. On
   * OOM leave the original allocation and its contents intact, as realloc
   * must. */
  void *replacement = multi_heap_malloc(heap, size);
  if (!replacement)
    return NULL;
  memcpy(replacement, ptr, old_size);
  __wrap_multi_heap_free(heap, ptr);
  return replacement;
}
#elif !defined(__APPLE__)
/* Linux simulator: mirror the firmware policy at libc's public boundary.
 * No custom allocation header, so library-owned malloc pointers stay valid. */
#include <malloc.h>
#include <stdlib.h>

void __real_free(void *ptr);
#ifdef SECURE_MEMORY_TEST_OBSERVER
void kern_memory_test_observe_release(void *ptr, size_t size);
#endif

void __wrap_free(void *ptr) {
  if (ptr)
    kern_memory_wipe(ptr, malloc_usable_size(ptr));
#ifdef SECURE_MEMORY_TEST_OBSERVER
  if (ptr)
    kern_memory_test_observe_release(ptr, malloc_usable_size(ptr));
#endif
  __real_free(ptr);
}

void *__wrap_realloc(void *ptr, size_t size) {
  if (!ptr)
    return malloc(size);
  if (!size) {
    __wrap_free(ptr);
    return NULL;
  }
  void *replacement = malloc(size);
  if (!replacement)
    return NULL;
  size_t old_size = malloc_usable_size(ptr);
  memcpy(replacement, ptr, old_size < size ? old_size : size);
  __wrap_free(ptr);
  return replacement;
}
#endif
