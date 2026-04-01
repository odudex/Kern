#pragma once
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Capability flags (values match ESP-IDF; only used as pass-through in sim)
#define MALLOC_CAP_DEFAULT  (1 << 12)
#define MALLOC_CAP_8BIT     (1 <<  2)
#define MALLOC_CAP_32BIT    (1 <<  9)
#define MALLOC_CAP_SPIRAM   (1 <<  3)
#define MALLOC_CAP_DMA      (1 <<  1)
#define MALLOC_CAP_EXEC     (1 <<  4)
#define MALLOC_CAP_INTERNAL (1 <<  0)

static inline void *heap_caps_malloc(size_t size, uint32_t caps) {
    (void)caps; return malloc(size);
}
static inline void heap_caps_free(void *ptr) {
    free(ptr);
}
static inline void *heap_caps_realloc(void *ptr, size_t size, uint32_t caps) {
    (void)caps; return realloc(ptr, size);
}
static inline void *heap_caps_calloc(size_t n, size_t size, uint32_t caps) {
    (void)caps; return calloc(n, size);
}
static inline void *heap_caps_aligned_calloc(size_t alignment, size_t n, size_t size, uint32_t caps) {
    (void)caps;
    void *ptr = NULL;
    posix_memalign(&ptr, alignment, n * size);
    if (ptr) memset(ptr, 0, n * size);
    return ptr;
}
static inline size_t heap_caps_get_free_size(uint32_t caps) {
    (void)caps; return 4 * 1024 * 1024;  // 4 MB stub value
}
static inline size_t heap_caps_get_minimum_free_size(uint32_t caps) {
    (void)caps; return 1 * 1024 * 1024;  // 1 MB stub value
}
