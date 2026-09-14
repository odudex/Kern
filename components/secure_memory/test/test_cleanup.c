#include "multi_heap.h"
#include "secure_memory.h"
#include "session_cleanup.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void __wrap_multi_heap_free(multi_heap_handle_t heap, void *ptr);
void __wrap_multi_heap_aligned_free(multi_heap_handle_t heap, void *ptr);
void *__wrap_multi_heap_realloc(multi_heap_handle_t heap, void *ptr,
                                size_t size);

static struct {
  void *ptr;
  size_t size;
} allocations[16];
static bool fail_alloc;
static unsigned releases;

void *multi_heap_malloc(multi_heap_handle_t heap, size_t size) {
  (void)heap;
  if (fail_alloc || !size)
    return NULL;
  for (unsigned i = 0; i < 16; ++i) {
    if (!allocations[i].ptr) {
      /* Padding must be scrubbed too, even if the caller wiped strlen(). */
      allocations[i].size = size + 8;
      allocations[i].ptr = malloc(size + 8);
      assert(allocations[i].ptr);
      memset(allocations[i].ptr, 0xA7, size + 8);
      return allocations[i].ptr;
    }
  }
  abort();
}

size_t multi_heap_get_allocated_size(multi_heap_handle_t heap, void *ptr) {
  (void)heap;
  for (unsigned i = 0; i < 16; ++i)
    if (allocations[i].ptr == ptr)
      return allocations[i].size;
  abort();
}

void *__real_multi_heap_realloc(multi_heap_handle_t heap, void *ptr,
                                size_t size) {
  (void)heap;
  for (unsigned i = 0; i < 16; ++i) {
    if (allocations[i].ptr == ptr) {
      /* Only in-place trims reach the real allocator, with the tail cleared. */
      assert(size <= allocations[i].size);
      for (size_t j = size; j < allocations[i].size; ++j)
        assert(((unsigned char *)ptr)[j] == 0);
      allocations[i].size = size + 8;
      return ptr;
    }
  }
  abort();
}

void __real_multi_heap_free(multi_heap_handle_t heap, void *ptr) {
  (void)heap;
  if (!ptr)
    return;
  for (unsigned i = 0; i < 16; ++i) {
    if (allocations[i].ptr == ptr) {
      for (size_t j = 0; j < allocations[i].size; ++j)
        assert(((unsigned char *)ptr)[j] == 0);
      free(ptr);
      allocations[i].ptr = NULL;
      ++releases;
      return;
    }
  }
  abort();
}

static void test_heap_cleanup(void) {
  char *p = multi_heap_malloc(NULL, 64);
  memcpy(p, "first\0remaining mnemonic words", 30);
  __wrap_multi_heap_free(NULL, p);
  assert(releases == 1);
  __wrap_multi_heap_free(NULL, NULL);

  p = multi_heap_malloc(NULL, 64);
  memset(p, 0x51, 64);
  fail_alloc = true;
  assert(__wrap_multi_heap_realloc(NULL, p, 128) == NULL);
  for (unsigned i = 0; i < 64; ++i)
    assert(p[i] == 0x51);
  assert(releases == 1);
  fail_alloc = false;
  char *grown = __wrap_multi_heap_realloc(NULL, p, 128);
  assert(grown && grown != p && releases == 2);
  for (unsigned i = 0; i < 64; ++i)
    assert(grown[i] == 0x51);
  char *shrunk = __wrap_multi_heap_realloc(NULL, grown, 16);
  assert(shrunk == grown && releases == 2);
  for (unsigned i = 0; i < 16; ++i)
    assert(shrunk[i] == 0x51);
  assert(__wrap_multi_heap_realloc(NULL, shrunk, 0) == NULL);
  assert(releases == 3);
  p = __wrap_multi_heap_realloc(NULL, NULL, 8);
  assert(p);
  __wrap_multi_heap_aligned_free(NULL, p);
  assert(releases == 4);
}

static unsigned order[8], order_count;
static void child(void) {
  session_cleanup_unregister(child);
  order[order_count++] = 2;
}
static void parent(void) {
  session_cleanup_unregister(parent);
  session_cleanup_unregister(child);
  order[order_count++] = 1;
}
static void canceled(void) { abort(); }

static void test_session_cleanup(void) {
  session_cleanup_register(parent);
  session_cleanup_register(parent);
  session_cleanup_register(canceled);
  session_cleanup_register(child);
  session_cleanup_unregister(canceled);
  session_cleanup_run();
  assert(order_count == 2 && order[0] == 2 && order[1] == 1);
  session_cleanup_run();
  assert(order_count == 2);
  session_cleanup_register(parent);
  session_cleanup_run();
  assert(order_count == 3 && order[2] == 1);
}

static void test_unaligned_wipe(void) {
  unsigned char raw[43];
  memset(raw, 0xff, sizeof(raw));
  kern_memory_wipe(raw + 1, sizeof(raw) - 2);
  assert(raw[0] == 0xff && raw[sizeof(raw) - 1] == 0xff);
  for (size_t i = 1; i < sizeof(raw) - 1; ++i)
    assert(raw[i] == 0);
  kern_memory_wipe(raw + 3, 2);
  kern_memory_wipe(NULL, 8);
  kern_memory_wipe(raw, 0);
}

int main(void) {
  test_unaligned_wipe();
  test_heap_cleanup();
  test_session_cleanup();
  puts("Cleanup tests passed: full-block wipe, resize, OOM, and session "
       "ownership");
}
