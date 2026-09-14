#pragma once
#include <stddef.h>
typedef void *multi_heap_handle_t;
void *multi_heap_malloc(multi_heap_handle_t heap, size_t size);
size_t multi_heap_get_allocated_size(multi_heap_handle_t heap, void *ptr);
