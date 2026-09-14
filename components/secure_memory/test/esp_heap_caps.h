#pragma once
#include <stddef.h>
#define MALLOC_CAP_INTERNAL 0x100
#define MALLOC_CAP_8BIT 0x4
void *heap_caps_malloc(size_t size, unsigned caps);
