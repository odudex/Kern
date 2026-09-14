#pragma once

#include <stddef.h>

/* The caller owns this range and must stop DMA/other writers first. External
 * memory is written back after clearing; adjacent cache lines are not
 * invalidated. This does not change where live secrets are allocated. */
void kern_memory_wipe(void *ptr, size_t size);

/* Small secret objects: internal byte-addressable RAM only on firmware.
 * NULL means failure; callers must propagate it. Compatible with free().
 * Host builds use malloc and cannot establish physical placement. */
void *kern_secret_alloc(size_t size);
char *kern_secret_strdup(const char *text);
char *kern_secret_strndup(const char *text, size_t limit);
