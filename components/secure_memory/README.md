# Secure memory

Rules and rationale live in `docs/security-plan.md` (Phase 0c). This file keeps the operational notes that are not obvious from the code.

**Release policy.** The firmware links `--wrap=multi_heap_free`, `multi_heap_aligned_free` and `multi_heap_realloc`, the boundary ESP-IDF routes libc, C++ deletion, capability-heap releases and owned FreeRTOS stacks through. The wrapper clears the whole block, padding included, before the real release. Growing reallocs allocate, copy, then wipe and free the old block, because TLSF would otherwise free it internally where nothing can wipe it; shrinks are trimmed in place after the tail is cleared. Growth therefore needs both blocks alive at once, which on wave_4b lowers the internal heap low-water mark by about 60 KiB. The Linux simulator mirrors the policy at libc's `free`/`realloc` (copy on both grow and shrink, since glibc may move either); macOS gets neither.

**After an ESP-IDF update** confirm in the ELF disassembly that `heap_caps_free` still calls `__wrap_multi_heap_free` and `heap_caps_realloc_base` still calls `__wrap_multi_heap_realloc`. The realloc wrapper does not support `CONFIG_HEAP_TASK_TRACKING` (a `#error` guards it).

**`kern_memory_wipe`** uses volatile word stores and writes external ranges back with `esp_cache_msync` without invalidating neighbouring cache lines, so the caller must own the whole range and stop DMA writers first. `main/ui/display_cleanup.c` reaches into LVGL 9.5's private display struct to cover inactive draw buffers; re-check that field layout on an LVGL bump.

**Secret placement.** `kern_secret_alloc` requests `MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT` exactly once and returns NULL on exhaustion. `components/libwally-core/kern_wally.c` installs one malloc dispatcher at startup and switches only the calling thread to that allocator for the wrapped BIP39/BIP32 operations; the adapters fail closed if the callback has been replaced.

Tests: `just test` covers the wrappers, the cleanup registry and key-load allocation failures; `just sim-test` runs the LVGL page lifecycle regression.
