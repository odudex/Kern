idf_component_register(SRCS "secure_memory.c" "secret_alloc.c" INCLUDE_DIRS "include"
                       PRIV_REQUIRES esp_mm heap esp_hw_support)

# At the multi_heap boundary, libc, C++ delete, capability allocations and
# third-party libraries share the same release policy. This also catches
# entire task stacks and NVS cipher contexts without patching ESP-IDF/LVGL.
target_link_libraries(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=multi_heap_free"
    "-Wl,--wrap=multi_heap_aligned_free"
    "-Wl,--wrap=multi_heap_realloc")
