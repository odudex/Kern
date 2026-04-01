#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>

typedef int esp_partition_type_t;
typedef int esp_partition_subtype_t;

#define ESP_PARTITION_TYPE_DATA         1
#define ESP_PARTITION_SUBTYPE_DATA_SPIFFS 130

typedef struct {
    esp_partition_type_t    type;
    esp_partition_subtype_t subtype;
    uint32_t                address;
    uint32_t                size;
    char                    label[17];
    bool                    encrypted;
} esp_partition_t;

static inline const esp_partition_t *esp_partition_find_first(
    esp_partition_type_t type, esp_partition_subtype_t subtype,
    const char *label) {
    (void)type; (void)subtype; (void)label;
    return NULL;
}

static inline esp_err_t esp_partition_erase_range(
    const esp_partition_t *partition, size_t offset, size_t size) {
    (void)partition; (void)offset; (void)size;
    return ESP_OK;
}

static inline esp_err_t esp_partition_read(
    const esp_partition_t *partition, size_t src_offset,
    void *dst, size_t size) {
    (void)partition; (void)src_offset; (void)dst; (void)size;
    return ESP_ERR_NOT_FOUND;
}

static inline esp_err_t esp_partition_write(
    const esp_partition_t *partition, size_t dst_offset,
    const void *src, size_t size) {
    (void)partition; (void)dst_offset; (void)src; (void)size;
    return ESP_OK;
}
