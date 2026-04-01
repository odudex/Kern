#pragma once
#include <stdint.h>
#include "esp_err.h"

// Chip model enum (subset used by firmware)
typedef enum {
    CHIP_ESP32   = 1,
    CHIP_ESP32S2 = 2,
    CHIP_ESP32S3 = 9,
    CHIP_ESP32P4 = 18,
} esp_chip_model_t;

typedef struct {
    esp_chip_model_t model;
    uint32_t revision;
    uint8_t  cores;
    uint32_t features;
} esp_chip_info_t;

void     esp_restart(void) __attribute__((noreturn));
void     esp_chip_info(esp_chip_info_t *out_info);
uint32_t esp_get_free_heap_size(void);
uint32_t esp_get_minimum_free_heap_size(void);
