#pragma once
#include <stdint.h>
#include <stdio.h>

typedef struct {
    char    version[32];
    char    project_name[32];
    char    idf_ver[32];
    uint8_t app_elf_sha256[32];
} esp_app_desc_t;

const esp_app_desc_t *esp_app_get_description(void);
