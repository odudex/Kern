#pragma once

#include "esp_err.h"
#include <stdint.h>

#define NVS_DEFAULT_PART_NAME "nvs"
#define NVS_KEY_SIZE 32

typedef struct {
    uint8_t eky[NVS_KEY_SIZE];
    uint8_t tky[NVS_KEY_SIZE];
} nvs_sec_cfg_t;

typedef struct {
    int scheme_id;
} nvs_sec_scheme_t;

esp_err_t nvs_flash_init(void);
esp_err_t nvs_flash_init_partition(const char *part_name);
esp_err_t nvs_flash_deinit(void);
esp_err_t nvs_flash_erase(void);

/* Encrypted-NVS stubs: the simulator has no flash encryption; these map to
 * the plain file-backed store so core/nvs_secure.c compiles and runs. */
nvs_sec_scheme_t *nvs_flash_get_default_security_scheme(void);
esp_err_t nvs_flash_read_security_cfg_v2(nvs_sec_scheme_t *scheme_cfg,
                                         nvs_sec_cfg_t *cfg);
esp_err_t nvs_flash_secure_init(nvs_sec_cfg_t *cfg);
