#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* eFuse block identifiers */
typedef int esp_efuse_block_t;
#define EFUSE_BLK_KEY0  0
#define EFUSE_BLK_KEY1  1
#define EFUSE_BLK_KEY2  2
#define EFUSE_BLK_KEY3  3
#define EFUSE_BLK_KEY4  4
#define EFUSE_BLK_KEY5  5

/* eFuse key purposes */
typedef int esp_efuse_purpose_t;
#define ESP_EFUSE_KEY_PURPOSE_USER                            0
#define ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY                 4
#define ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_ALL                   5
#define ESP_EFUSE_KEY_PURPOSE_HMAC_UP                         6
#define ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE     7

/* HMAC key IDs (also used by esp_hmac.h) */
typedef enum {
    HMAC_KEY0 = 0,
    HMAC_KEY1 = 1,
    HMAC_KEY2 = 2,
    HMAC_KEY3 = 3,
    HMAC_KEY4 = 4,
    HMAC_KEY5 = 5,
} hmac_key_id_t;

/* Query functions */
esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t block);
bool                esp_efuse_key_block_unused(esp_efuse_block_t block);

/* Write / protect functions */
esp_err_t esp_efuse_write_key(esp_efuse_block_t block,
                               esp_efuse_purpose_t purpose,
                               const void *key, size_t key_size);
esp_err_t esp_efuse_set_key_dis_read(esp_efuse_block_t block);
esp_err_t esp_efuse_set_key_dis_write(esp_efuse_block_t block);
