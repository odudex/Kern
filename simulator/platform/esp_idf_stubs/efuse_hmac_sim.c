/*
 * eFuse and HMAC simulator stubs
 *
 * Simulates eFuse KEY5 as "always provisioned for HMAC_UP".
 * HMAC computation uses mbedTLS HMAC-SHA256 with a deterministic test key.
 */

#include "esp_efuse.h"
#include "esp_hmac.h"
#include <mbedtls/md.h>
#include <string.h>

/* 32-byte deterministic test key — stable across simulator restarts */
static const uint8_t SIM_HMAC_KEY[32] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
};

/* KEY5 state — starts as provisioned so pin.c uses HMAC path by default */
static bool               s_key5_provisioned = true;
static esp_efuse_purpose_t s_key5_purpose     = ESP_EFUSE_KEY_PURPOSE_HMAC_UP;

/* -------------------------------------------------------------------------- */
/* eFuse stubs                                                                 */
/* -------------------------------------------------------------------------- */

esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t block) {
    if (block == EFUSE_BLK_KEY5)
        return s_key5_provisioned ? s_key5_purpose : ESP_EFUSE_KEY_PURPOSE_USER;
    return ESP_EFUSE_KEY_PURPOSE_USER;
}

bool esp_efuse_key_block_unused(esp_efuse_block_t block) {
    if (block == EFUSE_BLK_KEY5)
        return !s_key5_provisioned;
    return true;
}

esp_err_t esp_efuse_write_key(esp_efuse_block_t block,
                               esp_efuse_purpose_t purpose,
                               const void *key, size_t key_size) {
    (void)key;
    (void)key_size;
    if (block == EFUSE_BLK_KEY5) {
        s_key5_purpose     = purpose;
        s_key5_provisioned = true;
    }
    return ESP_OK;
}

esp_err_t esp_efuse_set_key_dis_read(esp_efuse_block_t block) {
    (void)block;
    return ESP_OK; /* No-op in simulator */
}

esp_err_t esp_efuse_set_key_dis_write(esp_efuse_block_t block) {
    (void)block;
    return ESP_OK; /* No-op in simulator */
}

/* -------------------------------------------------------------------------- */
/* HMAC stub                                                                   */
/* -------------------------------------------------------------------------- */

esp_err_t esp_hmac_calculate(hmac_key_id_t key_id,
                              const void *message, size_t message_len,
                              uint8_t *hmac) {
    (void)key_id;
    if (!message || !hmac) return ESP_ERR_INVALID_ARG;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return ESP_FAIL;

    int ret = mbedtls_md_hmac(md,
                               SIM_HMAC_KEY, sizeof(SIM_HMAC_KEY),
                               (const unsigned char *)message, message_len,
                               (unsigned char *)hmac);
    return (ret == 0) ? ESP_OK : ESP_FAIL;
}
