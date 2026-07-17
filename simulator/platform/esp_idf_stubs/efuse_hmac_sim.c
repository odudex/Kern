/*
 * eFuse and HMAC simulator stubs
 *
 * Simulates eFuse KEY5 as "always provisioned for HMAC_UP".
 * HMAC computation uses mbedTLS HMAC-SHA256 with a deterministic test key.
 */

#include "esp_efuse.h"
#include "esp_hmac.h"
#include "sim_nvs.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

/* 32-byte deterministic test key — stable across simulator restarts */
static const uint8_t SIM_HMAC_KEY[32] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
};

/* Per-block state. KEY5 starts provisioned so pin.c uses the HMAC path by
 * default; KEY4 starts unprovisioned so the NVS-encryption consent flow in
 * PIN setup is exercisable in the simulator. Burns persist to
 * <nvs-data-dir>/efuse.sim, which nvs_flash_erase() does not remove — burned
 * blocks survive an NVS wipe, matching real eFuse semantics. */
#define SIM_EFUSE_BLOCKS 6
static bool s_provisioned[SIM_EFUSE_BLOCKS] = {
    [EFUSE_BLK_KEY5] = true,
};
static esp_efuse_purpose_t s_purpose[SIM_EFUSE_BLOCKS] = {
    [EFUSE_BLK_KEY5] = ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
};
static bool s_loaded = false;

static void efuse_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/efuse.sim", sim_nvs_get_data_dir());
}

static void efuse_load(void) {
    if (s_loaded)
        return;
    s_loaded = true;
    char path[512];
    efuse_path(path, sizeof(path));
    FILE *f = fopen(path, "rb");
    if (!f)
        return;
    if (fread(s_provisioned, sizeof(s_provisioned[0]), SIM_EFUSE_BLOCKS, f) ==
        SIM_EFUSE_BLOCKS)
        fread(s_purpose, sizeof(s_purpose[0]), SIM_EFUSE_BLOCKS, f);
    fclose(f);
}

static void efuse_save(void) {
    char path[512];
    efuse_path(path, sizeof(path));
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fwrite(s_provisioned, sizeof(s_provisioned[0]), SIM_EFUSE_BLOCKS, f);
    fwrite(s_purpose, sizeof(s_purpose[0]), SIM_EFUSE_BLOCKS, f);
    fclose(f);
}

/* -------------------------------------------------------------------------- */
/* eFuse stubs                                                                 */
/* -------------------------------------------------------------------------- */

esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t block) {
    efuse_load();
    if (block >= 0 && block < SIM_EFUSE_BLOCKS && s_provisioned[block])
        return s_purpose[block];
    return ESP_EFUSE_KEY_PURPOSE_USER;
}

bool esp_efuse_key_block_unused(esp_efuse_block_t block) {
    efuse_load();
    if (block >= 0 && block < SIM_EFUSE_BLOCKS)
        return !s_provisioned[block];
    return true;
}

esp_err_t esp_efuse_write_key(esp_efuse_block_t block,
                               esp_efuse_purpose_t purpose,
                               const void *key, size_t key_size) {
    (void)key;
    (void)key_size;
    efuse_load();
    if (block >= 0 && block < SIM_EFUSE_BLOCKS) {
        s_purpose[block]     = purpose;
        s_provisioned[block] = true;
        efuse_save();
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
