#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#define SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS 3
#define ESP_SECURE_BOOT_KEY_DIGEST_SHA_256_LEN 32

/* Opaque on the host: the firmware only ever passes a pointer through. */
typedef struct {
  uint8_t raw[4096];
} ets_secure_boot_signature_t;

typedef struct {
  uint8_t key_digests[SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS]
                     [ESP_SECURE_BOOT_KEY_DIGEST_SHA_256_LEN];
  unsigned num_digests;
} esp_image_sig_public_key_digests_t;

bool esp_secure_boot_enabled(void);
esp_err_t esp_secure_boot_get_signature_blocks_for_running_app(
    bool digest_public_keys,
    esp_image_sig_public_key_digests_t *public_key_digests);
esp_err_t esp_secure_boot_verify_sbv2_signature_block(
    const ets_secure_boot_signature_t *sig_block, const uint8_t *image_digest,
    uint8_t *verified_digest);
