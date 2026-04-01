#pragma once

#include "esp_err.h"
#include "esp_efuse.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Compute HMAC using the key stored in eFuse KEY<key_id>.
 *
 * Simulator: uses a hardcoded 32-byte test key with mbedTLS HMAC-SHA256.
 *
 * @param key_id     eFuse key slot (HMAC_KEY0..HMAC_KEY5)
 * @param message    Input message
 * @param message_len Length of message
 * @param hmac       Output buffer — must be at least 32 bytes
 * @return ESP_OK on success
 */
esp_err_t esp_hmac_calculate(hmac_key_id_t key_id,
                              const void *message, size_t message_len,
                              uint8_t *hmac);
