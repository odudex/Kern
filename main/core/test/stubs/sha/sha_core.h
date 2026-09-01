/* Host stand-in for the ESP-IDF SHA peripheral API; the test implements
 * these in software (see test_pbkdf2.c). */
#pragma once
#include <hal/sha_types.h>
#include <stdbool.h>

void esp_sha_set_mode(esp_sha_type sha_type);
void esp_sha_block(esp_sha_type sha_type, const void *data_block,
                   bool is_first_block);
void esp_sha_read_digest_state(esp_sha_type sha_type, void *digest_state);
void esp_sha_write_digest_state(esp_sha_type sha_type, void *digest_state);
void esp_sha_acquire_hardware(void);
void esp_sha_release_hardware(void);
