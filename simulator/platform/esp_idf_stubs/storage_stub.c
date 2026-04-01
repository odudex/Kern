/*
 * Storage stub for desktop simulator
 *
 * The real firmware stores encrypted mnemonics and descriptors
 * in eFuse-protected flash (SPIFFS). The simulator has no
 * encrypted flash, so all storage operations are no-ops.
 * pin.c calls storage_init() and storage_wipe_flash().
 */

#include "core/storage.h"
#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "STORAGE_STUB";

esp_err_t storage_init(void) {
    return ESP_OK;
}

esp_err_t storage_wipe_flash(void) {
    ESP_LOGW(TAG, "storage_wipe_flash() called — stub, no-op in simulator");
    return ESP_OK;
}

/* No-op implementations for storage functions that require
 * encrypted flash not available in the desktop simulator. */

esp_err_t storage_save_mnemonic(storage_location_t loc, const char *id,
                                const uint8_t *kef, size_t len) {
    (void)loc; (void)id; (void)kef; (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t storage_load_mnemonic(storage_location_t loc, const char *filename,
                                uint8_t **out, size_t *len_out) {
    (void)loc; (void)filename; (void)out; (void)len_out;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t storage_list_mnemonics(storage_location_t loc, char ***names,
                                 int *count) {
    (void)loc;
    if (names)  *names = NULL;
    if (count)  *count = 0;
    return ESP_OK;
}

esp_err_t storage_delete_mnemonic(storage_location_t loc, const char *fn) {
    (void)loc; (void)fn;
    return ESP_ERR_NOT_FOUND;
}

bool storage_mnemonic_exists(storage_location_t loc, const char *id) {
    (void)loc; (void)id;
    return false;
}

void storage_sanitize_id(const char *raw, char *out, size_t out_size) {
    if (!raw || !out || out_size == 0) return;
    strncpy(out, raw, out_size - 1);
    out[out_size - 1] = '\0';
}

void storage_free_file_list(char **files, int count) {
    if (!files) return;
    for (int i = 0; i < count; i++) free(files[i]);
    free(files);
}

char *storage_get_kef_display_name(const uint8_t *data, size_t len) {
    (void)data; (void)len;
    return NULL;
}

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
    (void)loc; (void)id; (void)data; (void)len; (void)encrypted;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *fn,
                                  uint8_t **out, size_t *len_out,
                                  bool *encrypted_out) {
    (void)loc; (void)fn; (void)out; (void)len_out; (void)encrypted_out;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t storage_list_descriptors(storage_location_t loc, char ***names,
                                   int *count) {
    (void)loc;
    if (names)  *names = NULL;
    if (count)  *count = 0;
    return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc, const char *fn) {
    (void)loc; (void)fn;
    return ESP_ERR_NOT_FOUND;
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               bool encrypted) {
    (void)loc; (void)id; (void)encrypted;
    return false;
}
