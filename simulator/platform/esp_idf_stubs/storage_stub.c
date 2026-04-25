/*
 * Storage stub for desktop simulator
 *
 * Mnemonic storage stays no-op (the sim loads via QR each session).
 * Descriptor storage is file-backed under simulator/sim_data/descriptors/
 * so the registry persists across reboots — matching the real firmware's
 * SPIFFS-backed behaviour just enough for the §5/§9 register-and-test
 * flows. `just sim-reset` removes simulator/sim_data/ wholesale.
 */

#include "core/storage.h"
#include "esp_log.h"
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *TAG = "STORAGE_STUB";

#define DESC_DIR "simulator/sim_data/descriptors"

static esp_err_t ensure_desc_dir(void) {
    mkdir("simulator", 0775);
    mkdir("simulator/sim_data", 0775);
    if (mkdir(DESC_DIR, 0775) != 0) {
        struct stat st;
        if (stat(DESC_DIR, &st) != 0 || !S_ISDIR(st.st_mode))
            return ESP_FAIL;
    }
    return ESP_OK;
}

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
    /* Sim stores plaintext .txt only; the encrypted flag is accepted but
     * ignored (no KEF crypto path here). */
    (void)loc; (void)encrypted;
    if (!id || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (ensure_desc_dir() != ESP_OK) return ESP_FAIL;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s.txt", DESC_DIR, id);
    FILE *f = fopen(path, "wb");
    if (!f) return ESP_FAIL;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? ESP_OK : ESP_FAIL;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *fn,
                                  uint8_t **out, size_t *len_out,
                                  bool *encrypted_out) {
    (void)loc;
    if (!fn || !out || !len_out) return ESP_ERR_INVALID_ARG;
    *out = NULL;
    *len_out = 0;
    if (encrypted_out) *encrypted_out = false;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", DESC_DIR, fn);
    FILE *f = fopen(path, "rb");
    if (!f) return ESP_ERR_NOT_FOUND;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return ESP_FAIL; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return ESP_FAIL; }
    rewind(f);

    uint8_t *buf = malloc((size_t)size);
    if (!buf) { fclose(f); return ESP_ERR_NO_MEM; }

    size_t r = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (r != (size_t)size) { free(buf); return ESP_FAIL; }

    *out = buf;
    *len_out = (size_t)size;
    return ESP_OK;
}

esp_err_t storage_list_descriptors(storage_location_t loc, char ***names,
                                   int *count) {
    (void)loc;
    if (!names || !count) return ESP_ERR_INVALID_ARG;
    *names = NULL;
    *count = 0;

    DIR *d = opendir(DESC_DIR);
    if (!d) return ESP_OK; /* no dir yet → empty list */

    char **list = NULL;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        size_t nl = strlen(e->d_name);
        if (nl < 4 || strcmp(e->d_name + nl - 4, ".txt") != 0) continue;

        char **tmp = realloc(list, (size_t)(n + 1) * sizeof(char *));
        if (!tmp) { storage_free_file_list(list, n); closedir(d); return ESP_ERR_NO_MEM; }
        list = tmp;
        list[n] = strdup(e->d_name);
        if (!list[n]) { storage_free_file_list(list, n); closedir(d); return ESP_ERR_NO_MEM; }
        n++;
    }
    closedir(d);

    *names = list;
    *count = n;
    return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc, const char *fn) {
    (void)loc;
    if (!fn) return ESP_ERR_INVALID_ARG;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", DESC_DIR, fn);
    return (unlink(path) == 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               bool encrypted) {
    (void)loc; (void)encrypted;
    if (!id) return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.txt", DESC_DIR, id);
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}
