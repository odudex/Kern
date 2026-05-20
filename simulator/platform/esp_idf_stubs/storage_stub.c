/*
 * Storage stub for desktop simulator
 *
 * Mnemonic storage stays no-op (the sim loads via QR each session).
 * Descriptor storage is file-backed under simulator/sim_data/{spiffs,sd}/
 * so the registry persists across reboots — matching the real firmware's
 * two-location split (SPIFFS vs SD) so that registry_init's per-location
 * scan doesn't double-load the same file.
 *
 * Layout mirrors the real firmware paths from main/core/storage.h:
 *   STORAGE_FLASH → simulator/sim_data/spiffs/<id>.txt
 *   STORAGE_SD    → simulator/sim_data/sd/kern/descriptors/<id>.txt
 *
 * `just sim-reset` removes simulator/sim_data/ wholesale.
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

#define DESC_DIR_FLASH "simulator/sim_data/spiffs"
#define DESC_DIR_SD    "simulator/sim_data/sd/kern/descriptors"

static const char *desc_dir_for(storage_location_t loc) {
    return (loc == STORAGE_FLASH) ? DESC_DIR_FLASH : DESC_DIR_SD;
}

static esp_err_t mkdir_p(const char *path) {
    /* Best-effort recursive mkdir, mirroring `mkdir -p`. Ignores
     * EEXIST. Returns ESP_OK iff the final path is a directory. */
    char buf[256];
    size_t n = strlen(path);
    if (n >= sizeof(buf)) return ESP_ERR_INVALID_ARG;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] == '/') {
            buf[i] = '\0';
            mkdir(buf, 0775);
            buf[i] = '/';
        }
    }
    mkdir(buf, 0775);
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return ESP_FAIL;
    return ESP_OK;
}

static esp_err_t ensure_desc_dir(storage_location_t loc) {
    return mkdir_p(desc_dir_for(loc));
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
    (void)encrypted;
    if (!id || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (ensure_desc_dir(loc) != ESP_OK) return ESP_FAIL;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s.txt", desc_dir_for(loc), id);
    FILE *f = fopen(path, "wb");
    if (!f) return ESP_FAIL;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? ESP_OK : ESP_FAIL;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *fn,
                                  uint8_t **out, size_t *len_out,
                                  bool *encrypted_out) {
    if (!fn || !out || !len_out) return ESP_ERR_INVALID_ARG;
    *out = NULL;
    *len_out = 0;
    if (encrypted_out) *encrypted_out = false;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", desc_dir_for(loc), fn);
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
    if (!names || !count) return ESP_ERR_INVALID_ARG;
    *names = NULL;
    *count = 0;

    DIR *d = opendir(desc_dir_for(loc));
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
    if (!fn) return ESP_ERR_INVALID_ARG;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", desc_dir_for(loc), fn);
    return (unlink(path) == 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               bool encrypted) {
    (void)encrypted;
    if (!id) return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.txt", desc_dir_for(loc), id);
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}
