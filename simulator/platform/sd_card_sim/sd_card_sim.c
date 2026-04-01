/**
 * SD Card Simulator — maps sd_card.h API to POSIX filesystem under sim_data/sdcard/
 */

#include "sd_card.h"
#include "esp_log.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *TAG = "SD_SIM";

static bool s_mounted = false;

static char *s_sdcard_root_override = NULL;

void sim_sdcard_set_data_dir(const char *dir) {
    free(s_sdcard_root_override);
    s_sdcard_root_override = dir ? strdup(dir) : NULL;
}

static const char *sdcard_root(void) {
    return s_sdcard_root_override ? s_sdcard_root_override : SD_CARD_MOUNT_POINT;
}

/* If s_sdcard_root_override is set and path starts with SD_CARD_MOUNT_POINT,
 * rewrite path into buf replacing that prefix with s_sdcard_root_override.
 * Returns a pointer to the (possibly rewritten) path to use. */
static const char *rewrite_path(const char *path, char *buf, size_t bufsz) {
    if (s_sdcard_root_override) {
        size_t mlen = strlen(SD_CARD_MOUNT_POINT);
        if (strncmp(path, SD_CARD_MOUNT_POINT, mlen) == 0) {
            snprintf(buf, bufsz, "%s%s", s_sdcard_root_override, path + mlen);
            return buf;
        }
    }
    return path;
}

/* Create a directory path recursively, ignoring EEXIST */
static void mkdir_p(const char *path) {
    char tmp[256];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

esp_err_t sd_card_init(void) {
    if (s_mounted) return ESP_OK;
    const char *root = sdcard_root();
    char path[512];
    snprintf(path, sizeof(path), "%s/kern/mnemonics", root);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/kern/descriptors", root);
    mkdir_p(path);
    s_mounted = true;
    ESP_LOGI(TAG, "SD card simulator initialized at %s", root);
    return ESP_OK;
}

esp_err_t sd_card_deinit(void) {
    s_mounted = false;
    return ESP_OK;
}

bool sd_card_is_mounted(void) {
    return s_mounted;
}

esp_err_t sd_card_write_file(const char *path, const uint8_t *data, size_t len) {
    if (!path || !data) return ESP_ERR_INVALID_ARG;
    char buf[1024];
    const char *rpath = rewrite_path(path, buf, sizeof(buf));
    FILE *f = fopen(rpath, "wb");
    if (!f) {
        ESP_LOGE(TAG, "write_file: cannot open %s: %s", rpath, strerror(errno));
        return ESP_FAIL;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? ESP_OK : ESP_FAIL;
}

esp_err_t sd_card_read_file(const char *path, uint8_t **data_out, size_t *len_out) {
    if (!path || !data_out || !len_out) return ESP_ERR_INVALID_ARG;
    char pathbuf[1024];
    const char *rpath = rewrite_path(path, pathbuf, sizeof(pathbuf));
    FILE *f = fopen(rpath, "rb");
    if (!f) return ESP_ERR_NOT_FOUND;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return ESP_ERR_INVALID_SIZE; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return ESP_ERR_NO_MEM; }
    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *data_out = buf;
    *len_out = nread;
    return ESP_OK;
}

esp_err_t sd_card_file_exists(const char *path, bool *exists) {
    if (!path || !exists) return ESP_ERR_INVALID_ARG;
    char buf[1024];
    const char *rpath = rewrite_path(path, buf, sizeof(buf));
    *exists = (access(rpath, F_OK) == 0);
    return ESP_OK;
}

esp_err_t sd_card_delete_file(const char *path) {
    if (!path) return ESP_ERR_INVALID_ARG;
    char buf[1024];
    const char *rpath = rewrite_path(path, buf, sizeof(buf));
    return (remove(rpath) == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out, int *count_out) {
    if (!dir_path || !files_out || !count_out) return ESP_ERR_INVALID_ARG;
    *files_out = NULL;
    *count_out = 0;

    char buf[1024];
    const char *rpath = rewrite_path(dir_path, buf, sizeof(buf));
    DIR *d = opendir(rpath);
    if (!d) return ESP_OK; /* directory doesn't exist → empty list */

    char **files = NULL;
    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue; /* skip . and .. */
        char **tmp = realloc(files, (size_t)(count + 1) * sizeof(char *));
        if (!tmp) {
            sd_card_free_file_list(files, count);
            closedir(d);
            return ESP_ERR_NO_MEM;
        }
        files = tmp;
        files[count] = strdup(entry->d_name);
        if (!files[count]) {
            sd_card_free_file_list(files, count);
            closedir(d);
            return ESP_ERR_NO_MEM;
        }
        count++;
    }
    closedir(d);
    *files_out = files;
    *count_out = count;
    return ESP_OK;
}

void sd_card_free_file_list(char **files, int count) {
    if (!files) return;
    for (int i = 0; i < count; i++) free(files[i]);
    free(files);
}
