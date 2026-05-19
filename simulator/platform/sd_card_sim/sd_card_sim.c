/**
 * SD Card Simulator — maps /sdcard paths to POSIX filesystem under
 * simulator/sim_data/sdcard/
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

#define SIM_SDCARD_DEFAULT_ROOT "simulator/sim_data/sdcard"

static bool s_mounted = false;

static char *s_sdcard_root_override = NULL;

void sim_sdcard_set_data_dir(const char *dir) {
    free(s_sdcard_root_override);
    s_sdcard_root_override = dir ? strdup(dir) : NULL;
}

static const char *sdcard_root(void) {
    return s_sdcard_root_override ? s_sdcard_root_override : SIM_SDCARD_DEFAULT_ROOT;
}

/* Reject any path containing a ".." component — the simulator's SD root is
 * a real directory on the host, so a traversal would escape into the user's
 * filesystem.  Returns true if the path is safe. */
static bool path_is_safe(const char *path) {
    if (!path) return false;
    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '\0' || p[2] == '/') &&
            (p == path || p[-1] == '/')) {
            return false;
        }
        p++;
    }
    return true;
}

/* Rewrite paths under the firmware mount point into the simulator root.
 * Returns a pointer to the (possibly rewritten) path to use, or NULL if the
 * path contains a traversal component. */
static const char *rewrite_path(const char *path, char *buf, size_t bufsz) {
    if (!path_is_safe(path)) {
        ESP_LOGE(TAG, "rejected unsafe path: %s", path ? path : "(null)");
        return NULL;
    }
    size_t mlen = strlen(SD_CARD_MOUNT_POINT);
    if (strncmp(path, SD_CARD_MOUNT_POINT, mlen) == 0 &&
        (path[mlen] == '\0' || path[mlen] == '/')) {
        int n = snprintf(buf, bufsz, "%s%s", sdcard_root(), path + mlen);
        if (n < 0 || (size_t)n >= bufsz) return NULL;
        return buf;
    }

    size_t rlen = strlen(sdcard_root());
    if (strncmp(path, sdcard_root(), rlen) == 0 &&
        (path[rlen] == '\0' || path[rlen] == '/')) {
        return path;
    }

    ESP_LOGE(TAG, "rejected path outside simulated SD root: %s", path);
    return NULL;
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
    if (!rpath) return ESP_ERR_INVALID_ARG;
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
    if (!rpath) return ESP_ERR_INVALID_ARG;
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
    if (!rpath) { *exists = false; return ESP_ERR_INVALID_ARG; }
    *exists = (access(rpath, F_OK) == 0);
    return ESP_OK;
}

esp_err_t sd_card_delete_file(const char *path) {
    if (!path) return ESP_ERR_INVALID_ARG;
    char buf[1024];
    const char *rpath = rewrite_path(path, buf, sizeof(buf));
    if (!rpath) return ESP_ERR_INVALID_ARG;
    return (remove(rpath) == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out, int *count_out) {
    if (!dir_path || !files_out || !count_out) return ESP_ERR_INVALID_ARG;
    *files_out = NULL;
    *count_out = 0;

    char buf[1024];
    const char *rpath = rewrite_path(dir_path, buf, sizeof(buf));
    if (!rpath) return ESP_ERR_INVALID_ARG;
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
