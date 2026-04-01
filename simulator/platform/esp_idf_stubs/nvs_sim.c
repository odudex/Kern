/*
 * File-backed NVS simulator
 *
 * Each namespace is stored as a binary file:
 *   simulator/sim_data/nvs/<namespace>.nvs
 *
 * File format — sequence of entries:
 *   [key_len : 1 byte][key : key_len bytes][type : 1 byte]
 *   [value_len_lo : 1 byte][value_len_hi : 1 byte][value : value_len bytes]
 *
 * Types: 0x01 = u8, 0x02 = u16, 0x03 = blob
 */

#include "nvs.h"
#include "nvs_flash.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef NVS_DATA_DIR
#define NVS_DATA_DIR "simulator/sim_data/nvs"
#endif

static char *s_nvs_dir_override = NULL;

void sim_nvs_set_data_dir(const char *dir) {
    free(s_nvs_dir_override);
    s_nvs_dir_override = dir ? strdup(dir) : NULL;
}

static const char *nvs_dir(void) {
    return s_nvs_dir_override ? s_nvs_dir_override : NVS_DATA_DIR;
}

#define NVS_MAX_HANDLES  16
#define NVS_MAX_KEY_LEN  15
#define NVS_TYPE_U8      0x01
#define NVS_TYPE_U16     0x02
#define NVS_TYPE_BLOB    0x03

/* -------------------------------------------------------------------------- */
/* In-memory key-value list                                                    */
/* -------------------------------------------------------------------------- */

typedef struct nvs_entry {
    char              key[NVS_MAX_KEY_LEN + 1];
    uint8_t           type;
    uint16_t          value_len;
    uint8_t          *value;
    struct nvs_entry *next;
} nvs_entry_t;

typedef struct {
    bool             used;
    char             ns[16];
    char             filepath[256];
    int              dirty;
    nvs_open_mode_t  mode;
    nvs_entry_t     *entries;
} nvs_handle_impl_t;

static nvs_handle_impl_t s_handles[NVS_MAX_HANDLES];

/* -------------------------------------------------------------------------- */
/* Directory helpers                                                           */
/* -------------------------------------------------------------------------- */

static void ensure_dir(const char *path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char save = tmp[i];
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = save;
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Entry list management                                                       */
/* -------------------------------------------------------------------------- */

static nvs_entry_t *find_entry(nvs_handle_impl_t *h, const char *key) {
    for (nvs_entry_t *e = h->entries; e; e = e->next) {
        if (strncmp(e->key, key, NVS_MAX_KEY_LEN) == 0)
            return e;
    }
    return NULL;
}

static void free_entries(nvs_handle_impl_t *h) {
    nvs_entry_t *e = h->entries;
    while (e) {
        nvs_entry_t *next = e->next;
        free(e->value);
        free(e);
        e = next;
    }
    h->entries = NULL;
}

/* -------------------------------------------------------------------------- */
/* Persistence                                                                 */
/* -------------------------------------------------------------------------- */

static void load_from_file(nvs_handle_impl_t *h) {
    free_entries(h);
    FILE *f = fopen(h->filepath, "rb");
    if (!f) return; /* File doesn't exist yet — empty namespace */

    nvs_entry_t **tail = &h->entries;
    uint8_t key_len;
    while (fread(&key_len, 1, 1, f) == 1) {
        if (key_len == 0 || key_len > NVS_MAX_KEY_LEN) break;
        nvs_entry_t *e = calloc(1, sizeof(nvs_entry_t));
        if (!e) break;
        if (fread(e->key, 1, key_len, f) != key_len) { free(e); break; }
        e->key[key_len] = '\0';
        if (fread(&e->type, 1, 1, f) != 1) { free(e); break; }
        uint8_t vlo, vhi;
        if (fread(&vlo, 1, 1, f) != 1 || fread(&vhi, 1, 1, f) != 1) {
            free(e); break;
        }
        e->value_len = (uint16_t)vlo | ((uint16_t)vhi << 8);
        e->value = malloc(e->value_len ? e->value_len : 1);
        if (!e->value) { free(e); break; }
        if (e->value_len > 0 &&
            fread(e->value, 1, e->value_len, f) != e->value_len) {
            free(e->value); free(e); break;
        }
        *tail = e;
        tail = &e->next;
    }
    fclose(f);
}

static void save_to_file(nvs_handle_impl_t *h) {
    FILE *f = fopen(h->filepath, "wb");
    if (!f) return;
    for (nvs_entry_t *e = h->entries; e; e = e->next) {
        uint8_t klen = (uint8_t)strlen(e->key);
        fwrite(&klen, 1, 1, f);
        fwrite(e->key, 1, klen, f);
        fwrite(&e->type, 1, 1, f);
        uint8_t vlo = e->value_len & 0xFF;
        uint8_t vhi = (e->value_len >> 8) & 0xFF;
        fwrite(&vlo, 1, 1, f);
        fwrite(&vhi, 1, 1, f);
        if (e->value_len > 0)
            fwrite(e->value, 1, e->value_len, f);
    }
    fclose(f);
    h->dirty = 0;
}

/* -------------------------------------------------------------------------- */
/* Flash init / erase                                                          */
/* -------------------------------------------------------------------------- */

esp_err_t nvs_flash_init(void) {
    ensure_dir(nvs_dir());
    return ESP_OK;
}

esp_err_t nvs_flash_erase(void) {
    for (int i = 0; i < NVS_MAX_HANDLES; i++) {
        if (s_handles[i].used) {
            free_entries(&s_handles[i]);
            s_handles[i].used = false;
        }
    }
    DIR *d = opendir(nvs_dir());
    if (!d) return ESP_OK;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen > 4 && strcmp(ent->d_name + nlen - 4, ".nvs") == 0) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", nvs_dir(), ent->d_name);
            unlink(path);
        }
    }
    closedir(d);
    return ESP_OK;
}

/* -------------------------------------------------------------------------- */
/* Open / close                                                                */
/* -------------------------------------------------------------------------- */

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t open_mode,
                   nvs_handle_t *out_handle) {
    if (!namespace_name || !out_handle) return ESP_ERR_INVALID_ARG;

    int idx = -1;
    for (int i = 0; i < NVS_MAX_HANDLES; i++) {
        if (!s_handles[i].used) { idx = i; break; }
    }
    if (idx < 0) return ESP_ERR_NVS_INVALID_HANDLE;

    nvs_handle_impl_t *h = &s_handles[idx];
    memset(h, 0, sizeof(*h));
    strncpy(h->ns, namespace_name, sizeof(h->ns) - 1);
    h->mode = open_mode;
    h->used = true;
    snprintf(h->filepath, sizeof(h->filepath), "%s/%s.nvs",
             nvs_dir(), namespace_name);

    load_from_file(h);

    *out_handle = (nvs_handle_t)(idx + 1); /* 1-based index */
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle) {
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used) return;
    nvs_handle_impl_t *h = &s_handles[idx];
    if (h->dirty) save_to_file(h);
    free_entries(h);
    h->used = false;
}

/* -------------------------------------------------------------------------- */
/* Commit / erase                                                              */
/* -------------------------------------------------------------------------- */

esp_err_t nvs_commit(nvs_handle_t handle) {
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    save_to_file(&s_handles[idx]);
    return ESP_OK;
}

esp_err_t nvs_erase_all(nvs_handle_t handle) {
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    free_entries(&s_handles[idx]);
    s_handles[idx].dirty = 1;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char *key) {
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    if (!key) return ESP_ERR_INVALID_ARG;
    nvs_handle_impl_t *h = &s_handles[idx];
    nvs_entry_t **prev = &h->entries;
    for (nvs_entry_t *e = h->entries; e; e = e->next) {
        if (strncmp(e->key, key, NVS_MAX_KEY_LEN) == 0) {
            *prev = e->next;
            free(e->value);
            free(e);
            h->dirty = 1;
            return ESP_OK;
        }
        prev = &e->next;
    }
    return ESP_ERR_NVS_NOT_FOUND;
}

/* -------------------------------------------------------------------------- */
/* Generic set / get helpers                                                   */
/* -------------------------------------------------------------------------- */

static esp_err_t nvs_set_raw(nvs_handle_t handle, const char *key, uint8_t type,
                              const uint8_t *val, uint16_t len) {
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    if (!key || !val) return ESP_ERR_INVALID_ARG;
    nvs_handle_impl_t *h = &s_handles[idx];

    nvs_entry_t *e = find_entry(h, key);
    if (e) {
        uint8_t *newval = malloc(len ? len : 1);
        if (!newval) return ESP_ERR_NO_MEM;
        free(e->value);
        e->value     = newval;
        e->value_len = len;
        e->type      = type;
        if (len) memcpy(e->value, val, len);
    } else {
        e = calloc(1, sizeof(nvs_entry_t));
        if (!e) return ESP_ERR_NO_MEM;
        strncpy(e->key, key, NVS_MAX_KEY_LEN);
        e->type      = type;
        e->value_len = len;
        e->value     = malloc(len ? len : 1);
        if (!e->value) { free(e); return ESP_ERR_NO_MEM; }
        if (len) memcpy(e->value, val, len);
        /* Append to tail */
        nvs_entry_t **tail = &h->entries;
        while (*tail) tail = &(*tail)->next;
        *tail = e;
    }
    h->dirty = 1;
    return ESP_OK;
}

/* -------------------------------------------------------------------------- */
/* Typed setters                                                               */
/* -------------------------------------------------------------------------- */

esp_err_t nvs_set_u8(nvs_handle_t handle, const char *key, uint8_t value) {
    return nvs_set_raw(handle, key, NVS_TYPE_U8, &value, 1);
}

esp_err_t nvs_set_u16(nvs_handle_t handle, const char *key, uint16_t value) {
    uint8_t buf[2] = { (uint8_t)(value & 0xFF), (uint8_t)((value >> 8) & 0xFF) };
    return nvs_set_raw(handle, key, NVS_TYPE_U16, buf, 2);
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value,
                       size_t length) {
    if (length > 65535) return ESP_ERR_INVALID_SIZE;
    return nvs_set_raw(handle, key, NVS_TYPE_BLOB, (const uint8_t *)value,
                       (uint16_t)length);
}

/* -------------------------------------------------------------------------- */
/* Typed getters                                                               */
/* -------------------------------------------------------------------------- */

esp_err_t nvs_get_u8(nvs_handle_t handle, const char *key, uint8_t *out_value) {
    if (!out_value) return ESP_ERR_INVALID_ARG;
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    if (!key) return ESP_ERR_INVALID_ARG;
    nvs_entry_t *e = find_entry(&s_handles[idx], key);
    if (!e) return ESP_ERR_NVS_NOT_FOUND;
    if (e->type != NVS_TYPE_U8 || e->value_len != 1) return ESP_FAIL;
    *out_value = e->value[0];
    return ESP_OK;
}

esp_err_t nvs_get_u16(nvs_handle_t handle, const char *key, uint16_t *out_value) {
    if (!out_value) return ESP_ERR_INVALID_ARG;
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    if (!key) return ESP_ERR_INVALID_ARG;
    nvs_entry_t *e = find_entry(&s_handles[idx], key);
    if (!e) return ESP_ERR_NVS_NOT_FOUND;
    if (e->type != NVS_TYPE_U16 || e->value_len != 2) return ESP_FAIL;
    *out_value = (uint16_t)e->value[0] | ((uint16_t)e->value[1] << 8);
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *out_value,
                       size_t *length) {
    if (!length) return ESP_ERR_INVALID_ARG;
    int idx = (int)handle - 1;
    if (idx < 0 || idx >= NVS_MAX_HANDLES || !s_handles[idx].used)
        return ESP_ERR_NVS_INVALID_HANDLE;
    if (!key) return ESP_ERR_INVALID_ARG;
    nvs_entry_t *e = find_entry(&s_handles[idx], key);
    if (!e) return ESP_ERR_NVS_NOT_FOUND;
    if (e->type != NVS_TYPE_BLOB) return ESP_FAIL;
    if (!out_value) {
        /* Size query */
        *length = e->value_len;
        return ESP_OK;
    }
    if (*length < e->value_len) {
        *length = e->value_len;
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(out_value, e->value, e->value_len);
    *length = e->value_len;
    return ESP_OK;
}
