/**
 * ESP-IDF stub implementations for Kern Desktop Simulator
 */

#include "esp_err.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_spiffs.h"
#include "esp_app_desc.h"
#include "driver/ppa.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

const char *esp_err_to_name(esp_err_t code) {
    switch (code) {
        case ESP_OK:                        return "ESP_OK";
        case ESP_FAIL:                      return "ESP_FAIL";
        case ESP_ERR_NO_MEM:                return "ESP_ERR_NO_MEM";
        case ESP_ERR_INVALID_ARG:           return "ESP_ERR_INVALID_ARG";
        case ESP_ERR_INVALID_STATE:         return "ESP_ERR_INVALID_STATE";
        case ESP_ERR_INVALID_SIZE:          return "ESP_ERR_INVALID_SIZE";
        case ESP_ERR_NOT_FOUND:             return "ESP_ERR_NOT_FOUND";
        case ESP_ERR_NOT_SUPPORTED:         return "ESP_ERR_NOT_SUPPORTED";
        case ESP_ERR_TIMEOUT:               return "ESP_ERR_TIMEOUT";
        case ESP_ERR_NVS_NOT_FOUND:         return "ESP_ERR_NVS_NOT_FOUND";
        case ESP_ERR_NVS_NO_FREE_PAGES:     return "ESP_ERR_NVS_NO_FREE_PAGES";
        case ESP_ERR_NVS_INVALID_HANDLE:    return "ESP_ERR_NVS_INVALID_HANDLE";
        case ESP_ERR_NVS_NEW_VERSION_FOUND: return "ESP_ERR_NVS_NEW_VERSION_FOUND";
        default:                            return "UNKNOWN_ERROR";
    }
}

/* --- esp_random --- */

uint32_t esp_random(void) {
    uint32_t val = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)fread(&val, sizeof(val), 1, f);
        fclose(f);
    } else {
        val = (uint32_t)rand();
    }
    return val;
}

void esp_fill_random(void *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)fread(buf, 1, len, f);
        fclose(f);
    } else {
        uint8_t *p = (uint8_t *)buf;
        for (size_t i = 0; i < len; i++) p[i] = (uint8_t)rand();
    }
}

/* --- esp_system --- */

void esp_restart(void) {
    fprintf(stderr, "[SIM] esp_restart() called — exiting\n");
    exit(1);
}

void esp_chip_info(esp_chip_info_t *out_info) {
    out_info->model    = CHIP_ESP32P4;
    out_info->revision = 0;
    out_info->cores    = 2;
    out_info->features = 0;
}

uint32_t esp_get_free_heap_size(void) {
    return 4 * 1024 * 1024;
}

uint32_t esp_get_minimum_free_heap_size(void) {
    return 1 * 1024 * 1024;
}

/* --- esp_timer --- */

int64_t esp_timer_get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000);
}

struct sim_esp_timer {
    esp_timer_cb_t callback;
    void          *arg;
};

esp_err_t esp_timer_create(const esp_timer_create_args_t *args,
                            esp_timer_handle_t *out_handle) {
    struct sim_esp_timer *t = malloc(sizeof(*t));
    if (!t) return ESP_ERR_NO_MEM;
    t->callback  = args->callback;
    t->arg       = args->arg;
    *out_handle  = t;
    return ESP_OK;
}

esp_err_t esp_timer_start_once(esp_timer_handle_t timer, uint64_t timeout_us) {
    (void)timer; (void)timeout_us;
    return ESP_OK;
}

esp_err_t esp_timer_start_periodic(esp_timer_handle_t timer, uint64_t period_us) {
    (void)timer; (void)period_us;
    return ESP_OK;
}

esp_err_t esp_timer_stop(esp_timer_handle_t timer) {
    (void)timer;
    return ESP_OK;
}

esp_err_t esp_timer_delete(esp_timer_handle_t timer) {
    free(timer);
    return ESP_OK;
}

/* --- PPA (Pixel Processing Accelerator) --- */

esp_err_t ppa_register_client(const ppa_client_config_t *config,
                               ppa_client_handle_t *ret_client) {
    (void)config;
    static int s_dummy = 0;
    if (ret_client) *ret_client = &s_dummy;
    return ESP_OK;
}

esp_err_t ppa_unregister_client(ppa_client_handle_t client) {
    (void)client;
    return ESP_OK;
}

esp_err_t ppa_do_scale_rotate_mirror(ppa_client_handle_t client,
                                      const ppa_srm_oper_config_t *config) {
    (void)client;
    if (!config) return ESP_ERR_INVALID_ARG;
    size_t copy_len = config->in.block_w * config->in.block_h * 2;
    if (copy_len > config->out.buffer_size) copy_len = config->out.buffer_size;
    if (config->out.buffer && config->in.buffer)
        memcpy(config->out.buffer, config->in.buffer, copy_len);
    return ESP_OK;
}

/* --- SPIFFS --- */

esp_err_t esp_vfs_spiffs_register(const esp_vfs_spiffs_conf_t *conf) {
    if (!conf || !conf->base_path) return ESP_ERR_INVALID_ARG;
    /* Create the directory tree so POSIX file ops work */
    struct stat st;
    if (stat(conf->base_path, &st) != 0) {
        mkdir(conf->base_path, 0755);
    }
    return ESP_OK;
}

esp_err_t esp_vfs_spiffs_unregister(const char *partition_label) {
    (void)partition_label;
    return ESP_OK;
}

bool esp_spiffs_check(const char *partition_label) {
    (void)partition_label;
    return true;
}

/* --- App description --- */

const esp_app_desc_t *esp_app_get_description(void) {
    static const esp_app_desc_t s_desc = {
        .version      = "sim-dev",
        .project_name = "kern_simulator",
        .idf_ver      = "v5.4-sim",
        .app_elf_sha256 = {0},
    };
    return &s_desc;
}
