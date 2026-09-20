/**
 * ESP-IDF stub implementations for Kern Desktop Simulator
 */

#include "esp_err.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_spiffs.h"
#include "esp_app_desc.h"
#include "esp_mac.h"
#include "sim_flash.h"
#include "driver/ppa.h"
#include <errno.h>
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
        case ESP_ERR_INVALID_RESPONSE:      return "ESP_ERR_INVALID_RESPONSE";
        case ESP_ERR_NVS_NOT_FOUND:         return "ESP_ERR_NVS_NOT_FOUND";
        case ESP_ERR_NVS_NO_FREE_PAGES:     return "ESP_ERR_NVS_NO_FREE_PAGES";
        case ESP_ERR_NVS_INVALID_HANDLE:    return "ESP_ERR_NVS_INVALID_HANDLE";
        case ESP_ERR_NVS_NEW_VERSION_FOUND: return "ESP_ERR_NVS_NEW_VERSION_FOUND";
        default:                            return "UNKNOWN_ERROR";
    }
}

/* --- esp_random ---
 *
 * The simulator MUST never fall back to libc rand() — that would silently
 * produce predictable bytes for mnemonic generation, nonces, and entropy.
 * /dev/urandom is opened once at first use; any failure (or short read) is
 * a hard abort.
 */

#include <fcntl.h>

static int s_urandom_fd = -1;

static void urandom_init_or_die(void) {
    if (s_urandom_fd >= 0) return;
    s_urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (s_urandom_fd < 0) {
        fprintf(stderr,
            "[SIM] FATAL: cannot open /dev/urandom (%s). Refusing to use a "
            "weaker entropy source.\n", strerror(errno));
        abort();
    }
}

static void urandom_read_or_die(void *buf, size_t len) {
    urandom_init_or_die();
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(s_urandom_fd, p, len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            fprintf(stderr,
                "[SIM] FATAL: short read from /dev/urandom (%zd): %s\n",
                n, strerror(errno));
            abort();
        }
        p   += (size_t)n;
        len -= (size_t)n;
    }
}

uint32_t esp_random(void) {
    uint32_t val;
    urandom_read_or_die(&val, sizeof(val));
    return val;
}

esp_reset_reason_t esp_reset_reason(void) { return ESP_RST_POWERON; }

void esp_fill_random(void *buf, size_t len) {
    urandom_read_or_die(buf, len);
}

/* --- esp_system --- */

void esp_restart(void) {
    fprintf(stderr, "[SIM] esp_restart() called — exiting\n");
    exit(0);
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

/* One client at a time is all the firmware uses. */
static ppa_event_callback_t s_ppa_done_cb = NULL;

esp_err_t ppa_unregister_client(ppa_client_handle_t client) {
    (void)client;
    s_ppa_done_cb = NULL;
    return ESP_OK;
}

esp_err_t ppa_client_register_event_callbacks(ppa_client_handle_t client,
                                              const ppa_event_callbacks_t *cbs) {
    (void)client;
    if (!cbs)
        return ESP_ERR_INVALID_ARG;
    s_ppa_done_cb = cbs->on_trans_done;
    return ESP_OK;
}

/* Packed YUV420 (OUYY_EVYY): three bytes per pixel pair, chroma first - U on
 * even lines, V on odd ones - then the pair's two luma samples. BT.601, full
 * range, which is all the firmware asks of the real PPA. */
static int ppa_clamp_u8(int v) { return v < 0 ? 0 : (v > 255 ? 255 : v); }

static void ppa_read_rgb(const ppa_srm_oper_config_t *config, uint32_t x,
                         uint32_t y, int *r, int *g, int *b) {
    if (config->in.srm_cm == PPA_SRM_COLOR_MODE_YUV420) {
        const uint8_t *frame = (const uint8_t *)config->in.buffer;
        size_t stride = (size_t)config->in.pic_w * 3 / 2;
        size_t pair = (size_t)(x / 2) * 3;
        int luma = frame[y * stride + pair + 1 + (x & 1)];
        int u = frame[(y & ~1u) * stride + pair] - 128;
        int v = frame[(y | 1u) * stride + pair] - 128;
        *r = ppa_clamp_u8(luma + (359 * v) / 256);
        *g = ppa_clamp_u8(luma - (88 * u + 183 * v) / 256);
        *b = ppa_clamp_u8(luma + (454 * u) / 256);
        return;
    }
    uint16_t pixel = ((const uint16_t *)config->in.buffer)[y * config->in.pic_w + x];
    *r = ((pixel >> 11) & 0x1F) * 255 / 31;
    *g = ((pixel >> 5) & 0x3F) * 255 / 63;
    *b = (pixel & 0x1F) * 255 / 31;
}

esp_err_t ppa_do_scale_rotate_mirror(ppa_client_handle_t client,
                                      const ppa_srm_oper_config_t *config) {
    if (!config || !config->out.buffer || !config->in.buffer)
        return ESP_ERR_INVALID_ARG;

    /* Nearest-neighbor crop + scale */
    uint32_t ox = config->in.block_offset_x;
    uint32_t oy = config->in.block_offset_y;
    uint32_t crop_w = config->in.block_w;
    uint32_t crop_h = config->in.block_h;
    uint32_t dst_w = config->out.pic_w;
    uint32_t dst_h = config->out.pic_h;
    bool yuv_out = config->out.srm_cm == PPA_SRM_COLOR_MODE_YUV420;
    size_t yuv_stride = (size_t)dst_w * 3 / 2;

    for (uint32_t dy = 0; dy < dst_h; dy++) {
        uint32_t sy = oy + (dy * crop_h / dst_h);
        for (uint32_t dx = 0; dx < dst_w; dx++) {
            uint32_t sx = ox + (dx * crop_w / dst_w);
            int r, g, b;
            ppa_read_rgb(config, sx, sy, &r, &g, &b);
            if (!yuv_out) {
                ((uint16_t *)config->out.buffer)[dy * dst_w + dx] =
                    (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
                continue;
            }
            uint8_t *pair = (uint8_t *)config->out.buffer + dy * yuv_stride +
                            (size_t)(dx / 2) * 3;
            pair[1 + (dx & 1)] = (uint8_t)((77 * r + 150 * g + 29 * b) >> 8);
            if (!(dx & 1)) {
                int chroma = (dy & 1) ? (128 * r - 107 * g - 21 * b) / 256
                                      : (-43 * r - 85 * g + 128 * b) / 256;
                pair[0] = (uint8_t)ppa_clamp_u8(chroma + 128);
            }
        }
    }

    /* As on the device, every transaction reports its completion. */
    if (s_ppa_done_cb) {
        ppa_event_data_t event = {0};
        s_ppa_done_cb(client, &event, config->user_data);
    }
    return ESP_OK;
}

/* --- SPIFFS --- */

esp_err_t esp_vfs_spiffs_register(const esp_vfs_spiffs_conf_t *conf) {
    return sim_flash_spiffs_register(conf);
}

esp_err_t esp_vfs_spiffs_unregister(const char *partition_label) {
    return sim_flash_spiffs_unregister(partition_label);
}

bool esp_spiffs_check(const char *partition_label) {
    return sim_flash_spiffs_check(partition_label);
}

/* --- eFuse --- */

esp_err_t esp_efuse_mac_get_default(uint8_t *mac) {
    static const uint8_t s_mac[6] = {0x02, 0x00, 0x00, 0x53, 0x49, 0x4d};
    if (!mac) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(mac, s_mac, sizeof(s_mac));
    return ESP_OK;
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
