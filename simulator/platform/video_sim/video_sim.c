/**
 * Video simulator for Kern Desktop Simulator.
 *
 * Loads a QR image from disk via stb_image, converts it to RGB565,
 * and delivers frames at ~30fps via the registered frame callback.
 * Replaces the previous no-op stub.
 */

#include "video/video.h"
#include "esp_err.h"
#include "esp_log.h"
#include "stb_image.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <strings.h>
#include <unistd.h>

static const char *TAG = "VIDEO_SIM";

static app_video_frame_operation_cb_t s_frame_cb = NULL;
static uint8_t *s_frame_buf = NULL;     /* RGB565 frame, owned by this module */
static uint32_t s_width = 800;
static uint32_t s_height = 640;
static size_t s_frame_size = 0;

static pthread_t s_stream_thread;
static volatile bool s_streaming = false;

static char *s_qr_image_path = NULL;    /* set by sim_video_set_qr_image() */
static char *s_qr_image_dir = NULL;    /* set by sim_video_set_qr_dir() */
static size_t s_qr_dir_index = 0;      /* cycles through images in s_qr_image_dir */

static uint8_t *s_user_bufs[4];
static uint32_t s_num_user_bufs = 0;

/* --- Helpers --- */

static uint8_t *load_rgb565(const char *path, uint32_t *out_w, uint32_t *out_h, size_t *out_size) {
    int w, h, channels;
    unsigned char *rgb = stbi_load(path, &w, &h, &channels, 3); /* force RGB888 */
    if (!rgb) {
        ESP_LOGE(TAG, "stbi_load failed: %s", stbi_failure_reason());
        return NULL;
    }
    size_t npixels = (size_t)w * h;
    uint16_t *buf = malloc(npixels * 2);
    if (!buf) { stbi_image_free(rgb); return NULL; }
    for (size_t i = 0; i < npixels; i++) {
        uint16_t r = (rgb[i*3+0] >> 3) & 0x1F;
        uint16_t g = (rgb[i*3+1] >> 2) & 0x3F;
        uint16_t b = (rgb[i*3+2] >> 3) & 0x1F;
        buf[i] = (r << 11) | (g << 5) | b;
    }
    stbi_image_free(rgb);
    *out_w = (uint32_t)w;
    *out_h = (uint32_t)h;
    *out_size = npixels * 2;
    return (uint8_t *)buf;
}

static uint8_t *alloc_blank_rgb565(uint32_t w, uint32_t h, size_t *out_size) {
    size_t sz = (size_t)w * h * 2;
    uint8_t *buf = calloc(1, sz);
    if (buf) *out_size = sz;
    return buf;
}

/* --- Stream thread --- */

static void *stream_thread_func(void *arg) {
    (void)arg;
    while (s_streaming) {
        if (s_frame_cb && s_frame_buf) {
            uint8_t *deliver_buf = s_frame_buf;
            if (s_num_user_bufs > 0 && s_user_bufs[0]) {
                memcpy(s_user_bufs[0], s_frame_buf, s_frame_size);
                deliver_buf = s_user_bufs[0];
            }
            s_frame_cb(deliver_buf, 0, s_width, s_height, s_frame_size);
        }
        usleep(33333); /* ~30 fps */
    }
    return NULL;
}

/* --- API --- */

esp_err_t app_video_main(i2c_master_bus_handle_t i2c_bus_handle) {
    (void)i2c_bus_handle;
    return ESP_OK;
}

int app_video_open(char *dev, video_fmt_t init_fmt) {
    (void)dev; (void)init_fmt;
    free(s_frame_buf);
    s_frame_buf = NULL;
    s_frame_size = 0;

    if (s_qr_image_path) {
        s_frame_buf = load_rgb565(s_qr_image_path, &s_width, &s_height, &s_frame_size);
        if (!s_frame_buf) {
            ESP_LOGW(TAG, "Failed to load QR image, using blank frame");
        } else {
            ESP_LOGI(TAG, "Loaded QR image: %s (%"PRIu32"x%"PRIu32")",
                     s_qr_image_path, s_width, s_height);
        }
    }
    if (!s_frame_buf && s_qr_image_dir) {
        /* Collect image filenames from directory, pick one by cycling index */
        DIR *dir = opendir(s_qr_image_dir);
        if (!dir) {
            ESP_LOGW(TAG, "Cannot open qr-dir: %s", s_qr_image_dir);
        } else {
            /* Two-pass: first count, then pick by index */
            char **entries = NULL;
            size_t count = 0;
            size_t capacity = 0;
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL) {
                const char *name = ent->d_name;
                size_t nlen = strlen(name);
                bool is_img = (nlen > 4 &&
                               (strcasecmp(name + nlen - 4, ".png") == 0 ||
                                strcasecmp(name + nlen - 4, ".jpg") == 0)) ||
                              (nlen > 5 && strcasecmp(name + nlen - 5, ".jpeg") == 0);
                if (!is_img) continue;
                if (count >= capacity) {
                    capacity = capacity ? capacity * 2 : 8;
                    char **tmp = realloc(entries, capacity * sizeof(char *));
                    if (!tmp) { free(entries); entries = NULL; count = 0; break; }
                    entries = tmp;
                }
                entries[count++] = strdup(name);
            }
            closedir(dir);
            if (count > 0) {
                size_t pick = s_qr_dir_index % count;
                s_qr_dir_index++;
                size_t dir_len = strlen(s_qr_image_dir);
                size_t name_len = strlen(entries[pick]);
                char *full_path = malloc(dir_len + 1 + name_len + 1);
                if (full_path) {
                    memcpy(full_path, s_qr_image_dir, dir_len);
                    full_path[dir_len] = '/';
                    memcpy(full_path + dir_len + 1, entries[pick], name_len + 1);
                    s_frame_buf = load_rgb565(full_path, &s_width, &s_height, &s_frame_size);
                    if (s_frame_buf) {
                        ESP_LOGI(TAG, "Loaded QR image from dir: %s (%"PRIu32"x%"PRIu32")",
                                 full_path, s_width, s_height);
                    } else {
                        ESP_LOGW(TAG, "Failed to load QR image from dir: %s", full_path);
                    }
                    free(full_path);
                }
                for (size_t i = 0; i < count; i++) free(entries[i]);
                free(entries);
            } else {
                ESP_LOGW(TAG, "No .png/.jpg images found in qr-dir: %s", s_qr_image_dir);
                free(entries);
            }
        }
    }
    if (!s_frame_buf) {
        /* No image configured or load failed — blank 800x640 frame */
        s_width = 800;
        s_height = 640;
        s_frame_buf = alloc_blank_rgb565(s_width, s_height, &s_frame_size);
        if (!s_frame_buf) {
            ESP_LOGE(TAG, "Failed to allocate blank frame buffer");
            return -1;
        }
    }
    return 42; /* fake fd — must be >= 0 */
}

esp_err_t app_video_set_bufs(int video_fd, uint32_t fb_num, const void **fb) {
    (void)video_fd;
    if (fb && fb_num > 0) {
        uint32_t count = fb_num < 4 ? fb_num : 4;
        for (uint32_t i = 0; i < count; i++) {
            s_user_bufs[i] = (uint8_t *)fb[i];
        }
        s_num_user_bufs = count;
    }
    return ESP_OK;
}

esp_err_t app_video_get_bufs(int fb_num, void **fb) {
    if (!fb) return ESP_FAIL;
    for (int i = 0; i < fb_num; i++) {
        uint32_t idx = (uint32_t)i;
        fb[i] = (s_num_user_bufs > 0 && idx < s_num_user_bufs && s_user_bufs[idx])
                    ? s_user_bufs[idx]
                    : s_frame_buf;
    }
    return ESP_OK;
}

uint32_t app_video_get_buf_size(void) {
    return (uint32_t)s_frame_size;
}

esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height) {
    if (width)  *width  = s_width;
    if (height) *height = s_height;
    return ESP_OK;
}

esp_err_t app_video_register_frame_operation_cb(app_video_frame_operation_cb_t cb) {
    s_frame_cb = cb;
    return ESP_OK;
}

esp_err_t app_video_stream_task_start(int video_fd, int core_id) {
    (void)video_fd; (void)core_id;
    if (s_streaming) return ESP_OK;
    s_streaming = true;
    if (pthread_create(&s_stream_thread, NULL, stream_thread_func, NULL) != 0) {
        s_streaming = false;
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t app_video_stream_task_stop(int video_fd) {
    (void)video_fd;
    if (!s_streaming) return ESP_OK;
    s_streaming = false;
    pthread_join(s_stream_thread, NULL);
    return ESP_OK;
}

esp_err_t app_video_close(int video_fd) {
    app_video_stream_task_stop(video_fd);
    free(s_frame_buf);
    s_frame_buf = NULL;
    s_frame_size = 0;
    return ESP_OK;
}

esp_err_t app_video_set_ae_target(int video_fd, uint32_t level) {
    (void)video_fd;
    ESP_LOGI(TAG, "AE target: %"PRIu32" (no-op in sim)", level);
    return ESP_OK;
}

esp_err_t app_video_set_focus(int video_fd, uint32_t position) {
    (void)video_fd;
    ESP_LOGI(TAG, "Focus: %"PRIu32" (no-op in sim)", position);
    return ESP_OK;
}

bool app_video_has_focus_motor(int video_fd) {
    (void)video_fd;
    return false;
}

esp_err_t app_video_disable_af(void) {
    return ESP_OK;
}

esp_err_t app_video_deinit(void) {
    return ESP_OK;
}

/* --- Simulator control API --- */

void sim_video_set_qr_image(const char *path) {
    free(s_qr_image_path);
    s_qr_image_path = path ? strdup(path) : NULL;
}

void sim_video_set_qr_dir(const char *dir_path) {
    free(s_qr_image_dir);
    s_qr_image_dir = dir_path ? strdup(dir_path) : NULL;
}
