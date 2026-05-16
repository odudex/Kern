/**
 * Video simulator for Kern Desktop Simulator.
 *
 * Loads QR images from disk or captures webcam frames, converts them to RGB565,
 * and delivers frames at ~30fps through the same singleton video API used by
 * firmware.
 */

#include "video/video.h"
#include "esp_err.h"
#include "esp_log.h"
#include "stb_image.h"
#ifdef SIM_WEBCAM
#include "v4l2_capture.h"
#endif
#include <dirent.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static const char *TAG = "VIDEO_SIM";

static app_video_frame_operation_cb_t s_frame_cb = NULL;
static uint8_t *s_frame_buf = NULL;
static uint32_t s_width = 800;
static uint32_t s_height = 640;
static size_t s_frame_size = 0;

static pthread_t s_stream_thread;
static volatile bool s_streaming = false;
static bool s_initialized = false;

static char *s_qr_image_path = NULL;
static char *s_qr_image_dir = NULL;
static size_t s_qr_dir_index = 0;

#ifdef SIM_WEBCAM
static bool s_webcam_enabled = false;
static char *s_webcam_device = NULL;
static v4l2_capture_t *s_webcam = NULL;
#endif

static uint8_t *load_rgb565(const char *path, uint32_t *out_w, uint32_t *out_h,
                            size_t *out_size) {
  int w, h, channels;
  unsigned char *rgb = stbi_load(path, &w, &h, &channels, 3);
  if (!rgb) {
    ESP_LOGE(TAG, "stbi_load failed: %s", stbi_failure_reason());
    return NULL;
  }

  size_t npixels = (size_t)w * h;
  uint16_t *buf = malloc(npixels * 2);
  if (!buf) {
    stbi_image_free(rgb);
    return NULL;
  }

  for (size_t i = 0; i < npixels; i++) {
    uint16_t r = (rgb[i * 3 + 0] >> 3) & 0x1F;
    uint16_t g = (rgb[i * 3 + 1] >> 2) & 0x3F;
    uint16_t b = (rgb[i * 3 + 2] >> 3) & 0x1F;
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
  if (buf)
    *out_size = sz;
  return buf;
}

static uint8_t *load_next_dir_rgb565(uint32_t *out_w, uint32_t *out_h,
                                     size_t *out_size) {
  if (!s_qr_image_dir)
    return NULL;

  DIR *dir = opendir(s_qr_image_dir);
  if (!dir) {
    ESP_LOGW(TAG, "Cannot open qr-dir: %s", s_qr_image_dir);
    return NULL;
  }

  char **entries = NULL;
  size_t count = 0;
  size_t capacity = 0;
  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    const char *name = ent->d_name;
    size_t nlen = strlen(name);
    bool is_img =
        (nlen > 4 && (strcasecmp(name + nlen - 4, ".png") == 0 ||
                      strcasecmp(name + nlen - 4, ".jpg") == 0)) ||
        (nlen > 5 && strcasecmp(name + nlen - 5, ".jpeg") == 0);
    if (!is_img)
      continue;

    if (count >= capacity) {
      capacity = capacity ? capacity * 2 : 8;
      char **tmp = realloc(entries, capacity * sizeof(char *));
      if (!tmp) {
        for (size_t i = 0; i < count; i++)
          free(entries[i]);
        free(entries);
        closedir(dir);
        return NULL;
      }
      entries = tmp;
    }
    entries[count++] = strdup(name);
  }
  closedir(dir);

  if (count == 0) {
    ESP_LOGW(TAG, "No .png/.jpg images found in qr-dir: %s", s_qr_image_dir);
    free(entries);
    return NULL;
  }

  size_t pick = s_qr_dir_index % count;
  s_qr_dir_index++;

  size_t dir_len = strlen(s_qr_image_dir);
  size_t name_len = strlen(entries[pick]);
  char *full_path = malloc(dir_len + 1 + name_len + 1);
  uint8_t *buf = NULL;
  if (full_path) {
    memcpy(full_path, s_qr_image_dir, dir_len);
    full_path[dir_len] = '/';
    memcpy(full_path + dir_len + 1, entries[pick], name_len + 1);
    buf = load_rgb565(full_path, out_w, out_h, out_size);
    if (buf) {
      ESP_LOGI(TAG, "Loaded QR image from dir: %s (%" PRIu32 "x%" PRIu32 ")",
               full_path, *out_w, *out_h);
    } else {
      ESP_LOGW(TAG, "Failed to load QR image from dir: %s", full_path);
    }
    free(full_path);
  }

  for (size_t i = 0; i < count; i++)
    free(entries[i]);
  free(entries);
  return buf;
}

static esp_err_t load_configured_frame(bool rotate_dir) {
#ifdef SIM_WEBCAM
  if (s_webcam)
    return ESP_OK;
#endif

  uint8_t *new_buf = NULL;
  uint32_t new_w = 0;
  uint32_t new_h = 0;
  size_t new_size = 0;

  if (rotate_dir && s_qr_image_dir)
    new_buf = load_next_dir_rgb565(&new_w, &new_h, &new_size);

  if (!new_buf && s_qr_image_path) {
    new_buf = load_rgb565(s_qr_image_path, &new_w, &new_h, &new_size);
    if (new_buf) {
      ESP_LOGI(TAG, "Loaded QR image: %s (%" PRIu32 "x%" PRIu32 ")",
               s_qr_image_path, new_w, new_h);
    } else {
      ESP_LOGW(TAG, "Failed to load QR image, using blank frame");
    }
  }

  if (new_buf) {
    free(s_frame_buf);
    s_frame_buf = new_buf;
    s_width = new_w;
    s_height = new_h;
    s_frame_size = new_size;
  }

  if (!s_frame_buf) {
    s_width = 800;
    s_height = 640;
    s_frame_buf = alloc_blank_rgb565(s_width, s_height, &s_frame_size);
    if (!s_frame_buf) {
      ESP_LOGE(TAG, "Failed to allocate blank frame buffer");
      return ESP_ERR_NO_MEM;
    }
  }

  return ESP_OK;
}

static void *stream_thread_func(void *arg) {
  (void)arg;
  while (s_streaming) {
#ifdef SIM_WEBCAM
    if (s_webcam && s_frame_buf) {
      v4l2_capture_read_rgb565(s_webcam, s_frame_buf, s_frame_size);
    }
#endif
    if (s_frame_cb && s_frame_buf) {
      s_frame_cb(s_frame_buf, 0, s_width, s_height, s_frame_size);
    }
#ifdef SIM_WEBCAM
    if (!s_webcam)
#endif
      usleep(33333);
  }
  return NULL;
}

esp_err_t app_video_init_once(i2c_master_bus_handle_t i2c_bus_handle) {
  (void)i2c_bus_handle;
  if (s_initialized)
    return ESP_OK;

#ifdef SIM_WEBCAM
  if (s_webcam_enabled) {
    // Defer v4l2_capture_open() until app_video_start() so the webcam light
    // only turns on while a camera page is active. Allocate a placeholder
    // buffer at the expected resolution so app_video_is_ready() can return
    // true and pages can query buffer size before starting the stream.
    s_width = 1280;
    s_height = 720;
    s_frame_size = (size_t)s_width * s_height * 2;
    s_frame_buf = calloc(1, s_frame_size);
    if (!s_frame_buf) {
      ESP_LOGE(TAG, "Failed to allocate webcam placeholder buffer");
      return ESP_ERR_NO_MEM;
    }
    s_initialized = true;
    return ESP_OK;
  }
#endif

  esp_err_t ret = load_configured_frame(false);
  if (ret == ESP_OK)
    s_initialized = true;
  return ret;
}

bool app_video_is_ready(void) { return s_initialized && s_frame_buf; }

bool app_video_is_streaming(void) { return s_streaming; }

uint32_t app_video_get_buf_size(void) { return (uint32_t)s_frame_size; }

esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height) {
  if (width)
    *width = s_width;
  if (height)
    *height = s_height;
  return ESP_OK;
}

esp_err_t app_video_start(app_video_frame_operation_cb_t cb, int core_id) {
  (void)core_id;
  if (!app_video_is_ready())
    return ESP_ERR_INVALID_STATE;
  if (!cb)
    return ESP_ERR_INVALID_ARG;
  if (s_streaming)
    return ESP_ERR_INVALID_STATE;

#ifdef SIM_WEBCAM
  if (s_webcam_enabled && !s_webcam) {
    s_webcam = v4l2_capture_open(s_webcam_device, 1280, 720);
    if (s_webcam) {
      uint32_t w = s_width, h = s_height;
      v4l2_capture_get_resolution(s_webcam, &w, &h);
      size_t needed = (size_t)w * h * 2;
      if (needed != s_frame_size) {
        uint8_t *nbuf = realloc(s_frame_buf, needed);
        if (!nbuf) {
          v4l2_capture_close(s_webcam);
          s_webcam = NULL;
          return ESP_ERR_NO_MEM;
        }
        s_frame_buf = nbuf;
        s_width = w;
        s_height = h;
        s_frame_size = needed;
      }
      ESP_LOGI(TAG, "Webcam opened: %" PRIu32 "x%" PRIu32, s_width, s_height);
    } else {
      ESP_LOGW(TAG, "Webcam unavailable, falling back to image/blank");
    }
  }
#endif

  esp_err_t ret = load_configured_frame(true);
  if (ret != ESP_OK)
    return ret;

  s_frame_cb = cb;
  s_streaming = true;
  if (pthread_create(&s_stream_thread, NULL, stream_thread_func, NULL) != 0) {
    s_streaming = false;
    s_frame_cb = NULL;
    return ESP_FAIL;
  }
  return ESP_OK;
}

esp_err_t app_video_stop(void) {
  if (!s_streaming) {
    s_frame_cb = NULL;
    return ESP_OK;
  }
  s_streaming = false;
  pthread_join(s_stream_thread, NULL);
  s_frame_cb = NULL;
#ifdef SIM_WEBCAM
  if (s_webcam) {
    v4l2_capture_close(s_webcam);
    s_webcam = NULL;
  }
#endif
  return ESP_OK;
}

esp_err_t app_video_set_ae_target(uint32_t level) {
  ESP_LOGI(TAG, "AE target: %" PRIu32 " (no-op in sim)", level);
  return ESP_OK;
}

esp_err_t app_video_set_focus(uint32_t position) {
  ESP_LOGI(TAG, "Focus: %" PRIu32 " (no-op in sim)", position);
  return ESP_OK;
}

bool app_video_has_focus_motor(void) { return false; }

/* --- Simulator control API --- */

void sim_video_set_qr_image(const char *path) {
  free(s_qr_image_path);
  s_qr_image_path = path ? strdup(path) : NULL;
}

void sim_video_set_qr_dir(const char *dir_path) {
  free(s_qr_image_dir);
  s_qr_image_dir = dir_path ? strdup(dir_path) : NULL;
}

void sim_video_set_webcam(const char *device) {
#ifdef SIM_WEBCAM
  free(s_webcam_device);
  s_webcam_device = strdup(device ? device : "/dev/video0");
  s_webcam_enabled = true;
#else
  (void)device;
  fprintf(stderr,
          "Warning: webcam support not compiled in (build with "
          "-DSIM_WEBCAM=ON)\n");
#endif
}
