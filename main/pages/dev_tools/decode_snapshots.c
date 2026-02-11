#ifdef K_QUIRC_DEBUG

#include "decode_snapshots.h"

#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <k_quirc.h>
#include <lvgl.h>
#include <sd_card.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../ui/theme.h"

static const char *TAG = "decode_snapshots";

#define IMG_SIZE 320
#define IMG_PIXELS (IMG_SIZE * IMG_SIZE)
#define IMG_RGB565_BYTES (IMG_PIXELS * 2)

#define DEBUG_COLOR_WHITE 0xFFFF
#define DEBUG_COLOR_BLACK 0x0000
#define DEBUG_COLOR_TIMING_OK 0x07E0
#define DEBUG_COLOR_TIMING_BAD 0xF800
#define DEBUG_COLOR_CAPSTONE 0x07FF

static lv_obj_t *page_screen = NULL;
static lv_obj_t *original_img = NULL;
static lv_obj_t *debug_img = NULL;
static lv_obj_t *info_label = NULL;
static lv_obj_t *nav_label = NULL;
static lv_obj_t *hint_label = NULL;
static void (*return_callback)(void) = NULL;

static uint8_t *original_rgb565_buf = NULL;
static uint8_t *debug_rgb565_buf = NULL;
static uint8_t *pgm_grayscale_buf = NULL;

static lv_img_dsc_t original_img_dsc;
static lv_img_dsc_t debug_img_dsc;

static char **pgm_files = NULL;
static int pgm_file_count = 0;
static int current_file_index = 0;

/* --- Debug visualization functions (moved from scanner.c) --- */

static inline void debug_perspective_map(const float *c, float u, float v,
                                         int *ret_x, int *ret_y) {
  float den = c[6] * u + c[7] * v + 1.0f;
  float inv_den = 1.0f / den;
  float x = (c[0] * u + c[1] * v + c[2]) * inv_den;
  float y = (c[3] * u + c[4] * v + c[5]) * inv_den;
  *ret_x = (int)(x + 0.5f);
  *ret_y = (int)(y + 0.5f);
}

static inline void debug_draw_marker(uint16_t *rgb565_out, int out_width,
                                     int out_height, int cx, int cy, int radius,
                                     uint16_t color) {
  for (int dy = -radius; dy <= radius; dy++) {
    for (int dx = -radius; dx <= radius; dx++) {
      int px = cx + dx;
      int py = cy + dy;
      if (px >= 0 && px < out_width && py >= 0 && py < out_height) {
        rgb565_out[py * out_width + px] = color;
      }
    }
  }
}

static void render_debug_visualization(const k_quirc_debug_info_t *debug,
                                       uint16_t *rgb565_out, int out_width,
                                       int out_height) {
  const uint8_t *pixels = (const uint8_t *)debug->pixels;

  for (int y = 0; y < out_height && y < debug->h; y++) {
    for (int x = 0; x < out_width && x < debug->w; x++) {
      uint8_t pix = pixels[y * debug->w + x];
      uint16_t color;

      if (pix == K_QUIRC_PIXEL_WHITE)
        color = DEBUG_COLOR_WHITE;
      else if (pix == K_QUIRC_PIXEL_BLACK)
        color = DEBUG_COLOR_BLACK;
      else
        color = 0x8410;

      rgb565_out[y * out_width + x] = color;
    }
  }

  for (int g = 0; g < debug->num_grids; g++) {
    const k_quirc_debug_grid_t *grid = &debug->grids[g];
    int grid_size = grid->grid_size;

    for (int pos = 8; pos < grid_size - 8; pos++) {
      bool expected_black = (pos & 1) == 0;

      int hx, hy;
      debug_perspective_map(grid->c, pos + 0.5f, 6.5f, &hx, &hy);
      if (hx >= 0 && hx < out_width && hy >= 0 && hy < out_height) {
        uint8_t actual = pixels[hy * debug->w + hx];
        bool actual_black = (actual > K_QUIRC_PIXEL_WHITE);
        uint16_t color = (actual_black == expected_black)
                             ? DEBUG_COLOR_TIMING_OK
                             : DEBUG_COLOR_TIMING_BAD;
        debug_draw_marker(rgb565_out, out_width, out_height, hx, hy, 1, color);
      }

      int vx, vy;
      debug_perspective_map(grid->c, 6.5f, pos + 0.5f, &vx, &vy);
      if (vx >= 0 && vx < out_width && vy >= 0 && vy < out_height) {
        uint8_t actual = pixels[vy * debug->w + vx];
        bool actual_black = (actual > K_QUIRC_PIXEL_WHITE);
        uint16_t color = (actual_black == expected_black)
                             ? DEBUG_COLOR_TIMING_OK
                             : DEBUG_COLOR_TIMING_BAD;
        debug_draw_marker(rgb565_out, out_width, out_height, vx, vy, 1, color);
      }
    }
  }

  for (int i = 0; i < debug->num_capstones; i++) {
    int cx = debug->capstones[i].x;
    int cy = debug->capstones[i].y;
    for (int d = -4; d <= 4; d++) {
      if (cx + d >= 0 && cx + d < out_width && cy >= 0 && cy < out_height)
        rgb565_out[cy * out_width + cx + d] = DEBUG_COLOR_CAPSTONE;
      if (cx >= 0 && cx < out_width && cy + d >= 0 && cy + d < out_height)
        rgb565_out[(cy + d) * out_width + cx] = DEBUG_COLOR_CAPSTONE;
    }
  }
}

/* --- Utility functions --- */

static inline uint16_t grayscale_to_rgb565(uint8_t gray) {
  uint16_t r = (gray >> 3) & 0x1F;
  uint16_t g = (gray >> 2) & 0x3F;
  uint16_t b = (gray >> 3) & 0x1F;
  return (r << 11) | (g << 5) | b;
}

static bool parse_pgm_header(const uint8_t *data, size_t len, int *width,
                              int *height, size_t *data_offset) {
  if (len < 10 || data[0] != 'P' || data[1] != '5')
    return false;

  const char *p = (const char *)data + 2;
  const char *end = (const char *)data + (len < 64 ? len : 64);

  while (p < end && (*p == ' ' || *p == '\n'))
    p++;
  *width = strtol(p, (char **)&p, 10);

  while (p < end && (*p == ' ' || *p == '\n'))
    p++;
  *height = strtol(p, (char **)&p, 10);

  while (p < end && (*p == ' ' || *p == '\n'))
    p++;
  int maxval = strtol(p, (char **)&p, 10);
  if (maxval != 255)
    return false;

  if (*p == '\n')
    p++;
  *data_offset = p - (const char *)data;

  return (*width > 0 && *height > 0 && *data_offset < len);
}

static void collect_pgm_files(void) {
  char **all_files = NULL;
  int all_count = 0;

  if (sd_card_list_files(SD_CARD_MOUNT_POINT, &all_files, &all_count) !=
          ESP_OK ||
      all_count == 0) {
    pgm_files = NULL;
    pgm_file_count = 0;
    return;
  }

  /* Count PGM files first */
  int count = 0;
  for (int i = 0; i < all_count; i++) {
    size_t name_len = strlen(all_files[i]);
    if (name_len >= 4 && strcmp(all_files[i] + name_len - 4, ".pgm") == 0)
      count++;
  }

  if (count == 0) {
    sd_card_free_file_list(all_files, all_count);
    pgm_files = NULL;
    pgm_file_count = 0;
    return;
  }

  pgm_files = malloc(count * sizeof(char *));
  if (!pgm_files) {
    sd_card_free_file_list(all_files, all_count);
    pgm_file_count = 0;
    return;
  }

  int j = 0;
  for (int i = 0; i < all_count && j < count; i++) {
    size_t name_len = strlen(all_files[i]);
    if (name_len >= 4 && strcmp(all_files[i] + name_len - 4, ".pgm") == 0) {
      pgm_files[j] = strdup(all_files[i]);
      j++;
    }
  }
  pgm_file_count = j;

  sd_card_free_file_list(all_files, all_count);
}

static void free_pgm_files(void) {
  if (pgm_files) {
    for (int i = 0; i < pgm_file_count; i++)
      free(pgm_files[i]);
    free(pgm_files);
    pgm_files = NULL;
  }
  pgm_file_count = 0;
}

static void process_and_display_file(int index) {
  if (index < 0 || index >= pgm_file_count)
    return;

  char filepath[128];
  snprintf(filepath, sizeof(filepath), "%s/%s", SD_CARD_MOUNT_POINT,
           pgm_files[index]);

  uint8_t *file_data = NULL;
  size_t file_len = 0;
  if (sd_card_read_file(filepath, &file_data, &file_len) != ESP_OK) {
    lv_label_set_text_fmt(info_label, "%s\nRead failed", pgm_files[index]);
    return;
  }

  int width, height;
  size_t data_offset;
  if (!parse_pgm_header(file_data, file_len, &width, &height, &data_offset)) {
    lv_label_set_text_fmt(info_label, "%s\nInvalid PGM", pgm_files[index]);
    free(file_data);
    return;
  }

  if (width > IMG_SIZE || height > IMG_SIZE) {
    lv_label_set_text_fmt(info_label, "%s\nToo large: %dx%d", pgm_files[index],
                          width, height);
    free(file_data);
    return;
  }

  const uint8_t *gray_data = file_data + data_offset;
  size_t gray_size = file_len - data_offset;

  if (gray_size < (size_t)(width * height)) {
    lv_label_set_text_fmt(info_label, "%s\nTruncated data", pgm_files[index]);
    free(file_data);
    return;
  }

  /* Keep a copy of the grayscale data before k_quirc_end overwrites it */
  memcpy(pgm_grayscale_buf, gray_data, width * height);

  /* Convert original grayscale to RGB565 for left image */
  uint16_t *orig_pixels = (uint16_t *)original_rgb565_buf;
  memset(original_rgb565_buf, 0, IMG_RGB565_BYTES);
  for (int y = 0; y < height; y++) {
    for (int x = 0; x < width; x++) {
      orig_pixels[y * IMG_SIZE + x] =
          grayscale_to_rgb565(pgm_grayscale_buf[y * width + x]);
    }
  }

  /* Decode with k_quirc lower-level API to access debug info */
  k_quirc_t *q = k_quirc_new();
  if (!q) {
    lv_label_set_text_fmt(info_label, "%s\nAlloc failed", pgm_files[index]);
    free(file_data);
    return;
  }

  if (k_quirc_resize(q, width, height) < 0) {
    lv_label_set_text_fmt(info_label, "%s\nResize failed", pgm_files[index]);
    k_quirc_destroy(q);
    free(file_data);
    return;
  }

  uint8_t *qr_buf = k_quirc_begin(q, NULL, NULL);
  memcpy(qr_buf, pgm_grayscale_buf, width * height);

  int64_t start_time = esp_timer_get_time();
  k_quirc_end(q, true);
  int64_t elapsed_us = esp_timer_get_time() - start_time;
  float elapsed_ms = elapsed_us / 1000.0f;

  /* Get debug info and render visualization */
  const k_quirc_debug_info_t *dbg = k_quirc_get_debug_info(q);
  memset(debug_rgb565_buf, 0, IMG_RGB565_BYTES);
  if (dbg && dbg->pixels) {
    render_debug_visualization(dbg, (uint16_t *)debug_rgb565_buf, IMG_SIZE,
                               IMG_SIZE);
  }

  /* Decode QR codes */
  int num_codes = k_quirc_count(q);
  k_quirc_result_t result;
  bool decoded_ok = false;
  int version = 0;
  int payload_len = 0;

  for (int i = 0; i < num_codes; i++) {
    k_quirc_error_t err = k_quirc_decode(q, i, &result);
    if (err == K_QUIRC_SUCCESS && result.valid) {
      decoded_ok = true;
      version = result.data.version;
      payload_len = result.data.payload_len;
      break;
    }
  }

  int num_grids = dbg ? dbg->num_grids : 0;
  int num_capstones = dbg ? dbg->num_capstones : 0;
  int thr_off = dbg ? dbg->threshold_offset : 0;

  k_quirc_destroy(q);
  free(file_data);

  /* Update UI */
  lv_label_set_text_fmt(nav_label, "%d / %d", index + 1, pgm_file_count);

  if (decoded_ok) {
    lv_label_set_text_fmt(info_label,
                          "%s\nDecoded OK  v%d  %d bytes\n%.1f ms  grids:%d  "
                          "caps:%d  thr_off:%d",
                          pgm_files[index], version, payload_len, elapsed_ms,
                          num_grids, num_capstones, thr_off);
  } else {
    lv_label_set_text_fmt(
        info_label,
        "%s\nNo QR decoded\n%.1f ms  grids:%d  caps:%d  thr_off:%d",
        pgm_files[index], elapsed_ms, num_grids, num_capstones, thr_off);
  }

  original_img_dsc.data = original_rgb565_buf;
  debug_img_dsc.data = debug_rgb565_buf;
  lv_img_set_src(original_img, &original_img_dsc);
  lv_img_set_src(debug_img, &debug_img_dsc);
}

static void touch_advance_cb(lv_event_t *e) {
  (void)e;
  current_file_index++;
  if (current_file_index >= pgm_file_count) {
    if (return_callback)
      return_callback();
    return;
  }
  process_and_display_file(current_file_index);
}

/* --- Page lifecycle --- */

void decode_snapshots_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  (void)parent;
  return_callback = return_cb;
  current_file_index = 0;

  /* Allocate SPIRAM buffers */
  original_rgb565_buf =
      heap_caps_malloc(IMG_RGB565_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  debug_rgb565_buf =
      heap_caps_malloc(IMG_RGB565_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  pgm_grayscale_buf =
      heap_caps_malloc(IMG_PIXELS, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

  if (!original_rgb565_buf || !debug_rgb565_buf || !pgm_grayscale_buf) {
    ESP_LOGE(TAG, "Failed to allocate buffers");
    decode_snapshots_page_destroy();
    if (return_cb)
      return_cb();
    return;
  }

  memset(original_rgb565_buf, 0, IMG_RGB565_BYTES);
  memset(debug_rgb565_buf, 0, IMG_RGB565_BYTES);

  /* Init image descriptors */
  original_img_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565, .w = IMG_SIZE, .h = IMG_SIZE},
      .data_size = IMG_RGB565_BYTES,
      .data = original_rgb565_buf,
  };
  debug_img_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565, .w = IMG_SIZE, .h = IMG_SIZE},
      .data_size = IMG_RGB565_BYTES,
      .data = debug_rgb565_buf,
  };

  /* Collect PGM files from SD card */
  collect_pgm_files();
  if (pgm_file_count == 0) {
    ESP_LOGW(TAG, "No PGM files found on SD card");
    decode_snapshots_page_destroy();
    if (return_cb)
      return_cb();
    return;
  }

  /* Build UI */
  page_screen = theme_create_page_container(lv_screen_active());
  lv_obj_add_event_cb(page_screen, touch_advance_cb, LV_EVENT_CLICKED, NULL);

  /* Title */
  theme_create_page_title(page_screen, "QR Debug");

  /* Navigation counter */
  nav_label = theme_create_label(page_screen, "", true);
  lv_obj_align(nav_label, LV_ALIGN_TOP_RIGHT, -10,
               theme_get_default_padding());

  /* Original image (left) */
  original_img = lv_img_create(page_screen);
  lv_obj_set_size(original_img, IMG_SIZE, IMG_SIZE);
  lv_obj_set_pos(original_img, 40, 60);
  lv_img_set_src(original_img, &original_img_dsc);

  /* Debug visualization image (right) */
  debug_img = lv_img_create(page_screen);
  lv_obj_set_size(debug_img, IMG_SIZE, IMG_SIZE);
  lv_obj_set_pos(debug_img, 360, 60);
  lv_img_set_src(debug_img, &debug_img_dsc);

  /* Info label below images */
  info_label = theme_create_label(page_screen, "", false);
  lv_obj_set_width(info_label, 640);
  lv_obj_align(info_label, LV_ALIGN_TOP_MID, 0, 390);

  /* Hint label at bottom */
  hint_label = theme_create_label(page_screen, "Tap to advance", true);
  lv_obj_align(hint_label, LV_ALIGN_BOTTOM_MID, 0, -10);

  /* Process first file */
  process_and_display_file(0);
}

void decode_snapshots_page_show(void) {
  if (page_screen)
    lv_obj_clear_flag(page_screen, LV_OBJ_FLAG_HIDDEN);
}

void decode_snapshots_page_hide(void) {
  if (page_screen)
    lv_obj_add_flag(page_screen, LV_OBJ_FLAG_HIDDEN);
}

void decode_snapshots_page_destroy(void) {
  if (page_screen) {
    lv_obj_del(page_screen);
    page_screen = NULL;
  }

  original_img = NULL;
  debug_img = NULL;
  info_label = NULL;
  nav_label = NULL;
  hint_label = NULL;

  if (original_rgb565_buf) {
    heap_caps_free(original_rgb565_buf);
    original_rgb565_buf = NULL;
  }
  if (debug_rgb565_buf) {
    heap_caps_free(debug_rgb565_buf);
    debug_rgb565_buf = NULL;
  }
  if (pgm_grayscale_buf) {
    heap_caps_free(pgm_grayscale_buf);
    pgm_grayscale_buf = NULL;
  }

  free_pgm_files();
  return_callback = NULL;
  current_file_index = 0;
}

#endif /* K_QUIRC_DEBUG */
