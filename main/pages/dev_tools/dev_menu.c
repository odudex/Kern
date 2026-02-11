#include "dev_menu.h"

#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <k_quirc.h>
#include <lvgl.h>
#include <sd_card.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#ifdef K_QUIRC_DEBUG
#include "decode_snapshots.h"
#endif
#include "snapshot.h"

#ifndef K_QUIRC_DEBUG
static const char *TAG = "dev_menu";
#define DECODE_TASK_STACK_SIZE 32768
#endif

static ui_menu_t *dev_menu = NULL;
static lv_obj_t *dev_menu_screen = NULL;
static void (*return_callback)(void) = NULL;

static void return_from_snapshot_cb(void) {
  snapshot_page_destroy();
  dev_menu_page_show();
}

static void snapshot_cb(void) {
  dev_menu_page_hide();
  snapshot_page_create(lv_screen_active(), return_from_snapshot_cb);
  snapshot_page_show();
}

#ifdef K_QUIRC_DEBUG

static void return_from_decode_cb(void) {
  decode_snapshots_page_destroy();
  dev_menu_page_show();
}

static void decode_snapshots_cb(void) {
  if (!sd_card_is_mounted()) {
    if (sd_card_init() != ESP_OK) {
      dialog_show_message("Error", "Failed to mount SD card");
      return;
    }
  }

  dev_menu_page_hide();
  decode_snapshots_page_create(lv_screen_active(), return_from_decode_cb);
  decode_snapshots_page_show();
}

#else /* !K_QUIRC_DEBUG */

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

typedef struct {
  int pgm_count;
  int decoded_count;
  int failed_count;
  bool done;
} decode_result_t;

static decode_result_t decode_result;

static void decode_task(void *arg) {
  decode_result.pgm_count = 0;
  decode_result.decoded_count = 0;
  decode_result.failed_count = 0;

  char **files = NULL;
  int count = 0;
  if (sd_card_list_files(SD_CARD_MOUNT_POINT, &files, &count) != ESP_OK ||
      count == 0) {
    decode_result.done = true;
    vTaskDelete(NULL);
    return;
  }

  ESP_LOGI(TAG, "=== Decode Snapshots Start ===");

  for (int i = 0; i < count; i++) {
    size_t name_len = strlen(files[i]);
    if (name_len < 4 || strcmp(files[i] + name_len - 4, ".pgm") != 0)
      continue;

    decode_result.pgm_count++;

    char filepath[128];
    snprintf(filepath, sizeof(filepath), "%s/%s", SD_CARD_MOUNT_POINT,
             files[i]);

    uint8_t *file_data = NULL;
    size_t file_len = 0;
    if (sd_card_read_file(filepath, &file_data, &file_len) != ESP_OK) {
      ESP_LOGE(TAG, "%s: read failed", files[i]);
      decode_result.failed_count++;
      continue;
    }

    int width, height;
    size_t data_offset;
    if (!parse_pgm_header(file_data, file_len, &width, &height, &data_offset)) {
      ESP_LOGE(TAG, "%s: invalid PGM header", files[i]);
      free(file_data);
      decode_result.failed_count++;
      continue;
    }

    const uint8_t *gray_data = file_data + data_offset;
    size_t gray_size = file_len - data_offset;

    if (gray_size < (size_t)(width * height)) {
      ESP_LOGE(TAG, "%s: truncated data", files[i]);
      free(file_data);
      decode_result.failed_count++;
      continue;
    }

    k_quirc_result_t result;
    int64_t start_time = esp_timer_get_time();
    int qr_count =
        k_quirc_decode_grayscale(gray_data, width, height, &result, 1, true);
    int64_t elapsed_us = esp_timer_get_time() - start_time;

    if (qr_count > 0 && result.valid) {
      decode_result.decoded_count++;
      ESP_LOGI(TAG, "%s: OK (%d bytes) [%lld ms]", files[i],
               result.data.payload_len, elapsed_us / 1000);
    } else {
      decode_result.failed_count++;
      ESP_LOGW(TAG, "%s: NO QR [%lld ms]", files[i], elapsed_us / 1000);
    }

    free(file_data);
  }

  sd_card_free_file_list(files, count);

  ESP_LOGI(TAG, "=== Results: %d/%d decoded ===", decode_result.decoded_count,
           decode_result.pgm_count);

  decode_result.done = true;
  vTaskDelete(NULL);
}

static void decode_snapshots_cb(void) {
  if (!sd_card_is_mounted()) {
    if (sd_card_init() != ESP_OK) {
      dialog_show_message("Error", "Failed to mount SD card");
      return;
    }
  }

  decode_result.done = false;

  BaseType_t ret =
      xTaskCreate(decode_task, "decode", DECODE_TASK_STACK_SIZE, NULL, 5, NULL);
  if (ret != pdPASS) {
    dialog_show_message("Error", "Failed to start decode task");
    return;
  }

  while (!decode_result.done) {
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  char msg[128];
  if (decode_result.pgm_count == 0) {
    snprintf(msg, sizeof(msg), "No .pgm files found");
  } else {
    snprintf(msg, sizeof(msg), "Decoded: %d/%d\nFailed: %d",
             decode_result.decoded_count, decode_result.pgm_count,
             decode_result.failed_count);
  }
  dialog_show_message("Decode Results", msg);
}

#endif /* K_QUIRC_DEBUG */

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  dev_menu_page_hide();
  dev_menu_page_destroy();
  if (callback)
    callback();
}

void dev_menu_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  dev_menu_screen = theme_create_page_container(parent);

  dev_menu = ui_menu_create(dev_menu_screen, "Developer Tools", back_cb);
  if (!dev_menu)
    return;

  ui_menu_add_entry(dev_menu, "Snapshot to SD", snapshot_cb);
  ui_menu_add_entry(dev_menu, "Decode Snapshots", decode_snapshots_cb);
  ui_menu_show(dev_menu);
}

void dev_menu_page_show(void) {
  if (dev_menu)
    ui_menu_show(dev_menu);
}

void dev_menu_page_hide(void) {
  if (dev_menu)
    ui_menu_hide(dev_menu);
}

void dev_menu_page_destroy(void) {
  if (dev_menu) {
    ui_menu_destroy(dev_menu);
    dev_menu = NULL;
  }
  if (dev_menu_screen) {
    lv_obj_del(dev_menu_screen);
    dev_menu_screen = NULL;
  }
  return_callback = NULL;
}
