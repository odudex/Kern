#include "snapshot.h"

#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>
#include <sd_card.h>
#include <stdio.h>
#include <string.h>

#include "../../../../components/video/video.h"
#include "../../../ui_components/simple_dialog.h"
#include "../../../ui_components/theme.h"
#include "../../../ui_components/ui_input_helpers.h"
#include "../../../utils/memory_utils.h"

static const char *TAG = "snapshot";

#define CAMERA_WIDTH 640
#define CAMERA_HEIGHT 640
#define GRAY_WIDTH 320
#define GRAY_HEIGHT 320

typedef enum {
  CAMERA_EVENT_TASK_RUN = BIT(0),
  CAMERA_EVENT_DELETE = BIT(1),
} camera_event_id_t;

static const uint8_t r5_to_gray[32] = {
    0,  2,  4,  7,  9,  12, 14, 17, 19, 22, 24, 27, 29, 31, 34, 36,
    39, 41, 44, 46, 49, 51, 53, 56, 58, 61, 63, 66, 68, 71, 73, 76};

static const uint8_t g6_to_gray[64] = {
    0,   2,   4,   7,   9,   11,  14,  16,  18,  21,  23,  25,  28,
    30,  32,  35,  37,  39,  42,  44,  46,  49,  51,  53,  56,  58,
    60,  63,  65,  67,  70,  72,  74,  77,  79,  81,  84,  86,  88,
    91,  93,  95,  98,  100, 102, 105, 107, 109, 112, 114, 116, 119,
    121, 123, 126, 128, 130, 133, 135, 137, 140, 142, 144, 147};

static const uint8_t b5_to_gray[32] = {
    0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 29};

static lv_obj_t *snapshot_screen = NULL;
static lv_obj_t *camera_img = NULL;
static lv_obj_t *capture_btn = NULL;
static lv_obj_t *back_btn = NULL;
static void (*return_callback)(void) = NULL;

static int camera_handle = -1;
static lv_img_dsc_t img_dsc;
static bool video_initialized = false;
static EventGroupHandle_t camera_event_group = NULL;

static uint8_t *display_buffer_a = NULL;
static uint8_t *display_buffer_b = NULL;
static uint8_t *current_display_buffer = NULL;
static uint8_t *grayscale_buffer = NULL;

static volatile bool closing = false;
static volatile bool is_initialized = false;
static volatile int active_frame_ops = 0;

static void back_btn_cb(lv_event_t *e);
static void capture_btn_cb(lv_event_t *e);
static void camera_frame_cb(uint8_t *camera_buf, uint8_t camera_buf_index,
                            uint32_t camera_buf_hes, uint32_t camera_buf_ves,
                            size_t camera_buf_len);

static uint8_t *allocate_buffer(size_t size) {
  uint8_t *buf = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!buf)
    buf = heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  return buf;
}

static bool allocate_buffers(void) {
  size_t display_size = CAMERA_WIDTH * CAMERA_HEIGHT * 2;

  display_buffer_a = allocate_buffer(display_size);
  display_buffer_b = allocate_buffer(display_size);
  grayscale_buffer = allocate_buffer(GRAY_WIDTH * GRAY_HEIGHT);

  if (!display_buffer_a || !display_buffer_b || !grayscale_buffer) {
    SAFE_FREE_STATIC(display_buffer_a);
    SAFE_FREE_STATIC(display_buffer_b);
    SAFE_FREE_STATIC(grayscale_buffer);
    return false;
  }
  return true;
}

static void free_buffers(void) {
  current_display_buffer = NULL;
  SAFE_FREE_STATIC(display_buffer_a);
  SAFE_FREE_STATIC(display_buffer_b);
  SAFE_FREE_STATIC(grayscale_buffer);
}

static void rgb565_to_grayscale_downsample(const uint8_t *rgb565_data,
                                           uint8_t *gray_data) {
  const uint16_t *pixels = (const uint16_t *)rgb565_data;

  for (uint32_t dst_y = 0; dst_y < GRAY_HEIGHT; dst_y++) {
    uint32_t src_y = dst_y * 2;
    for (uint32_t dst_x = 0; dst_x < GRAY_WIDTH; dst_x++) {
      uint16_t pixel = pixels[src_y * CAMERA_WIDTH + dst_x * 2];
      uint8_t r5 = (pixel >> 11) & 0x1F;
      uint8_t g6 = (pixel >> 5) & 0x3F;
      uint8_t b5 = pixel & 0x1F;
      gray_data[dst_y * GRAY_WIDTH + dst_x] =
          r5_to_gray[r5] + g6_to_gray[g6] + b5_to_gray[b5];
    }
  }
}

static esp_err_t save_pgm_file(const uint8_t *gray_data, const char *path) {
  char header[32];
  int header_len = snprintf(header, sizeof(header), "P5\n%d %d\n255\n",
                            GRAY_WIDTH, GRAY_HEIGHT);

  size_t data_size = GRAY_WIDTH * GRAY_HEIGHT;
  size_t total_size = header_len + data_size;

  uint8_t *file_data = malloc(total_size);
  if (!file_data)
    return ESP_ERR_NO_MEM;

  memcpy(file_data, header, header_len);
  memcpy(file_data + header_len, gray_data, data_size);

  esp_err_t ret = sd_card_write_file(path, file_data, total_size);
  free(file_data);
  return ret;
}

static void horizontal_crop(const uint8_t *camera_buf, uint8_t *display_buf,
                            uint32_t camera_width, uint32_t camera_height) {
  uint32_t crop_offset = (camera_width - CAMERA_WIDTH) / 2;
  const uint16_t *src = (const uint16_t *)camera_buf;
  uint16_t *dst = (uint16_t *)display_buf;

  for (uint32_t y = 0; y < camera_height; y++) {
    memcpy(dst + y * CAMERA_WIDTH, src + y * camera_width + crop_offset,
           CAMERA_WIDTH * 2);
  }
}

static void camera_frame_cb(uint8_t *camera_buf, uint8_t camera_buf_index,
                            uint32_t camera_buf_hes, uint32_t camera_buf_ves,
                            size_t camera_buf_len) {
  if (closing || !is_initialized || !camera_event_group)
    return;

  EventBits_t bits = xEventGroupGetBits(camera_event_group);
  if (!(bits & CAMERA_EVENT_TASK_RUN) || (bits & CAMERA_EVENT_DELETE))
    return;

  __atomic_add_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);

  if (!display_buffer_a || !display_buffer_b || !current_display_buffer) {
    __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  uint8_t *back_buffer = (current_display_buffer == display_buffer_a)
                             ? display_buffer_b
                             : display_buffer_a;

  horizontal_crop(camera_buf, back_buffer, camera_buf_hes, camera_buf_ves);

  if (!closing && camera_img && lvgl_port_lock(0)) {
    current_display_buffer = back_buffer;
    img_dsc.data = current_display_buffer;
    lv_img_set_src(camera_img, &img_dsc);
    lv_refr_now(NULL);
    lvgl_port_unlock();
  }

  __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
}

static bool camera_init(void) {
  if (video_initialized)
    return true;

  camera_event_group = xEventGroupCreate();
  if (!camera_event_group)
    return false;

  xEventGroupSetBits(camera_event_group, CAMERA_EVENT_TASK_RUN);

  i2c_master_bus_handle_t i2c_handle = bsp_i2c_get_handle();
  if (!i2c_handle)
    return false;

  if (app_video_main(i2c_handle) != ESP_OK)
    return false;
  video_initialized = true;

  camera_handle = app_video_open(CAM_DEV_PATH, APP_VIDEO_FMT_RGB565);
  if (camera_handle < 0)
    return false;

  ESP_ERROR_CHECK(app_video_register_frame_operation_cb(camera_frame_cb));

  img_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565,
                 .w = CAMERA_WIDTH,
                 .h = CAMERA_HEIGHT},
      .data_size = CAMERA_WIDTH * CAMERA_HEIGHT * 2,
      .data = NULL,
  };

  if (!allocate_buffers())
    return false;

  current_display_buffer = display_buffer_a;
  img_dsc.data = current_display_buffer;

  ESP_ERROR_CHECK(app_video_set_bufs(camera_handle, CAM_BUF_NUM, NULL));

  if (app_video_stream_task_start(camera_handle, 0) != ESP_OK)
    return false;

  return true;
}

static void back_btn_cb(lv_event_t *e) {
  if (closing)
    return;
  closing = true;
  if (return_callback)
    return_callback();
}

static void capture_btn_cb(lv_event_t *e) {
  if (closing || !current_display_buffer || !grayscale_buffer)
    return;

  if (!sd_card_is_mounted()) {
    if (sd_card_init() != ESP_OK) {
      show_simple_dialog("Error", "Failed to mount SD card");
      return;
    }
  }

  rgb565_to_grayscale_downsample(current_display_buffer, grayscale_buffer);

  char filename[64];
  snprintf(filename, sizeof(filename), SD_CARD_MOUNT_POINT "/snap_%lld.pgm",
           (long long)(esp_timer_get_time() / 1000));

  if (save_pgm_file(grayscale_buffer, filename) == ESP_OK) {
    char msg[80];
    snprintf(msg, sizeof(msg), "Saved: %s", strrchr(filename, '/') + 1);
    show_simple_dialog("Snapshot", msg);
  } else {
    show_simple_dialog("Error", "Failed to save snapshot");
  }
}

void snapshot_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  (void)parent;

  return_callback = return_cb;
  closing = false;
  is_initialized = false;
  active_frame_ops = 0;

  snapshot_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(snapshot_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(snapshot_screen, lv_color_hex(0x1e1e1e), 0);
  lv_obj_set_style_bg_opa(snapshot_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(snapshot_screen, 0, 0);
  lv_obj_set_style_pad_all(snapshot_screen, 0, 0);
  lv_obj_set_style_radius(snapshot_screen, 0, 0);
  lv_obj_clear_flag(snapshot_screen, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *frame = lv_obj_create(snapshot_screen);
  lv_obj_set_size(frame, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(frame);
  lv_obj_set_style_bg_opa(frame, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(frame, 0, 0);
  lv_obj_set_style_pad_all(frame, 0, 0);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_SCROLLABLE);

  camera_img = lv_img_create(frame);
  lv_obj_set_size(camera_img, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(camera_img);
  lv_obj_clear_flag(camera_img, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(camera_img, lv_color_white(), 0);
  lv_obj_set_style_bg_opa(camera_img, LV_OPA_COVER, 0);

  lv_obj_t *title = theme_create_label(snapshot_screen, "Snapshot", false);
  theme_apply_label(title, true);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

  back_btn = ui_create_back_button(snapshot_screen, back_btn_cb);

  capture_btn = theme_create_button(snapshot_screen, "Capture", true);
  lv_obj_align(capture_btn, LV_ALIGN_BOTTOM_MID, 0, -20);
  lv_obj_add_event_cb(capture_btn, capture_btn_cb, LV_EVENT_CLICKED, NULL);

  if (!camera_init()) {
    ESP_LOGE(TAG, "Failed to initialize camera");
    return;
  }

  is_initialized = true;
}

void snapshot_page_show(void) {
  if (is_initialized && !closing && snapshot_screen)
    lv_obj_clear_flag(snapshot_screen, LV_OBJ_FLAG_HIDDEN);
}

void snapshot_page_hide(void) {
  if (is_initialized && !closing && snapshot_screen)
    lv_obj_add_flag(snapshot_screen, LV_OBJ_FLAG_HIDDEN);
}

void snapshot_page_destroy(void) {
  closing = true;
  is_initialized = false;

  if (camera_event_group) {
    xEventGroupClearBits(camera_event_group, CAMERA_EVENT_TASK_RUN);
    xEventGroupSetBits(camera_event_group, CAMERA_EVENT_DELETE);
  }

  int wait = 0;
  while (__atomic_load_n(&active_frame_ops, __ATOMIC_SEQ_CST) > 0 &&
         wait < 30) {
    vTaskDelay(pdMS_TO_TICKS(10));
    wait++;
  }

  if (camera_handle >= 0) {
    app_video_stream_task_stop(camera_handle);
    vTaskDelay(pdMS_TO_TICKS(50));
    app_video_close(camera_handle);
    camera_handle = -1;
  }

  bool locked = lvgl_port_lock(1000);
  camera_img = NULL;
  capture_btn = NULL;
  back_btn = NULL;
  if (snapshot_screen) {
    lv_obj_del(snapshot_screen);
    snapshot_screen = NULL;
  }
  if (locked)
    lvgl_port_unlock();

  free_buffers();

  if (video_initialized) {
    app_video_deinit();
    video_initialized = false;
  }

  if (camera_event_group) {
    vEventGroupDelete(camera_event_group);
    camera_event_group = NULL;
  }

  return_callback = NULL;
  closing = false;
  active_frame_ops = 0;
}
