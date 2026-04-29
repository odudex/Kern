// Capture Entropy Page - Reusable camera page for capturing entropy

#include "capture_entropy.h"

#include <bsp/esp-bsp.h>
#include <driver/ppa.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>
#include <math.h>
#include <string.h>
#include <wally_crypto.h>

#include "../components/video/video.h"
#include "../ui/dialog.h"
#include "../ui/theme.h"
#include "../utils/memory_utils.h"
#include "../utils/secure_mem.h"

static const char *TAG = "capture_entropy";

// Camera preview is a square sized to the smaller display dimension. Sensor
// outputs 1280x960 (binning mode); we take the full 960x960 vertical area
// (centered horizontally) and downscale with the PPA in a single pass.
//
// PPA uses Q4.4 fixed-point scaling (1/16 increments), so we quantize the
// scale down to the nearest 1/16 and derive the actual preview size from it.
//   wave_4b: crop 960, scale 12/16 -> 720x720 preview
//   wave_35: crop 960, scale  5/16 -> 300x300 preview
#define CAMERA_INPUT_WIDTH 1280
#define CAMERA_INPUT_HEIGHT 960
#define CAMERA_INPUT_CROP CAMERA_INPUT_HEIGHT
#define CAMERA_DIM_MIN                                                         \
  ((BSP_LCD_H_RES) < (BSP_LCD_V_RES) ? (BSP_LCD_H_RES) : (BSP_LCD_V_RES))
#define CAMERA_PPA_FRAG ((CAMERA_DIM_MIN * 16) / CAMERA_INPUT_CROP)
#define CAMERA_SIZE ((CAMERA_INPUT_CROP * CAMERA_PPA_FRAG) / 16)
#define CAMERA_WIDTH CAMERA_SIZE
#define CAMERA_HEIGHT CAMERA_SIZE
#define ENTROPY_THRESHOLD 6.0 // Minimum acceptable entropy (bits)

typedef enum {
  CAMERA_EVENT_TASK_RUN = BIT(0),
  CAMERA_EVENT_DELETE = BIT(1),
} camera_event_id_t;

static lv_obj_t *capture_screen = NULL;
static lv_obj_t *camera_img = NULL;
static void (*return_callback)(void) = NULL;

static int camera_handle = -1;
static lv_img_dsc_t img_dsc;
static bool video_initialized = false;
static EventGroupHandle_t camera_event_group = NULL;

static uint8_t *display_buffer_a = NULL;
static uint8_t *display_buffer_b = NULL;
static uint8_t *current_display_buffer = NULL;
static size_t display_buffer_size = 0;

static ppa_client_handle_t cam_ppa_client = NULL;

static volatile bool closing = false;
static volatile bool is_initialized = false;
static volatile int active_frame_ops = 0;

static uint8_t captured_entropy[32];
static volatile bool entropy_captured = false;
static volatile bool dialog_showing = false;

static void touch_event_cb(lv_event_t *e);
static void camera_frame_cb(uint8_t *camera_buf, uint8_t camera_buf_index,
                            uint32_t camera_buf_hes, uint32_t camera_buf_ves,
                            size_t camera_buf_len);

static void low_entropy_prompt_cb(bool retry, void *user_data) {
  (void)user_data;
  dialog_showing = false;
  if (!retry) {
    // User chose "No" - exit the capture page
    closing = true;
    if (return_callback)
      return_callback();
  }
  // If retry (Yes), do nothing - user stays on camera page
}

static uint8_t *allocate_buffer(size_t size) {
  // PPA writes directly into these buffers, so they must be cache-line aligned.
  size_t aligned = (size + CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1) &
                   ~(CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1);
  uint8_t *buf = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE,
                                          aligned, 1, MALLOC_CAP_SPIRAM);
  if (!buf)
    buf = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE, aligned, 1,
                                   MALLOC_CAP_INTERNAL);
  return buf;
}

static double calculate_shannon_entropy(const uint8_t *rgb565_data,
                                        size_t pixel_count) {
  // Allocate histogram for all 65536 possible RGB565 values
  uint32_t *histogram = heap_caps_calloc(65536, sizeof(uint32_t),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!histogram) {
    histogram = heap_caps_calloc(65536, sizeof(uint32_t),
                                 MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!histogram)
      return 0.0;
  }

  // Count pixel values
  const uint16_t *pixels = (const uint16_t *)rgb565_data;
  for (size_t i = 0; i < pixel_count; i++) {
    histogram[pixels[i]]++;
  }

  // Calculate entropy: H = -Σ(p × log2(p))
  double entropy = 0.0;
  for (int i = 0; i < 65536; i++) {
    if (histogram[i] > 0) {
      double p = (double)histogram[i] / pixel_count;
      entropy -= p * log2(p);
    }
  }

  free(histogram);
  return entropy;
}

static bool allocate_buffers(void) {
  display_buffer_size = CAMERA_WIDTH * CAMERA_HEIGHT * 2;
  display_buffer_size =
      (display_buffer_size + CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1) &
      ~(CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1);

  display_buffer_a = allocate_buffer(display_buffer_size);
  display_buffer_b = allocate_buffer(display_buffer_size);

  if (!display_buffer_a || !display_buffer_b) {
    SAFE_FREE_STATIC(display_buffer_a);
    SAFE_FREE_STATIC(display_buffer_b);
    display_buffer_size = 0;
    return false;
  }
  return true;
}

static void free_buffers(void) {
  current_display_buffer = NULL;
  SAFE_FREE_STATIC(display_buffer_a);
  SAFE_FREE_STATIC(display_buffer_b);
  display_buffer_size = 0;
}

static void camera_frame_cb(uint8_t *camera_buf, uint8_t camera_buf_index,
                            uint32_t camera_buf_hes, uint32_t camera_buf_ves,
                            size_t camera_buf_len) {
  __atomic_add_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);

  if (closing || !is_initialized || !camera_event_group) {
    __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  EventBits_t bits = xEventGroupGetBits(camera_event_group);
  if (!(bits & CAMERA_EVENT_TASK_RUN) || (bits & CAMERA_EVENT_DELETE)) {
    __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  if (!display_buffer_a || !display_buffer_b || !current_display_buffer ||
      !cam_ppa_client) {
    __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  uint8_t *back_buffer = (current_display_buffer == display_buffer_a)
                             ? display_buffer_b
                             : display_buffer_a;

  uint32_t in_w = camera_buf_hes ? camera_buf_hes : CAMERA_INPUT_WIDTH;
  uint32_t in_h = camera_buf_ves ? camera_buf_ves : CAMERA_INPUT_HEIGHT;
  uint32_t crop = (in_w < in_h) ? in_w : in_h;
  uint32_t crop_ox = (in_w - crop) / 2;
  uint32_t crop_oy = (in_h - crop) / 2;
  float scale = (float)CAMERA_WIDTH / (float)crop;

  ppa_srm_oper_config_t srm = {
      .in.buffer = camera_buf,
      .in.pic_w = in_w,
      .in.pic_h = in_h,
      .in.block_w = crop,
      .in.block_h = crop,
      .in.block_offset_x = crop_ox,
      .in.block_offset_y = crop_oy,
      .in.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .out.buffer = back_buffer,
      .out.buffer_size = display_buffer_size,
      .out.pic_w = CAMERA_WIDTH,
      .out.pic_h = CAMERA_HEIGHT,
      .out.block_offset_x = 0,
      .out.block_offset_y = 0,
      .out.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
      .scale_x = scale,
      .scale_y = scale,
      .mode = PPA_TRANS_MODE_BLOCKING,
  };
  if (ppa_do_scale_rotate_mirror(cam_ppa_client, &srm) != ESP_OK) {
    __atomic_sub_fetch(&active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  if (!closing && !dialog_showing && bsp_display_lock(0)) {
    if (!closing && camera_img) {
      current_display_buffer = back_buffer;
      img_dsc.data = back_buffer;
      lv_img_set_src(camera_img, &img_dsc);
      lv_refr_now(NULL);
    }
    bsp_display_unlock();
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

  // Apply the wider AE hysteresis + gain cap — without this, the sensor keeps
  // its init-time ±8% window and uncapped gain ceiling, which causes
  // square-wave luminance pulsing under low-light, high-contrast scenes.
  app_video_set_ae_target(camera_handle, 80);

  ppa_client_config_t ppa_cfg = {.oper_type = PPA_OPERATION_SRM};
  if (ppa_register_client(&ppa_cfg, &cam_ppa_client) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to register PPA client");
    cam_ppa_client = NULL;
    return false;
  }

  return true;
}

static void touch_event_cb(lv_event_t *e) {
  if (closing || dialog_showing || !current_display_buffer)
    return;

  size_t pixel_count = CAMERA_WIDTH * CAMERA_HEIGHT;
  double entropy =
      calculate_shannon_entropy(current_display_buffer, pixel_count);

  if (entropy < ENTROPY_THRESHOLD) {
    dialog_showing = true;
    dialog_show_confirm("Low entropy\nTry again?", low_entropy_prompt_cb, NULL,
                        DIALOG_STYLE_OVERLAY);
    return;
  }

  unsigned char hash[SHA256_LEN];
  size_t buffer_size = pixel_count * 2;

  if (wally_sha256(current_display_buffer, buffer_size, hash, sizeof(hash)) ==
      WALLY_OK) {
    memcpy(captured_entropy, hash, 32);
    entropy_captured = true;
    closing = true;
    if (return_callback)
      return_callback();
  }
}

void capture_entropy_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  (void)parent;

  return_callback = return_cb;
  closing = false;
  is_initialized = false;
  dialog_showing = false;
  active_frame_ops = 0;
  entropy_captured = false;
  secure_memzero(captured_entropy, sizeof(captured_entropy));

  capture_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(capture_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(capture_screen, lv_color_hex(0x1e1e1e), 0);
  lv_obj_set_style_bg_opa(capture_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(capture_screen, 0, 0);
  lv_obj_set_style_pad_all(capture_screen, 0, 0);
  lv_obj_set_style_radius(capture_screen, 0, 0);
  lv_obj_clear_flag(capture_screen, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *frame = lv_obj_create(capture_screen);
  lv_obj_set_size(frame, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(frame);
  lv_obj_set_style_bg_opa(frame, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(frame, 0, 0);
  lv_obj_set_style_pad_all(frame, 0, 0);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(frame, touch_event_cb, LV_EVENT_CLICKED, NULL);

  camera_img = lv_img_create(frame);
  lv_obj_set_size(camera_img, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(camera_img);
  lv_obj_clear_flag(camera_img, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(camera_img, lv_color_white(), 0);
  lv_obj_set_style_bg_opa(camera_img, LV_OPA_COVER, 0);

  lv_obj_t *title =
      theme_create_label(capture_screen, "Capture Entropy", false);
  theme_apply_label(title, true);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 8);

  lv_obj_t *instruction =
      theme_create_label(capture_screen, "Tap to capture", false);
  lv_obj_set_style_text_color(instruction, highlight_color(), 0);
  lv_obj_align(instruction, LV_ALIGN_BOTTOM_MID, 0, -10);

  if (!camera_init()) {
    ESP_LOGE(TAG, "Failed to initialize camera");
    return;
  }

  is_initialized = true;
}

void capture_entropy_page_show(void) {
  if (is_initialized && !closing && capture_screen)
    lv_obj_clear_flag(capture_screen, LV_OBJ_FLAG_HIDDEN);
}

void capture_entropy_page_hide(void) {
  if (is_initialized && !closing && capture_screen)
    lv_obj_add_flag(capture_screen, LV_OBJ_FLAG_HIDDEN);
}

void capture_entropy_page_destroy(void) {
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

  bool locked = bsp_display_lock(1000);
  camera_img = NULL;
  if (capture_screen) {
    lv_obj_del(capture_screen);
    capture_screen = NULL;
  }
  if (locked)
    bsp_display_unlock();

  free_buffers();

  if (cam_ppa_client) {
    ppa_unregister_client(cam_ppa_client);
    cam_ppa_client = NULL;
  }

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
  dialog_showing = false;
  active_frame_ops = 0;
}

bool capture_entropy_get_hash(uint8_t *hash_out) {
  if (!entropy_captured || !hash_out)
    return false;
  memcpy(hash_out, captured_entropy, 32);
  return true;
}

bool capture_entropy_has_result(void) { return entropy_captured; }

void capture_entropy_clear(void) {
  entropy_captured = false;
  secure_memzero(captured_entropy, sizeof(captured_entropy));
}
