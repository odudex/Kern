// Capture Entropy Page - Reusable camera page for capturing entropy

#include "capture_entropy.h"
#include "../qr/frame_pool.h"
#include "../utils/camera_pipeline.h"
#include "../utils/session_cleanup.h"

#include <bsp/esp-bsp.h>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <lvgl.h>
#include <string.h>
#include <wally_crypto.h>

#include "../core/crypto_utils.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include "../utils/estimated_entropy.h"
#include "../utils/memory_utils.h"
#include "../utils/secure_mem.h"
#include "video.h"

static const char *TAG = "capture_entropy";

// Camera preview is a square sized to the smaller display dimension, cut from
// the centre of the sensor frame (OV5647: 800x800) and downscaled with the PPA
// in a single pass. PPA uses Q4.4 fixed-point scaling (1/16 increments), so
// app_video_ppa_snap_crop() picks the largest crop that scales exactly onto it.
//   wave_4b: crop 768, scale 15/16 -> 720x720 preview
//   wave_35: crop 640, scale  8/16 -> 320x320 preview
#define CAMERA_INPUT_WIDTH 800
#define CAMERA_INPUT_HEIGHT 800
#define CAMERA_DIM_MIN                                                         \
  ((BSP_LCD_H_RES) < (BSP_LCD_V_RES) ? (BSP_LCD_H_RES) : (BSP_LCD_V_RES))
#define CAMERA_SIZE                                                            \
  ((CAMERA_DIM_MIN) < (CAMERA_INPUT_HEIGHT) ? (CAMERA_DIM_MIN)                 \
                                            : (CAMERA_INPUT_HEIGHT))
#define CAMERA_WIDTH CAMERA_SIZE
#define CAMERA_HEIGHT CAMERA_SIZE
#define PREVIEW_UPDATE_INTERVAL_MS 30
// Minimum acceptable bits per pixel. Not derived from the 128/256 bits the seed
// needs. It is a sanity gate on the frame, set high only because the camera is
// a rich source and demanding more costs nothing: what fails it is a covered
// lens, a dark room, or a blank wall.
#define ESTIMATED_ENTROPY_THRESHOLD 5.0f
#define ESTIMATED_ENTROPY_UNAVAILABLE (-1.0f)

static lv_obj_t *capture_screen = NULL;
static lv_obj_t *camera_img = NULL;
static lv_timer_t *preview_timer = NULL;
static void (*return_callback)(void) = NULL;

static lv_img_dsc_t img_dsc;
static camera_pipeline_t pipeline;

// Lock-free preview pool handed from the camera task to the LVGL timer: the
// camera task never waits on bsp_display_lock, skips PPA when LVGL has not
// consumed the previous frame or a dialog is open, and never overwrites the
// CLAIMED buffer while touch_event_cb hashes it.
static uint8_t *preview_buffers[FRAME_POOL_SIZE];
static const uint8_t *current_display_buffer = NULL;
static size_t display_buffer_size = 0;
static frame_pool_t preview_pool;
static portMUX_TYPE pool_lock = portMUX_INITIALIZER_UNLOCKED;

static volatile bool closing = false;
static volatile bool is_initialized = false;

static uint8_t captured_entropy[32];
static volatile bool entropy_captured = false;
static volatile bool dialog_showing = false;

static void touch_event_cb(lv_event_t *e);

static void low_entropy_prompt_cb(bool retry, void *user_data) {
  (void)user_data;
  dialog_showing = false;
  if (!retry) {
    // User chose "No" - exit the capture page
    closing = true;
    camera_pipeline_request_stop(&pipeline);
    if (return_callback)
      return_callback();
  }
  // If retry (Yes), do nothing - user stays on camera page
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (closing)
    return;
  closing = true;
  camera_pipeline_request_stop(&pipeline);
  if (return_callback)
    return_callback();
}

// Returns bits per pixel, or ESTIMATED_ENTROPY_UNAVAILABLE if the histogram
// could not be allocated - a distinct outcome from a genuinely flat frame.
static float calculate_estimated_shannon_entropy(const uint8_t *rgb565_data,
                                                 size_t pixel_count) {
  // Allocate histogram for all 65536 possible RGB565 values
  uint32_t *histogram =
      heap_caps_calloc(65536, sizeof(uint32_t), MALLOC_CAP_SPIRAM);
  if (!histogram) {
    histogram = heap_caps_calloc(65536, sizeof(uint32_t), MALLOC_CAP_INTERNAL);
    if (!histogram)
      return ESTIMATED_ENTROPY_UNAVAILABLE;
  }

  // Count pixel values
  const uint16_t *pixels = (const uint16_t *)rgb565_data;
  for (size_t i = 0; i < pixel_count; i++) {
    histogram[pixels[i]]++;
  }

  float estimated_entropy =
      estimated_shannon_entropy_from_counts_f(histogram, 65536, pixel_count);

  free(histogram);
  return estimated_entropy;
}

static void reset_preview_pool(void) {
  portENTER_CRITICAL_SAFE(&pool_lock);
  preview_pool = (frame_pool_t){0};
  portEXIT_CRITICAL_SAFE(&pool_lock);
  current_display_buffer = NULL;
}

static void free_buffers(void) {
  reset_preview_pool();
  for (size_t i = 0; i < FRAME_POOL_SIZE; i++)
    SAFE_FREE_STATIC(preview_buffers[i]);
  display_buffer_size = 0;
}

static bool allocate_buffers(void) {
  if (preview_buffers[0]) {
    // Kept by a prior shutdown that could not confirm PPA idle.
    if (!camera_pipeline_is_idle(&pipeline)) {
      ESP_LOGE(TAG, "Camera display buffers are still in use");
      return false;
    }
    reset_preview_pool();
    return true;
  }

  display_buffer_size =
      camera_pipeline_align_size((size_t)CAMERA_WIDTH * CAMERA_HEIGHT * 2);

  for (size_t i = 0; i < FRAME_POOL_SIZE; i++) {
    preview_buffers[i] = camera_pipeline_alloc_buffer(display_buffer_size);
    if (!preview_buffers[i]) {
      free_buffers();
      return false;
    }
  }
  reset_preview_pool();
  return true;
}

static void on_camera_frame(ppa_client_handle_t ppa, uint8_t *camera_buf,
                            uint32_t width, uint32_t height, size_t len,
                            void *ctx) {
  (void)len;
  (void)ctx;

  if (closing || !is_initialized || dialog_showing || !preview_buffers[0])
    return;

  // Skip PPA if LVGL has not yet claimed the previous finished preview frame.
  int index = -1;
  portENTER_CRITICAL_SAFE(&pool_lock);
  if (!frame_pool_has_ready(&preview_pool))
    index = frame_pool_acquire(&preview_pool);
  portEXIT_CRITICAL_SAFE(&pool_lock);
  if (index < 0)
    return;

  uint32_t in_w = width ? width : CAMERA_INPUT_WIDTH;
  uint32_t in_h = height ? height : CAMERA_INPUT_HEIGHT;

  esp_err_t err = camera_pipeline_scale_rgb565_crop(
      ppa, camera_buf, in_w, in_h, 0, preview_buffers[index],
      display_buffer_size, CAMERA_WIDTH);

  portENTER_CRITICAL_SAFE(&pool_lock);
  if (err == ESP_OK)
    frame_pool_finish(&preview_pool, index);
  else
    frame_pool_abandon(&preview_pool, index);
  portEXIT_CRITICAL_SAFE(&pool_lock);
}

static void preview_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!camera_img || closing || dialog_showing || !preview_buffers[0])
    return;

  portENTER_CRITICAL_SAFE(&pool_lock);
  int index = frame_pool_claim(&preview_pool);
  portEXIT_CRITICAL_SAFE(&pool_lock);
  if (index < 0)
    return;

  current_display_buffer = preview_buffers[index];
  img_dsc.data = current_display_buffer;
  lv_img_set_src(camera_img, &img_dsc);
  // Live camera preview counts as activity: hold off screensaver/session lock
  lv_display_trigger_activity(NULL);
}

static bool camera_init(void) {
  if (app_video_is_streaming())
    return true;

  img_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565,
                 .w = CAMERA_WIDTH,
                 .h = CAMERA_HEIGHT},
      .data_size = CAMERA_WIDTH * CAMERA_HEIGHT * 2,
      .data = NULL,
  };

  if (!allocate_buffers())
    return false;

  const camera_pipeline_config_t cfg = {
      .on_frame = on_camera_frame,
      .on_ppa_done = NULL,
      .is_idle = NULL,
      .ctx = NULL,
      .max_pending_trans_num = 1,
      .core_id = 0,
      .stir_entropy = true,
  };
  if (!camera_pipeline_start(&pipeline, &cfg))
    return false;

  // Apply the wider AE hysteresis + gain cap - without this, the sensor keeps
  // its init-time +/-8% window and uncapped gain ceiling, which causes
  // square-wave luminance pulsing under low-light, high-contrast scenes.
  app_video_set_ae_target(80);

  return true;
}

static void touch_event_cb(lv_event_t *e) {
  (void)e;
  if (closing || dialog_showing || !current_display_buffer)
    return;

  size_t pixel_count = CAMERA_WIDTH * CAMERA_HEIGHT;
  float estimated_entropy =
      calculate_estimated_shannon_entropy(current_display_buffer, pixel_count);

  if (estimated_entropy < 0.0f) {
    dialog_show_error_timeout("Not enough memory to check estimated entropy",
                              NULL, 0);
    return;
  }

  if (estimated_entropy < ESTIMATED_ENTROPY_THRESHOLD) {
    dialog_showing = true;
    dialog_show_confirm("Low estimated entropy\nTry again?",
                        low_entropy_prompt_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }

  // Fold the hardware TRNG into the frame digest. A photo of a scene the
  // attacker knows has plenty of pixel-value diversity and no secrecy, so the
  // frame alone cannot be trusted to be unpredictable. Hashing rather than
  // XOR-ing means a TRNG that could observe the frame still cannot steer the
  // result: it would have to invert SHA-256 to land on a chosen seed.
  uint8_t mixed[SHA256_LEN * 2];
  size_t buffer_size = pixel_count * 2;
  bool mixed_ok = false;

  if (wally_sha256(current_display_buffer, buffer_size, mixed, SHA256_LEN) ==
      WALLY_OK) {
    mixed_ok =
        crypto_random_bytes(mixed + SHA256_LEN, SHA256_LEN) == CRYPTO_OK &&
        wally_sha256(mixed, sizeof(mixed), captured_entropy,
                     sizeof(captured_entropy)) == WALLY_OK;
  }
  secure_memzero(mixed, sizeof(mixed));

  if (!mixed_ok) {
    dialog_show_error_timeout("Failed to derive entropy", NULL, 0);
    return;
  }

  entropy_captured = true;
  closing = true;
  camera_pipeline_request_stop(&pipeline);
  if (return_callback)
    return_callback();
}

void capture_entropy_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(capture_entropy_page_destroy);
  (void)parent;

  return_callback = return_cb;
  closing = false;
  is_initialized = false;
  dialog_showing = false;
  entropy_captured = false;
  secure_memzero(captured_entropy, sizeof(captured_entropy));

  if (!app_video_is_ready()) {
    dialog_show_error_timeout("Camera not available", return_callback, 0);
    return;
  }

  capture_screen = theme_create_page_container(lv_screen_active());

  lv_obj_t *frame = lv_obj_create(capture_screen);
  lv_obj_set_size(frame, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(frame);
  theme_apply_transparent_container(frame);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(frame, touch_event_cb, LV_EVENT_CLICKED, NULL);

  camera_img = lv_img_create(frame);
  lv_obj_set_size(camera_img, CAMERA_WIDTH, CAMERA_HEIGHT);
  lv_obj_center(camera_img);
  lv_obj_clear_flag(camera_img, LV_OBJ_FLAG_SCROLLABLE);

  theme_create_page_title(capture_screen, "Capture Image");

  lv_obj_t *instruction =
      theme_create_label(capture_screen, "Tap to capture", false);
  lv_obj_set_style_text_color(instruction, highlight_color(), 0);
  lv_obj_align(instruction, LV_ALIGN_BOTTOM_MID, 0, -theme_default_padding());

  ui_create_back_button(capture_screen, back_btn_cb);

  if (!camera_init()) {
    ESP_LOGE(TAG, "Failed to initialize camera");
    return;
  }

  preview_timer =
      lv_timer_create(preview_timer_cb, PREVIEW_UPDATE_INTERVAL_MS, NULL);
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
  session_cleanup_unregister(capture_entropy_page_destroy);
  closing = true;
  is_initialized = false;

  if (preview_timer) {
    lv_timer_del(preview_timer);
    preview_timer = NULL;
  }

  bool pipeline_idle = camera_pipeline_stop(&pipeline);

  bool locked = bsp_display_lock(1000);
  camera_img = NULL;
  if (capture_screen) {
    lv_obj_del(capture_screen);
    capture_screen = NULL;
  }
  if (locked)
    bsp_display_unlock();

  if (pipeline_idle)
    free_buffers();

  capture_entropy_clear();

  return_callback = NULL;
  closing = false;
  dialog_showing = false;
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
