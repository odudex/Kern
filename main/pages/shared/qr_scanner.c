// QR Scanner Page (LVGL UI: preview, progress overlay, camera settings)

#include "qr_scanner.h"
#include "../../core/settings.h"
#include "../../qr/parser.h"
#include "../../qr/progress.h"
#include "../../qr/scanner_engine.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session_cleanup.h"
#include "video.h"
#include <bsp/esp-bsp.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>

#define CAMERA_SCREEN_DIM_MIN                                                  \
  ((BSP_LCD_H_RES) < (BSP_LCD_V_RES) ? (BSP_LCD_H_RES) : (BSP_LCD_V_RES))
#define PROGRESS_BAR_HEIGHT 20
#define PROGRESS_FRAME_INSET 6
// One LVGL timer presents the newest preview frame, applies scan progress and
// notices completion. It also caps the preview rate below the sensor's, which
// leaves PSRAM bandwidth to the decoder.
#define UI_UPDATE_INTERVAL_MS 30

static const char *TAG = "QR_SCANNER";

static lv_obj_t *qr_scanner_screen = NULL;
static lv_obj_t *camera_img = NULL;
static lv_obj_t *progress_frame = NULL;
static lv_obj_t *progress_grid = NULL;
static lv_obj_t *progress_label = NULL;
static qr_part_progress_t displayed_progress;
static qr_progress_grid_t progress_layout;
static qr_progress_canvas_t progress_canvas;
static lv_obj_t *ur_progress_bar = NULL;
static lv_obj_t *ur_progress_indicator = NULL;
static int ur_progress_bar_inner_width = 0;
static void (*return_callback)(void) = NULL;

static lv_img_dsc_t img_refresh_dsc;
static lv_timer_t *completion_timer = NULL;

static volatile bool closing = false;
static volatile bool is_fully_initialized = false;
static volatile bool destruction_in_progress = false;

// Camera settings overlay
static lv_obj_t *settings_overlay = NULL;
static lv_obj_t *ae_slider = NULL;
static lv_obj_t *focus_slider = NULL;
static bool has_focus_motor = false;
static bool has_ae_control = false;

// The canvas only borrows its pixels, so they must outlive it: tie the buffer
// to the widget rather than to the order the page is torn down in.
static void progress_grid_deleted_cb(lv_event_t *event) {
  lv_draw_buf_destroy(lv_event_get_user_data(event));
}

// The grid covers the camera preview, which LVGL redraws on every frame. One
// cell per draw task would queue up to two thousand tasks per frame, so cells
// are painted into a canvas when they change and blitted as a single image.
static void create_progress_grid(void) {
  lv_draw_buf_t *buf =
      lv_draw_buf_create(progress_layout.width, progress_layout.height,
                         LV_COLOR_FORMAT_RGB565, LV_STRIDE_AUTO);
  if (!buf)
    return;

  progress_grid = lv_canvas_create(progress_frame);
  if (!progress_grid) {
    lv_draw_buf_destroy(buf);
    return;
  }
  lv_canvas_set_draw_buf(progress_grid, buf);
  lv_obj_add_event_cb(progress_grid, progress_grid_deleted_cb, LV_EVENT_DELETE,
                      buf);
  lv_obj_set_size(progress_grid, progress_layout.width, progress_layout.height);
  lv_obj_align(progress_grid, LV_ALIGN_BOTTOM_MID, 0, 0);

  progress_canvas = (qr_progress_canvas_t){
      .pixels = (uint16_t *)buf->data,
      .stride = buf->header.stride / sizeof(uint16_t),
      .gap = lv_color_to_u16(panel_color()),
      .missing = lv_color_to_u16(bg_color()),
      .missing_border = lv_color_to_u16(
          lv_color_mix(secondary_color(), bg_color(), LV_OPA_50)),
      .received = lv_color_to_u16(primary_color()),
      .latest = lv_color_to_u16(highlight_color()),
  };
}

static void create_progress_indicators(int total_parts) {
  if (total_parts <= 1 || !qr_scanner_screen)
    return;

  lv_obj_update_layout(qr_scanner_screen);
  int width = lv_obj_get_width(qr_scanner_screen) * 80 / 100;
  progress_layout =
      qr_progress_grid_layout(total_parts, width - 2 * PROGRESS_FRAME_INSET);
  if (!progress_layout.columns)
    return;

  progress_frame = lv_obj_create(qr_scanner_screen);
  theme_apply_frame(progress_frame);
  lv_obj_set_style_bg_opa(progress_frame, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(progress_frame, PROGRESS_FRAME_INSET - 2, 0);
  lv_obj_remove_flag(progress_frame, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(progress_frame, LV_OBJ_FLAG_EVENT_BUBBLE);

  progress_label = theme_create_label(progress_frame, "", false);
  lv_obj_align(progress_label, LV_ALIGN_TOP_MID, 0, 0);

  // Without memory for the grid the frame count alone still shows progress.
  create_progress_grid();
  int height =
      lv_font_get_line_height(theme_font_small()) + 2 * PROGRESS_FRAME_INSET;
  if (progress_grid)
    height += progress_layout.height + 4;
  lv_obj_set_size(progress_frame,
                  progress_layout.width + 2 * PROGRESS_FRAME_INSET, height);
  lv_obj_align(progress_frame, LV_ALIGN_BOTTOM_MID, 0, -10);
}

static void update_progress_indicators(const qr_part_progress_t *progress) {
  bool created = false;
  if (!progress_frame) {
    create_progress_indicators(progress->total);
    if (!progress_frame)
      return;
    created = true;
  } else if (displayed_progress.received == progress->received &&
             displayed_progress.latest == progress->latest) {
    return;
  }

  if (created || displayed_progress.received != progress->received)
    lv_label_set_text_fmt(progress_label, "%d / %d frames", progress->received,
                          progress->total);
  if (progress_grid &&
      qr_progress_paint(&progress_canvas, &progress_layout,
                        created ? NULL : &displayed_progress, progress))
    lv_obj_invalidate(progress_grid);
  displayed_progress = *progress;
}

static void cleanup_progress_indicators(void) {
  progress_frame = NULL;
  progress_grid = NULL;
  progress_label = NULL;
  progress_canvas = (qr_progress_canvas_t){0};
  displayed_progress = (qr_part_progress_t){0};
  progress_layout = (qr_progress_grid_t){0};
}

static void create_ur_progress_bar(void) {
  if (!qr_scanner_screen || ur_progress_bar)
    return;

  int bar_width = lv_obj_get_width(qr_scanner_screen) * 80 / 100;
  int bar_height = PROGRESS_BAR_HEIGHT;
  ur_progress_bar_inner_width = bar_width - 4;

  ur_progress_bar = lv_obj_create(qr_scanner_screen);
  lv_obj_set_size(ur_progress_bar, bar_width, bar_height);
  lv_obj_align(ur_progress_bar, LV_ALIGN_BOTTOM_MID, 0, -10);
  theme_apply_frame(ur_progress_bar);
  lv_obj_set_style_pad_all(ur_progress_bar, 2, 0);

  ur_progress_indicator = lv_obj_create(ur_progress_bar);
  lv_obj_set_size(ur_progress_indicator, 0, 12);
  lv_obj_set_pos(ur_progress_indicator, 0, 0);
  theme_apply_solid_rectangle(ur_progress_indicator);
  lv_obj_set_style_bg_color(ur_progress_indicator, highlight_color(), 0);
}

static void update_ur_progress_bar(float percent_complete) {
  if (!ur_progress_bar || !ur_progress_indicator ||
      ur_progress_bar_inner_width <= 0)
    return;

  int indicator_width = (int)(ur_progress_bar_inner_width * percent_complete);
  if (indicator_width < 0)
    indicator_width = 0;
  if (indicator_width > ur_progress_bar_inner_width)
    indicator_width = ur_progress_bar_inner_width;

  lv_obj_set_width(ur_progress_indicator, indicator_width);
}

static void cleanup_ur_progress_bar(void) {
  ur_progress_bar = NULL;
  ur_progress_indicator = NULL;
  ur_progress_bar_inner_width = 0;
}

static void process_pending_progress_update(void) {
  qr_progress_update_t update;
  if (!qr_scanner_engine_poll_progress(&update))
    return;
  if (closing || destruction_in_progress || !qr_scanner_screen)
    return;

  // This runs from an LVGL timer, so progress objects can be mutated without
  // taking the display lock from the decoder task.
  if (update.format == FORMAT_UR) {
    if (!ur_progress_bar)
      create_ur_progress_bar();
    update_ur_progress_bar(update.percent_complete);
    return;
  }

  if ((update.format == FORMAT_PMOFN || update.format == FORMAT_BBQR) &&
      update.parts.total > 1) {
    update_progress_indicators(&update.parts);
  }
}

static void present_pending_preview(void) {
  if (!camera_img || closing || destruction_in_progress)
    return;

  const uint8_t *frame = qr_scanner_engine_claim_preview();
  if (!frame)
    return;

  img_refresh_dsc.data = frame;
  lv_img_set_src(camera_img, &img_refresh_dsc);
  // Active scanning counts as activity: hold off screensaver/session lock
  lv_display_trigger_activity(NULL);
}

static void completion_timer_cb(lv_timer_t *timer) {
  (void)timer;
  present_pending_preview();
  process_pending_progress_update();

  const char *failure_msg = NULL;
  bool completed = qr_scanner_engine_is_completed();
  bool failed = qr_scanner_engine_is_failed(&failure_msg);

  if ((completed || failed) && return_callback && !closing &&
      !destruction_in_progress) {
    closing = true;
    lv_timer_del(completion_timer);
    completion_timer = NULL;

    qr_scanner_engine_request_stop();

    vTaskDelay(pdMS_TO_TICKS(50));
    if (failed) {
      dialog_show_error_timeout(failure_msg ? failure_msg
                                            : "Invalid QR sequence",
                                return_callback, 0);
    } else {
      return_callback();
    }
  }
}

static void touch_event_cb(lv_event_t *e) {
  (void)e;
  if (closing || settings_overlay)
    return;
  closing = true;
  qr_scanner_engine_request_stop();
  if (return_callback)
    return_callback();
}

// --- Camera settings overlay ---

static void destroy_settings_overlay(void) {
  if (!settings_overlay)
    return;

  // Save current values to NVS (invert focus slider back to hardware range)
  if (ae_slider)
    settings_set_ae_target((uint8_t)lv_slider_get_value(ae_slider));
  if (focus_slider)
    settings_set_focus_position(
        (uint16_t)(FOCUS_POSITION_MAX - lv_slider_get_value(focus_slider)));

  lv_obj_del(settings_overlay);
  settings_overlay = NULL;
  ae_slider = NULL;
  focus_slider = NULL;
  qr_scanner_engine_set_settings_active(false);
}

static void ae_slider_cb(lv_event_t *e) {
  int32_t val = lv_slider_get_value(lv_event_get_target(e));
  app_video_set_ae_target((uint32_t)val);
}

static void focus_slider_cb(lv_event_t *e) {
  int32_t val = lv_slider_get_value(lv_event_get_target(e));
  app_video_set_focus((uint32_t)(FOCUS_POSITION_MAX - val));
}

static void settings_close_cb(lv_event_t *e) {
  (void)e;
  destroy_settings_overlay();
}

static void style_settings_slider(lv_obj_t *slider) {
  lv_obj_set_width(slider, LV_PCT(90));
  theme_apply_slider(slider);
  lv_obj_set_style_margin_ver(slider, theme_slider_knob_pad(), 0);
}

static void create_settings_overlay(void) {
  if (settings_overlay)
    return;

  qr_scanner_engine_set_settings_active(true);

  // Full-screen blocker
  settings_overlay = lv_obj_create(qr_scanner_screen);
  lv_obj_remove_style_all(settings_overlay);
  lv_obj_set_size(settings_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_opa(settings_overlay, LV_OPA_TRANSP, 0);
  lv_obj_add_flag(settings_overlay, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(settings_overlay, LV_OBJ_FLAG_SCROLLABLE);

  // Bottom-aligned panel
  lv_obj_t *panel = lv_obj_create(settings_overlay);
  lv_obj_set_size(panel, LV_PCT(85), LV_SIZE_CONTENT);
  lv_obj_align(panel, LV_ALIGN_BOTTOM_MID, 0, -12);
  theme_apply_frame(panel);
  lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
  lv_obj_set_flex_flow(panel, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(panel, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_ver(panel, 12, 0);
  lv_obj_set_style_pad_hor(panel, 12, 0);
  lv_obj_set_style_pad_row(panel, 10, 0);
  lv_obj_clear_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);

  // Exposure label + slider (only when sensor exposes AE control)
  if (has_ae_control) {
    lv_obj_t *ae_title = lv_label_create(panel);
    lv_label_set_text(ae_title, "Exposure");
    lv_obj_set_style_text_font(ae_title, theme_font_small(), 0);
    lv_obj_set_style_text_color(ae_title, primary_color(), 0);

    ae_slider = lv_slider_create(panel);
    lv_slider_set_range(ae_slider, AE_TARGET_MIN, AE_TARGET_MAX);
    lv_slider_set_value(ae_slider, settings_get_ae_target(), LV_ANIM_OFF);
    style_settings_slider(ae_slider);
    lv_obj_add_event_cb(ae_slider, ae_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);
  }

  // Focus label + slider (only if motor detected, inverted: left=near
  // right=far)
  if (has_focus_motor) {
    lv_obj_t *focus_title = lv_label_create(panel);
    lv_label_set_text(focus_title, "Focus");
    lv_obj_set_style_text_font(focus_title, theme_font_small(), 0);
    lv_obj_set_style_text_color(focus_title, primary_color(), 0);

    focus_slider = lv_slider_create(panel);
    lv_slider_set_range(focus_slider, 0, FOCUS_POSITION_MAX);
    lv_slider_set_value(focus_slider,
                        FOCUS_POSITION_MAX - settings_get_focus_position(),
                        LV_ANIM_OFF);
    style_settings_slider(focus_slider);
    lv_obj_add_event_cb(focus_slider, focus_slider_cb, LV_EVENT_VALUE_CHANGED,
                        NULL);
  }

  // Close button
  lv_obj_t *close_btn = theme_create_button(panel, "Close", true);
  lv_obj_set_width(close_btn, LV_PCT(60));
  lv_obj_set_style_bg_opa(close_btn, LV_OPA_COVER, 0);
  lv_obj_set_style_margin_top(close_btn, 16, 0);
  lv_obj_add_event_cb(close_btn, settings_close_cb, LV_EVENT_CLICKED, NULL);
}

static void settings_btn_cb(lv_event_t *e) {
  (void)e;
  create_settings_overlay();
}

void qr_scanner_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(qr_scanner_page_destroy);
  (void)parent;

  return_callback = return_cb;
  closing = false;
  is_fully_initialized = false;

  if (!app_video_is_ready()) {
    dialog_show_error_timeout("Camera not available", return_callback, 0);
    return;
  }

  qr_scanner_geometry_t geom =
      qr_scanner_compute_geometry(CAMERA_SCREEN_DIM_MIN);

  // Probe sensor capabilities up front so we can gate the settings button
  // before the stream starts.
  has_focus_motor = app_video_has_focus_motor();
  has_ae_control = app_video_has_ae_control();

  qr_scanner_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(qr_scanner_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(qr_scanner_screen, bg_color(), 0);
  lv_obj_set_style_bg_opa(qr_scanner_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_scanner_screen, 0, 0);
  lv_obj_set_style_pad_all(qr_scanner_screen, 0, 0);
  lv_obj_set_style_radius(qr_scanner_screen, 0, 0);
  lv_obj_set_style_shadow_width(qr_scanner_screen, 0, 0);
  lv_obj_clear_flag(qr_scanner_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(qr_scanner_screen, touch_event_cb, LV_EVENT_CLICKED,
                      NULL);

  lv_obj_t *frame_buffer = lv_obj_create(qr_scanner_screen);
  lv_obj_set_size(frame_buffer, geom.preview_size, geom.preview_size);
  lv_obj_center(frame_buffer);
  lv_obj_set_style_bg_opa(frame_buffer, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(frame_buffer, 0, 0);
  lv_obj_set_style_pad_all(frame_buffer, 0, 0);
  lv_obj_set_style_radius(frame_buffer, 0, 0);
  lv_obj_clear_flag(frame_buffer, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(frame_buffer, touch_event_cb, LV_EVENT_CLICKED, NULL);

  camera_img = lv_img_create(frame_buffer);
  lv_obj_set_size(camera_img, geom.preview_size, geom.preview_size);
  lv_obj_center(camera_img);
  lv_obj_clear_flag(camera_img, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(camera_img, bg_color(), 0);
  lv_obj_set_style_bg_opa(camera_img, LV_OPA_COVER, 0);

  lv_obj_t *title_label =
      theme_create_label(qr_scanner_screen, "QR Scanner", false);
  theme_apply_label(title_label, true);
  lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 8);

  if (has_ae_control || has_focus_motor) {
    lv_obj_t *settings_btn =
        ui_create_settings_button(qr_scanner_screen, settings_btn_cb);
    lv_obj_set_style_bg_opa(settings_btn, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(settings_btn, bg_color(), 0);
  }

  img_refresh_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565,
                 .w = geom.preview_size,
                 .h = geom.preview_size},
      .data_size = geom.preview_size * geom.preview_size * 2,
      .data = NULL,
  };

  if (!qr_scanner_engine_start(&geom)) {
    ESP_LOGE(TAG, "Failed to initialize camera");
    return;
  }

  // Apply camera settings after stream starts (V4L2 controls register with the
  // sensor device only once streaming).
  if (has_ae_control)
    app_video_set_ae_target(settings_get_ae_target());
  if (has_focus_motor)
    app_video_set_focus(settings_get_focus_position());

  completion_timer =
      lv_timer_create(completion_timer_cb, UI_UPDATE_INTERVAL_MS, NULL);
  is_fully_initialized = true;
}

void qr_scanner_page_show(void) {
  if (is_fully_initialized && !closing && qr_scanner_screen)
    lv_obj_clear_flag(qr_scanner_screen, LV_OBJ_FLAG_HIDDEN);
}

void qr_scanner_page_hide(void) {
  if (is_fully_initialized && !closing && qr_scanner_screen)
    lv_obj_add_flag(qr_scanner_screen, LV_OBJ_FLAG_HIDDEN);
}

void qr_scanner_page_destroy(void) {
  session_cleanup_unregister(qr_scanner_page_destroy);
  destruction_in_progress = true;
  closing = true;
  is_fully_initialized = false;
  destroy_settings_overlay();
  has_focus_motor = false;
  has_ae_control = false;

  if (completion_timer) {
    lv_timer_del(completion_timer);
    completion_timer = NULL;
  }

  bool pipeline_idle = qr_scanner_engine_stop();

  bool display_locked = bsp_display_lock(1000);
  if (!display_locked)
    ESP_LOGW(TAG, "Failed to lock display for UI cleanup");

  camera_img = NULL;
  cleanup_progress_indicators();
  cleanup_ur_progress_bar();
  if (qr_scanner_screen) {
    lv_obj_del(qr_scanner_screen);
    qr_scanner_screen = NULL;
  }

  if (display_locked)
    bsp_display_unlock();

  qr_scanner_engine_release_buffers(pipeline_idle);

  return_callback = NULL;
  destruction_in_progress = false;
  closing = false;
}

char *qr_scanner_get_completed_content(void) {
  return qr_scanner_engine_get_completed_content_with_len(NULL);
}

char *qr_scanner_get_completed_content_with_len(size_t *content_len) {
  return qr_scanner_engine_get_completed_content_with_len(content_len);
}

bool qr_scanner_has_completed_result(void) {
  return qr_scanner_engine_has_completed_result();
}

int qr_scanner_get_format(void) { return qr_scanner_engine_get_format(); }

char qr_scanner_get_bbqr_file_type(void) {
  return qr_scanner_engine_get_bbqr_file_type();
}

bool qr_scanner_get_ur_result(const char **ur_type_out,
                              const uint8_t **cbor_data_out,
                              size_t *cbor_len_out) {
  return qr_scanner_engine_get_ur_result(ur_type_out, cbor_data_out,
                                         cbor_len_out);
}
