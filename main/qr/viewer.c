#include "viewer.h"
#include "../components/bbqr/src/bbqr.h"
#include "../components/cUR/src/types/psbt.h"
#include "../components/cUR/src/ur_encoder.h"
#include "../core/settings.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme.h"
#include "../ui/theme_widgets.h"
#include "encoder.h"
#include "parser.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#define PROGRESS_BAR_HEIGHT 20
#define PROGRESS_FRAME_PADD 2
#define PROGRESS_BLOC_PAD 1
#define PROGRESS_RECT_MIN_LEN 4
#define MAX_QR_PARTS 100

#define UR_HEADER_OVERHEAD 30

#define CONTROLS_HIDE_MS 4000

static lv_obj_t *qr_viewer_screen = NULL;
static lv_obj_t *qr_code_obj = NULL;
static lv_obj_t *progress_frame = NULL;
static lv_obj_t **progress_rectangles = NULL;
static int progress_rectangles_count = 0;
static int progress_total_parts = 0;

static lv_obj_t *settings_overlay = NULL;
static lv_obj_t *density_slider = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *done_button = NULL;
static lv_timer_t *controls_timer = NULL;

static void (*return_callback)(void) = NULL;
static char *qr_content_copy = NULL;
static int qr_source_format = FORMAT_NONE;
static lv_timer_t *message_timer = NULL;
static lv_timer_t *animation_timer = NULL;

static char **qr_parts = NULL;
static BBQrParts *bbqr_parts_owner = NULL;
static int qr_parts_count = 0;
static int current_part_index = 0;

static bool bar_vertical = false;
static uint16_t qr_density = QR_DENSITY_DEFAULT;
static uint8_t qr_shade = QR_SHADE_DEFAULT;
static uint8_t qr_fps = QR_FPS_DEFAULT;

static void hide_controls(void) {
  if (controls_timer) {
    lv_timer_del(controls_timer);
    controls_timer = NULL;
  }
  if (settings_button) {
    lv_obj_add_flag(settings_button, LV_OBJ_FLAG_HIDDEN);
  }
  if (done_button) {
    lv_obj_add_flag(done_button, LV_OBJ_FLAG_HIDDEN);
  }
}

static void controls_timer_cb(lv_timer_t *timer) {
  controls_timer = NULL;
  hide_controls();
}

static void show_controls(void) {
  if (settings_overlay) {
    return;
  }
  if (settings_button) {
    lv_obj_clear_flag(settings_button, LV_OBJ_FLAG_HIDDEN);
  }
  if (done_button) {
    lv_obj_clear_flag(done_button, LV_OBJ_FLAG_HIDDEN);
  }
  if (controls_timer) {
    lv_timer_reset(controls_timer);
  } else {
    controls_timer = lv_timer_create(controls_timer_cb, CONTROLS_HIDE_MS, NULL);
    if (controls_timer) {
      lv_timer_set_repeat_count(controls_timer, 1);
    }
  }
}

static void screen_clicked_cb(lv_event_t *e) { show_controls(); }

static void done_button_cb(lv_event_t *e) {
  if (return_callback) {
    return_callback();
  }
}

static void position_done_button(void) {
  if (!done_button) {
    return;
  }
  int32_t y = 0;
  if (!bar_vertical && qr_parts_count > 1) {
    y = -(PROGRESS_BAR_HEIGHT + theme_small_padding());
  }
  lv_obj_align(done_button, LV_ALIGN_BOTTOM_MID, 0, y);
}

static void hide_message_timer_cb(lv_timer_t *timer) {
  lv_obj_t *msgbox = (lv_obj_t *)lv_timer_get_user_data(timer);
  if (msgbox) {
    lv_obj_del(msgbox);
  }
  message_timer = NULL;
}

static void load_viewer_settings(void) {
  qr_density = settings_get_qr_density();
  qr_shade = settings_get_qr_shade();
  qr_fps = settings_get_qr_fps();
}

static lv_color_t current_light_color(void) {
  uint8_t v = (uint8_t)((255 * qr_shade) / 100);
  return lv_color_make(v, v, v);
}

static void apply_qr_shade(void) {
  if (qr_viewer_screen) {
    lv_obj_set_style_bg_color(qr_viewer_screen, current_light_color(), 0);
  }
  if (qr_code_obj) {
    qr_set_light_color(qr_code_obj, current_light_color());
  }
}

static void create_progress_indicators(int total_parts) {
  if (total_parts <= 1 || total_parts > MAX_QR_PARTS || !qr_viewer_screen) {
    return;
  }

  int extent = bar_vertical ? lv_obj_get_content_height(qr_viewer_screen)
                            : lv_obj_get_content_width(qr_viewer_screen);
  int max_len = extent - (2 * PROGRESS_FRAME_PADD + 2) - 1;
  // One cell per part, unless cells would get too small to see; then each
  // cell represents a range of parts
  int rect_count = total_parts;
  int rect_len = max_len / rect_count;
  if (rect_len < PROGRESS_RECT_MIN_LEN) {
    rect_len = PROGRESS_RECT_MIN_LEN;
    rect_count = max_len / rect_len;
    if (rect_count < 1) {
      return;
    }
  }
  int frame_len = rect_count * rect_len + 1 + 2 * PROGRESS_FRAME_PADD + 2;

  progress_frame = lv_obj_create(qr_viewer_screen);
  if (bar_vertical) {
    lv_obj_set_size(progress_frame, PROGRESS_BAR_HEIGHT, frame_len);
    lv_obj_align(progress_frame, LV_ALIGN_RIGHT_MID, 0, 0);
  } else {
    lv_obj_set_size(progress_frame, frame_len, PROGRESS_BAR_HEIGHT);
    lv_obj_align(progress_frame, LV_ALIGN_BOTTOM_MID, 0, 0);
  }
  theme_apply_frame(progress_frame);
  lv_obj_set_style_pad_all(progress_frame, 2, 0);

  progress_rectangles = malloc(rect_count * sizeof(lv_obj_t *));
  if (!progress_rectangles) {
    lv_obj_del(progress_frame);
    progress_frame = NULL;
    return;
  }
  progress_rectangles_count = rect_count;
  progress_total_parts = total_parts;

  lv_obj_update_layout(progress_frame);

  for (int i = 0; i < rect_count; i++) {
    progress_rectangles[i] = lv_obj_create(progress_frame);
    if (bar_vertical) {
      lv_obj_set_size(progress_rectangles[i], 12, rect_len - PROGRESS_BLOC_PAD);
      lv_obj_set_pos(progress_rectangles[i], 0, i * rect_len);
    } else {
      lv_obj_set_size(progress_rectangles[i], rect_len - PROGRESS_BLOC_PAD, 12);
      lv_obj_set_pos(progress_rectangles[i], i * rect_len, 0);
    }
    theme_apply_solid_rectangle(progress_rectangles[i]);
  }
}

static void update_progress_indicator(int part_index) {
  if (!progress_rectangles || part_index < 0 || progress_total_parts <= 0 ||
      part_index >= progress_total_parts) {
    return;
  }

  int active = part_index * progress_rectangles_count / progress_total_parts;
  for (int i = 0; i < progress_rectangles_count; i++) {
    lv_color_t color = (i == active) ? highlight_color() : primary_color();
    lv_obj_set_style_bg_color(progress_rectangles[i], color, 0);
  }
}

static void cleanup_progress_indicators(void) {
  if (progress_rectangles) {
    free(progress_rectangles);
    progress_rectangles = NULL;
  }
  progress_rectangles_count = 0;
  progress_total_parts = 0;
  if (progress_frame) {
    lv_obj_del(progress_frame);
    progress_frame = NULL;
  }
}

static void split_content_into_parts(const char *content) {
  size_t content_len = strlen(content);
  size_t max_chars = qr_density;

  if (content_len <= max_chars) {
    qr_parts_count = 1;
    qr_parts = malloc(sizeof(char *));
    if (!qr_parts)
      return;

    qr_parts[0] = strdup(content);
    if (!qr_parts[0]) {
      free(qr_parts);
      qr_parts = NULL;
      qr_parts_count = 0;
    }
    return;
  }

  qr_parts_count = (content_len + max_chars - 1) / max_chars;
  if (qr_parts_count > MAX_QR_PARTS) {
    qr_parts_count = MAX_QR_PARTS;
  }

  int prefix_len = (qr_parts_count > 9) ? 8 : 6;
  size_t chars_per_part = max_chars - prefix_len;
  qr_parts_count = (content_len + chars_per_part - 1) / chars_per_part;

  qr_parts = malloc(qr_parts_count * sizeof(char *));
  if (!qr_parts) {
    qr_parts_count = 0;
    return;
  }

  for (int i = 0; i < qr_parts_count; i++) {
    size_t offset = i * chars_per_part;
    size_t remaining = content_len - offset;
    size_t chunk_size =
        (remaining > chars_per_part) ? chars_per_part : remaining;

    char header[16];
    snprintf(header, sizeof(header), "p%dof%d ", i + 1, qr_parts_count);
    size_t header_len = strlen(header);

    size_t part_len = header_len + chunk_size;
    qr_parts[i] = malloc(part_len + 1);
    if (!qr_parts[i]) {
      for (int j = 0; j < i; j++) {
        free(qr_parts[j]);
      }
      free(qr_parts);
      qr_parts = NULL;
      qr_parts_count = 0;
      return;
    }

    memcpy(qr_parts[i], header, header_len);
    memcpy(qr_parts[i] + header_len, content + offset, chunk_size);
    qr_parts[i][part_len] = '\0';
  }
}

static void cleanup_qr_parts(void) {
  if (bbqr_parts_owner) {
    bbqr_parts_free(bbqr_parts_owner);
    bbqr_parts_owner = NULL;
    qr_parts = NULL;
  } else if (qr_parts) {
    for (int i = 0; i < qr_parts_count; i++) {
      if (qr_parts[i]) {
        free(qr_parts[i]);
      }
    }
    free(qr_parts);
    qr_parts = NULL;
  }
  qr_parts_count = 0;
  current_part_index = 0;
}

static uint8_t *decode_psbt_base64(size_t *out_len) {
  size_t max_decoded_len = (strlen(qr_content_copy) * 3) / 4 + 1;
  uint8_t *psbt_bytes = malloc(max_decoded_len);
  if (!psbt_bytes) {
    return NULL;
  }

  if (wally_base64_to_bytes(qr_content_copy, 0, psbt_bytes, max_decoded_len,
                            out_len) != WALLY_OK) {
    free(psbt_bytes);
    return NULL;
  }
  return psbt_bytes;
}

static bool generate_bbqr_parts(void) {
  size_t psbt_len = 0;
  uint8_t *psbt_bytes = decode_psbt_base64(&psbt_len);
  if (!psbt_bytes) {
    return false;
  }

  bbqr_parts_owner =
      bbqr_encode(psbt_bytes, psbt_len, BBQR_TYPE_PSBT, qr_density);
  free(psbt_bytes);
  if (!bbqr_parts_owner) {
    return false;
  }

  qr_parts_count = bbqr_parts_owner->count;
  qr_parts = bbqr_parts_owner->parts;
  return true;
}

static bool generate_ur_parts(void) {
  size_t psbt_len = 0;
  uint8_t *psbt_bytes = decode_psbt_base64(&psbt_len);
  if (!psbt_bytes) {
    return false;
  }

  psbt_data_t *psbt_data = psbt_new(psbt_bytes, psbt_len);
  free(psbt_bytes);
  if (!psbt_data) {
    return false;
  }

  size_t cbor_len = 0;
  uint8_t *cbor_data = psbt_to_cbor(psbt_data, &cbor_len);
  psbt_free(psbt_data);
  if (!cbor_data) {
    return false;
  }

  size_t max_fragment_len = (qr_density - UR_HEADER_OVERHEAD) / 2;
  if (max_fragment_len < 10) {
    max_fragment_len = 10;
  }
  ur_encoder_t *encoder = ur_encoder_new("crypto-psbt", cbor_data, cbor_len,
                                         max_fragment_len, 0, 10);
  free(cbor_data);
  if (!encoder) {
    return false;
  }

  bool is_single = ur_encoder_is_single_part(encoder);
  size_t seq_len = ur_encoder_seq_len(encoder);
  size_t parts_count =
      is_single ? 1 : (seq_len * 2 > MAX_QR_PARTS ? MAX_QR_PARTS : seq_len * 2);

  qr_parts = malloc(parts_count * sizeof(char *));
  if (!qr_parts) {
    ur_encoder_free(encoder);
    return false;
  }

  for (size_t i = 0; i < parts_count; i++) {
    if (!ur_encoder_next_part(encoder, &qr_parts[i])) {
      qr_parts_count = (int)i;
      cleanup_qr_parts();
      ur_encoder_free(encoder);
      return false;
    }
  }
  qr_parts_count = (int)parts_count;
  ur_encoder_free(encoder);
  return true;
}

static bool generate_parts(void) {
  cleanup_qr_parts();
  if (!qr_content_copy) {
    return false;
  }

  if (qr_source_format == FORMAT_BBQR) {
    return generate_bbqr_parts();
  }
  if (qr_source_format == FORMAT_UR) {
    return generate_ur_parts();
  }

  split_content_into_parts(qr_content_copy);
  return qr_parts && qr_parts_count > 0;
}

static void animation_timer_cb(lv_timer_t *timer) {
  if (!qr_code_obj || !qr_parts || qr_parts_count <= 1) {
    return;
  }
  current_part_index = (current_part_index + 1) % qr_parts_count;
  qr_update_optimal(qr_code_obj, qr_parts[current_part_index], NULL);
  if (qr_shade != QR_SHADE_MAX) {
    qr_set_light_color(qr_code_obj, current_light_color());
  }
  update_progress_indicator(current_part_index);
}

static bool create_qr_and_bar(void) {
  lv_obj_update_layout(qr_viewer_screen);
  int32_t w = lv_obj_get_content_width(qr_viewer_screen);
  int32_t h = lv_obj_get_content_height(qr_viewer_screen);
  int32_t pad = theme_small_padding();

  // Controls overlap the QR and auto-hide, so only the bar reserves space
  bar_vertical = w >= h;
  int32_t bar_space = (qr_parts_count > 1) ? PROGRESS_BAR_HEIGHT + pad : 0;
  int32_t qr_size;
  int32_t x_ofs = 0;
  if (bar_vertical) {
    qr_size = LV_MIN(h, w - bar_space);
    x_ofs = -(bar_space + 1) / 2;
  } else {
    qr_size = LV_MIN(w, h - 2 * bar_space);
  }

  qr_code_obj = qr_create_optimal(qr_viewer_screen, qr_size, qr_parts[0]);
  if (!qr_code_obj) {
    return false;
  }
  lv_obj_align(qr_code_obj, LV_ALIGN_CENTER, x_ofs, 0);
  apply_qr_shade();

  if (qr_parts_count > 1) {
    create_progress_indicators(qr_parts_count);
    update_progress_indicator(0);
    animation_timer = lv_timer_create(animation_timer_cb, 1000 / qr_fps, NULL);
  }

  if (settings_button) {
    lv_obj_move_foreground(settings_button);
  }
  if (done_button) {
    lv_obj_move_foreground(done_button);
    position_done_button();
  }
  return true;
}

// --- Viewer settings overlay ---

static void rebuild_qr(void) {
  if (animation_timer) {
    lv_timer_del(animation_timer);
    animation_timer = NULL;
  }
  cleanup_progress_indicators();
  if (qr_code_obj) {
    lv_obj_del(qr_code_obj);
    qr_code_obj = NULL;
  }
  if (generate_parts()) {
    create_qr_and_bar();
  }
}

static void destroy_settings_overlay(void) {
  if (!settings_overlay) {
    return;
  }

  uint16_t new_density = (uint16_t)lv_slider_get_value(density_slider);
  lv_obj_del(settings_overlay);
  settings_overlay = NULL;
  density_slider = NULL;

  settings_set_qr_density(new_density);
  settings_set_qr_shade(qr_shade);
  settings_set_qr_fps(qr_fps);

  if (new_density != qr_density) {
    qr_density = new_density;
    rebuild_qr();
    dialog_show_message("Density Changed", "Restart the scan on coordinator");
  }
  if (animation_timer) {
    lv_timer_resume(animation_timer);
  }
}

static void shade_slider_cb(lv_event_t *e) {
  qr_shade = (uint8_t)lv_slider_get_value(lv_event_get_target(e));
  apply_qr_shade();
}

static void fps_slider_cb(lv_event_t *e) {
  qr_fps = (uint8_t)lv_slider_get_value(lv_event_get_target(e));
  if (animation_timer) {
    lv_timer_set_period(animation_timer, 1000 / qr_fps);
  }
}

static void settings_close_cb(lv_event_t *e) { destroy_settings_overlay(); }

static lv_obj_t *add_settings_slider(lv_obj_t *panel, const char *name,
                                     int32_t min, int32_t max, int32_t value,
                                     lv_event_cb_t cb) {
  lv_obj_t *title = lv_label_create(panel);
  lv_label_set_text(title, name);
  lv_obj_set_style_text_font(title, theme_font_small(), 0);
  lv_obj_set_style_text_color(title, primary_color(), 0);

  lv_obj_t *slider = lv_slider_create(panel);
  lv_slider_set_range(slider, min, max);
  lv_slider_set_value(slider, value, LV_ANIM_OFF);
  lv_obj_set_width(slider, LV_PCT(90));
  theme_apply_slider(slider);
  lv_obj_set_style_margin_ver(slider, theme_slider_knob_pad(), 0);
  if (cb) {
    lv_obj_add_event_cb(slider, cb, LV_EVENT_VALUE_CHANGED, NULL);
  }
  return slider;
}

static void create_settings_overlay(void) {
  if (settings_overlay) {
    return;
  }
  hide_controls();
  if (animation_timer) {
    lv_timer_pause(animation_timer);
  }

  // Full-screen blocker (also swallows tap-to-return)
  settings_overlay = lv_obj_create(qr_viewer_screen);
  lv_obj_remove_style_all(settings_overlay);
  lv_obj_set_size(settings_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_opa(settings_overlay, LV_OPA_TRANSP, 0);
  lv_obj_add_flag(settings_overlay, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(settings_overlay, LV_OBJ_FLAG_SCROLLABLE);

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

  density_slider = add_settings_slider(panel, "Density", QR_DENSITY_MIN,
                                       QR_DENSITY_MAX, qr_density, NULL);
  add_settings_slider(panel, "Brightness", QR_SHADE_MIN, QR_SHADE_MAX, qr_shade,
                      shade_slider_cb);
  add_settings_slider(panel, "Frame rate", QR_FPS_MIN, QR_FPS_MAX, qr_fps,
                      fps_slider_cb);

  lv_obj_t *close_btn = theme_create_button(panel, "Close", true);
  lv_obj_set_width(close_btn, LV_PCT(60));
  lv_obj_set_style_bg_opa(close_btn, LV_OPA_COVER, 0);
  lv_obj_set_style_margin_top(close_btn, 16, 0);
  lv_obj_add_event_cb(close_btn, settings_close_cb, LV_EVENT_CLICKED, NULL);
}

static void settings_btn_cb(lv_event_t *e) { create_settings_overlay(); }

static bool setup_qr_viewer_ui(lv_obj_t *parent, const char *title) {
  qr_viewer_screen = lv_obj_create(parent);
  lv_obj_set_size(qr_viewer_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(qr_viewer_screen, current_light_color(), 0);
  lv_obj_set_style_bg_opa(qr_viewer_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(qr_viewer_screen, 10, 0);
  lv_obj_clear_flag(qr_viewer_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(qr_viewer_screen, screen_clicked_cb, LV_EVENT_CLICKED,
                      NULL);

  if (!create_qr_and_bar()) {
    return false;
  }

  settings_button =
      ui_create_settings_button(qr_viewer_screen, settings_btn_cb);
  lv_obj_set_style_bg_opa(settings_button, LV_OPA_COVER, 0);
  lv_obj_set_style_bg_color(settings_button, bg_color(), 0);
  lv_obj_add_flag(settings_button, LV_OBJ_FLAG_HIDDEN);

  done_button = theme_create_button(qr_viewer_screen, "Done", true);
  lv_obj_set_size(done_button, theme_button_width(), theme_button_height());
  lv_obj_set_style_bg_opa(done_button, LV_OPA_COVER, 0);
  lv_obj_add_event_cb(done_button, done_button_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_add_flag(done_button, LV_OBJ_FLAG_HIDDEN);
  position_done_button();

  if (title) {
    lv_obj_t *msgbox = lv_obj_create(qr_viewer_screen);
    lv_obj_set_size(msgbox, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(msgbox, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(msgbox, LV_OPA_80, 0);
    lv_obj_set_style_border_width(msgbox, 2, 0);
    lv_obj_set_style_border_color(msgbox, primary_color(), 0);
    lv_obj_set_style_radius(msgbox, 10, 0);
    lv_obj_set_style_pad_all(msgbox, 20, 0);
    lv_obj_add_flag(msgbox, LV_OBJ_FLAG_FLOATING);
    lv_obj_center(msgbox);

    char message[128];
    snprintf(message, sizeof(message), "%s\nTap for options", title);
    lv_obj_t *msg_label = theme_create_label(msgbox, message, false);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(msg_label, lv_color_hex(0xFFFFFF), 0);

    message_timer = lv_timer_create(hide_message_timer_cb, 2000, msgbox);
    if (message_timer) {
      lv_timer_set_repeat_count(message_timer, 1);
    }
  }
  return true;
}

bool qr_viewer_page_create_with_format(lv_obj_t *parent, int qr_format,
                                       const char *content, const char *title,
                                       void (*return_cb)(void)) {
  if (!parent || !content) {
    return false;
  }

  cleanup_qr_parts();
  load_viewer_settings();
  return_callback = return_cb;
  message_timer = NULL;
  animation_timer = NULL;
  qr_source_format = (qr_format == FORMAT_UR || qr_format == FORMAT_BBQR)
                         ? qr_format
                         : FORMAT_NONE;

  free(qr_content_copy);
  qr_content_copy = strdup(content);
  if (!qr_content_copy) {
    return false;
  }

  if (!generate_parts()) {
    free(qr_content_copy);
    qr_content_copy = NULL;
    return false;
  }

  if (!setup_qr_viewer_ui(parent, title)) {
    cleanup_qr_parts();
    return false;
  }
  return true;
}

void qr_viewer_page_create(lv_obj_t *parent, const char *qr_content,
                           const char *title, void (*return_cb)(void)) {
  qr_viewer_page_create_with_format(parent, FORMAT_NONE, qr_content, title,
                                    return_cb);
}

typedef struct {
  char *content;
  char *title;
} fullscreen_ctx_t;

static void fullscreen_close_cb(void) { qr_viewer_page_destroy(); }

static void fullscreen_clicked_cb(lv_event_t *e) {
  fullscreen_ctx_t *ctx = lv_event_get_user_data(e);
  if (qr_viewer_screen)
    return;
  qr_viewer_page_create(lv_screen_active(), ctx->content, ctx->title,
                        fullscreen_close_cb);
}

static void fullscreen_delete_cb(lv_event_t *e) {
  fullscreen_ctx_t *ctx = lv_event_get_user_data(e);
  free(ctx->content);
  free(ctx->title);
  free(ctx);
}

void qr_viewer_attach_fullscreen(lv_obj_t *obj, const char *content,
                                 const char *title) {
  if (!obj || !content)
    return;

  fullscreen_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return;
  ctx->content = strdup(content);
  ctx->title = title ? strdup(title) : NULL;
  if (!ctx->content) {
    free(ctx->title);
    free(ctx);
    return;
  }

  lv_obj_add_flag(obj, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(obj, fullscreen_clicked_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_add_event_cb(obj, fullscreen_delete_cb, LV_EVENT_DELETE, ctx);
}

void qr_viewer_page_show(void) {
  if (qr_viewer_screen) {
    lv_obj_clear_flag(qr_viewer_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_viewer_page_hide(void) {
  if (qr_viewer_screen) {
    lv_obj_add_flag(qr_viewer_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_viewer_page_destroy(void) {
  if (animation_timer) {
    lv_timer_del(animation_timer);
    animation_timer = NULL;
  }

  if (message_timer) {
    lv_timer_del(message_timer);
    message_timer = NULL;
  }

  if (controls_timer) {
    lv_timer_del(controls_timer);
    controls_timer = NULL;
  }

  cleanup_qr_parts();
  cleanup_progress_indicators();

  if (qr_content_copy) {
    free(qr_content_copy);
    qr_content_copy = NULL;
  }

  if (qr_viewer_screen) {
    lv_obj_del(qr_viewer_screen);
    qr_viewer_screen = NULL;
  }

  settings_overlay = NULL;
  density_slider = NULL;
  settings_button = NULL;
  done_button = NULL;
  qr_code_obj = NULL;
  return_callback = NULL;
}
