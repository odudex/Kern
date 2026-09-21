#include "viewer.h"
#include "../core/settings.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include "../utils/session_cleanup.h"
#include "encoder.h"
#include "export.h"
#include "progress.h"
#include <inttypes.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

#define CONTROLS_HIDE_MS 4000
#define STATUS_INSET 6

typedef struct {
  qr_export_t *source;
  lv_obj_t *layer;
  lv_obj_t *qr;
  lv_obj_t *status;
  lv_obj_t *label;
  lv_obj_t *grid;
  qr_progress_grid_t layout;
  uint32_t index;
  bool sidebar;
} export_view_t;

static lv_obj_t *qr_viewer_screen;
static export_view_t *view;
static lv_obj_t *settings_overlay;
static lv_obj_t *density_slider;
static lv_obj_t *settings_button;
static lv_obj_t *done_button;
static lv_obj_t *playback_panel;
static lv_obj_t *play_label;
static lv_obj_t *jump_slider;
static lv_timer_t *controls_timer;
static lv_timer_t *message_timer;
static lv_timer_t *animation_timer;
static void (*return_callback)(void);
static char *qr_content_copy;
static int qr_source_format;
static bool paused;
static uint16_t qr_density = QR_DENSITY_DEFAULT;
static uint8_t qr_shade = QR_SHADE_DEFAULT;
static uint8_t qr_fps = QR_FPS_DEFAULT;

static void show_controls(void);
static void create_playback_controls(void);

static lv_color_t current_light_color(void) {
  uint8_t v = (uint8_t)(255 * qr_shade / 100);
  return lv_color_make(v, v, v);
}

static void apply_qr_shade(void) {
  if (qr_viewer_screen)
    lv_obj_set_style_bg_color(qr_viewer_screen, current_light_color(), 0);
  if (view)
    qr_set_light_color(view->qr, current_light_color());
}

static void hide_controls(void) {
  if (controls_timer) {
    lv_timer_del(controls_timer);
    controls_timer = NULL;
  }
  if (settings_button)
    lv_obj_add_flag(settings_button, LV_OBJ_FLAG_HIDDEN);
  if (done_button)
    lv_obj_add_flag(done_button, LV_OBJ_FLAG_HIDDEN);
  if (playback_panel)
    lv_obj_add_flag(playback_panel, LV_OBJ_FLAG_HIDDEN);
}

static void controls_timer_cb(lv_timer_t *timer) { hide_controls(); }

static void position_controls(void) {
  if (!view || !done_button)
    return;
  int x = 0, y = 0;
  if (view->status) {
    if (view->sidebar)
      x = -(lv_obj_get_width(view->status) + theme_small_padding()) / 2;
    else
      y = -(lv_obj_get_height(view->status) + theme_small_padding());
  }
  lv_obj_align(done_button, LV_ALIGN_BOTTOM_MID, x, y);
  if (playback_panel)
    lv_obj_align_to(playback_panel, done_button, LV_ALIGN_OUT_TOP_MID, 0,
                    -theme_small_padding());
}

static void show_controls(void) {
  if (settings_overlay)
    return;
  if (settings_button) {
    lv_obj_clear_flag(settings_button, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(settings_button);
  }
  if (done_button) {
    lv_obj_clear_flag(done_button, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(done_button);
  }
  if (playback_panel) {
    lv_obj_clear_flag(playback_panel, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(playback_panel);
  }
  position_controls();
  if (controls_timer) {
    lv_timer_del(controls_timer);
    controls_timer = NULL;
  }
  controls_timer = lv_timer_create(controls_timer_cb, CONTROLS_HIDE_MS, NULL);
  if (controls_timer)
    lv_timer_set_repeat_count(controls_timer, 1);
}

// The controls overlap the QR, so a paused frame must be able to shed them.
static void screen_clicked_cb(lv_event_t *e) {
  if (done_button && !lv_obj_has_flag(done_button, LV_OBJ_FLAG_HIDDEN))
    hide_controls();
  else
    show_controls();
}

static void done_button_cb(lv_event_t *e) {
  if (return_callback)
    return_callback();
}

static lv_area_t frame_cell(const export_view_t *v, uint32_t index) {
  lv_area_t area;
  lv_obj_get_content_coords(v->grid, &area);
  area.x1 += (index % v->layout.columns) *
             (v->layout.cell_width + QR_PROGRESS_CELL_GAP);
  area.y1 += (index / v->layout.columns) *
             (v->layout.cell_height + QR_PROGRESS_CELL_GAP);
  area.x2 = area.x1 + v->layout.cell_width - 1;
  area.y2 = area.y1 + v->layout.cell_height - 1;
  return area;
}

static void draw_frame_grid(lv_event_t *event) {
  export_view_t *v = lv_event_get_user_data(event);
  lv_layer_t *layer = lv_event_get_layer(event);
  lv_draw_rect_dsc_t rect;
  lv_draw_rect_dsc_init(&rect);
  rect.bg_opa = LV_OPA_COVER;
  for (uint32_t i = 0; i < qr_export_part_count(v->source); i++) {
    lv_area_t cell = frame_cell(v, i);
    const lv_area_t *clip = &layer->_clip_area;
    if (!qr_progress_spans_overlap(cell.x1, cell.x2, clip->x1, clip->x2) ||
        !qr_progress_spans_overlap(cell.y1, cell.y2, clip->y1, clip->y2))
      continue;
    rect.bg_color = i == v->index ? highlight_color() : primary_color();
    lv_draw_rect(layer, &rect, &cell);
  }
}

static void update_status(export_view_t *v, uint32_t old_index) {
  if (!v->label)
    return;
  if (qr_export_is_fountain(v->source)) {
    lv_label_set_text_fmt(v->label, "UR frame %" PRIu32 "\n%zu source parts",
                          v->index + 1, qr_export_part_count(v->source));
  } else {
    lv_label_set_text_fmt(v->label, "Frame %" PRIu32 " / %zu", v->index + 1,
                          qr_export_part_count(v->source));
    // Only the old and new cells change. No per-frame widget allocations or
    // restyling every cell in a potentially thousand-frame sequence.
    lv_area_t old = frame_cell(v, old_index);
    lv_area_t current = frame_cell(v, v->index);
    lv_obj_invalidate_area(v->grid, &old);
    lv_obj_invalidate_area(v->grid, &current);
  }
}

static void free_view(export_view_t *v) {
  if (!v)
    return;
  if (v->layer)
    lv_obj_delete(v->layer);
  qr_export_free(v->source);
  free(v);
}

static export_view_t *prepare_view(uint16_t density) {
  export_view_t *v = calloc(1, sizeof(*v));
  if (!v)
    return NULL;
  v->source = qr_export_create(qr_source_format, qr_content_copy, density);
  if (!v->source)
    goto fail;
  const char *first = qr_export_frame(v->source, 0);
  if (!first)
    goto fail;

  v->layer = lv_obj_create(qr_viewer_screen);
  lv_obj_remove_style_all(v->layer);
  lv_obj_set_size(v->layer, LV_PCT(100), LV_PCT(100));
  lv_obj_remove_flag(v->layer, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(v->layer, LV_OBJ_FLAG_EVENT_BUBBLE);
  lv_obj_update_layout(v->layer);
  int w = lv_obj_get_width(v->layer), h = lv_obj_get_height(v->layer);
  int pad = theme_small_padding();
  v->sidebar = w >= h;
  int qr_w = w, qr_h = h;
  if (qr_export_part_count(v->source) > 1) {
    int status_width = v->sidebar ? LV_MAX(160, w / 5) : w;
    int label_height = lv_font_get_line_height(theme_font_small());
    if (v->sidebar || qr_export_is_fountain(v->source))
      label_height *= 2;
    int status_height = label_height + 2 * STATUS_INSET;
    if (!qr_export_is_fountain(v->source)) {
      v->layout = qr_progress_grid_layout(qr_export_part_count(v->source),
                                          status_width - 2 * STATUS_INSET);
      if (!v->layout.columns)
        goto fail;
      status_height += v->layout.height + 4;
    }
    if (status_height > h || status_width > w)
      goto fail;
    v->status = lv_obj_create(v->layer);
    theme_apply_frame(v->status);
    lv_obj_set_style_pad_all(v->status, STATUS_INSET - 2, 0);
    lv_obj_set_size(v->status, status_width, status_height);
    lv_obj_remove_flag(v->status, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(v->status, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_align(v->status,
                 v->sidebar ? LV_ALIGN_RIGHT_MID : LV_ALIGN_BOTTOM_MID, 0, 0);
    v->label = theme_create_label(v->status, "", false);
    lv_obj_set_width(v->label, LV_PCT(100));
    lv_obj_set_style_text_align(v->label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(v->label, LV_ALIGN_TOP_MID, 0, 0);
    if (!qr_export_is_fountain(v->source)) {
      v->grid = lv_obj_create(v->status);
      lv_obj_remove_style_all(v->grid);
      lv_obj_remove_flag(v->grid,
                         LV_OBJ_FLAG_CLICKABLE | LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_size(v->grid, v->layout.width, v->layout.height);
      lv_obj_align(v->grid, LV_ALIGN_BOTTOM_MID, 0, 0);
      lv_obj_add_event_cb(v->grid, draw_frame_grid, LV_EVENT_DRAW_MAIN, v);
    }
    if (v->sidebar)
      qr_w -= status_width + pad;
    else
      qr_h -= status_height + pad;
  }
  int size = LV_MIN(qr_w, qr_h);
  if (size <= 0)
    goto fail;
  v->qr = qr_create_optimal(v->layer, size, first);
  if (!v->qr)
    goto fail;
  // qr_create_optimal() centers the widget, and lv_obj_set_pos() would only
  // offset it from that center: into the status area.
  lv_obj_align(v->qr, LV_ALIGN_TOP_LEFT, (qr_w - size) / 2, (qr_h - size) / 2);
  lv_obj_add_flag(v->qr, LV_OBJ_FLAG_EVENT_BUBBLE);
  qr_set_light_color(v->qr, current_light_color());
  lv_obj_update_layout(v->layer);
  update_status(v, 0);
  return v;
fail:
  free_view(v);
  return NULL;
}

static void set_paused(bool value) {
  paused = value;
  if (animation_timer) {
    if (paused || settings_overlay || !view ||
        qr_export_part_count(view->source) <= 1)
      lv_timer_pause(animation_timer);
    else {
      lv_timer_reset(animation_timer);
      lv_timer_resume(animation_timer);
    }
  }
  if (play_label)
    lv_label_set_text(play_label, paused ? LV_SYMBOL_PLAY : LV_SYMBOL_PAUSE);
}

static bool display_frame(uint32_t index) {
  const char *frame = qr_export_frame(view->source, index);
  if (!frame || qr_update_optimal(view->qr, frame, NULL) != LV_RESULT_OK) {
    set_paused(true);
    show_controls();
    dialog_show_message("QR export paused",
                        playback_panel
                            ? "Could not display the next frame. Try Play "
                              "again or restart the export."
                            : "Could not display the next frame. Restart the "
                              "export.");
    return false;
  }
  uint32_t previous = view->index;
  view->index = index;
  qr_set_light_color(view->qr, current_light_color());
  update_status(view, previous);
  if (jump_slider)
    lv_slider_set_value(jump_slider, index + 1, LV_ANIM_OFF);
  return true;
}

static void animation_timer_cb(lv_timer_t *timer) {
  if (!view || paused || settings_overlay ||
      qr_export_part_count(view->source) <= 1)
    return;
  lv_display_trigger_activity(NULL);
  uint32_t next = view->index + 1;
  if (!qr_export_is_fountain(view->source))
    next %= qr_export_part_count(view->source);
  display_frame(next);
}

static void play_cb(lv_event_t *e) {
  set_paused(!paused);
  show_controls();
}

static void step_cb(lv_event_t *e) {
  set_paused(true);
  int direction = (int)(intptr_t)lv_event_get_user_data(e);
  uint32_t count = qr_export_part_count(view->source);
  uint32_t next = direction < 0 ? (view->index + count - 1) % count
                                : (view->index + 1) % count;
  display_frame(next);
  show_controls();
}

static void jump_cb(lv_event_t *e) {
  set_paused(true);
  uint32_t index = lv_slider_get_value(jump_slider) - 1;
  if (!display_frame(index))
    lv_slider_set_value(jump_slider, view->index + 1, LV_ANIM_OFF);
  show_controls();
}

static void jump_pressed_cb(lv_event_t *e) { set_paused(true); }

static lv_obj_t *playback_button(lv_obj_t *parent, const char *text,
                                 lv_event_cb_t cb, void *data) {
  lv_obj_t *button = theme_create_button(parent, text, true);
  lv_obj_set_size(button, theme_corner_button_width(),
                  theme_corner_button_height());
  lv_obj_add_event_cb(button, cb, LV_EVENT_CLICKED, data);
  return button;
}

static void create_playback_controls(void) {
  if (playback_panel)
    lv_obj_delete(playback_panel);
  playback_panel = NULL;
  play_label = NULL;
  jump_slider = NULL;
  // Fountain frames never repeat: there is none to hold or to go back to.
  if (qr_export_part_count(view->source) <= 1 ||
      qr_export_is_fountain(view->source))
    return;
  int gap = theme_button_spacing();
  playback_panel = lv_obj_create(qr_viewer_screen);
  theme_apply_frame(playback_panel);
  lv_obj_set_style_bg_opa(playback_panel, LV_OPA_COVER, 0);
  lv_obj_set_size(playback_panel, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(playback_panel, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(playback_panel, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(playback_panel, gap, 0);
  lv_obj_set_style_pad_row(playback_panel, gap, 0);
  lv_obj_t *row = theme_create_flex_row(playback_panel);
  lv_obj_set_style_pad_column(row, gap, 0);
  playback_button(row, LV_SYMBOL_PREV, step_cb, (void *)(intptr_t)-1);
  lv_obj_t *play = playback_button(
      row, paused ? LV_SYMBOL_PLAY : LV_SYMBOL_PAUSE, play_cb, NULL);
  play_label = lv_obj_get_child(play, 0);
  playback_button(row, LV_SYMBOL_NEXT, step_cb, (void *)(intptr_t)1);
  jump_slider = lv_slider_create(playback_panel);
  // As wide as the buttons, less the half knob that overhangs each end.
  lv_obj_set_width(jump_slider, 3 * theme_corner_button_width() + 2 * gap -
                                    theme_min_touch_size());
  lv_slider_set_range(jump_slider, 1, qr_export_part_count(view->source));
  lv_slider_set_value(jump_slider, view->index + 1, LV_ANIM_OFF);
  theme_apply_slider(jump_slider);
  lv_obj_set_style_margin_ver(jump_slider, theme_slider_knob_pad(), 0);
  lv_obj_add_event_cb(jump_slider, jump_pressed_cb, LV_EVENT_PRESSED, NULL);
  lv_obj_add_event_cb(jump_slider, jump_cb, LV_EVENT_RELEASED, NULL);
  lv_obj_add_flag(playback_panel, LV_OBJ_FLAG_HIDDEN);
  lv_obj_update_layout(playback_panel);
  position_controls();
}

static bool rebuild_qr(uint16_t density) {
  export_view_t *replacement = prepare_view(density);
  if (!replacement)
    return false;
  export_view_t *old = view;
  view = replacement;
  free_view(old);
  qr_density = density;
  create_playback_controls();
  // Without the controls there is no Play to resume with.
  set_paused(paused && playback_panel);
  return true;
}

static void destroy_settings_overlay(void) {
  if (!settings_overlay)
    return;
  uint16_t new_density = lv_slider_get_value(density_slider);
  lv_obj_del(settings_overlay);
  settings_overlay = NULL;
  density_slider = NULL;
  if (new_density != qr_density) {
    if (rebuild_qr(new_density)) {
      settings_set_qr_density(qr_density);
      dialog_show_message("Density Changed", "Restart the scan on coordinator");
    } else
      dialog_show_message("Density unchanged",
                          "Could not create this QR sequence. Current export "
                          "kept. Try a higher density.");
  }
  settings_set_qr_shade(qr_shade);
  settings_set_qr_fps(qr_fps);
  set_paused(paused);
  show_controls();
}

static void shade_slider_cb(lv_event_t *e) {
  qr_shade = lv_slider_get_value(lv_event_get_target(e));
  apply_qr_shade();
}

static void fps_slider_cb(lv_event_t *e) {
  qr_fps = lv_slider_get_value(lv_event_get_target(e));
  if (animation_timer)
    lv_timer_set_period(animation_timer, 1000 / qr_fps);
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

static void hide_message_timer_cb(lv_timer_t *timer) {
  lv_obj_del(lv_timer_get_user_data(timer));
  message_timer = NULL;
}

static bool setup_qr_viewer_ui(lv_obj_t *parent, const char *title) {
  qr_viewer_screen = lv_obj_create(parent);
  lv_obj_set_size(qr_viewer_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(qr_viewer_screen, current_light_color(), 0);
  lv_obj_set_style_bg_opa(qr_viewer_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(qr_viewer_screen, 10, 0);
  lv_obj_clear_flag(qr_viewer_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(qr_viewer_screen, screen_clicked_cb, LV_EVENT_CLICKED,
                      NULL);
  // Density is only adjustable from this page, so a saved value too low for
  // this payload must not make the export unreachable.
  view = prepare_view(qr_density);
  while (!view && qr_density < QR_DENSITY_MAX) {
    qr_density = LV_MIN(qr_density + 50, QR_DENSITY_MAX);
    view = prepare_view(qr_density);
  }
  if (!view)
    return false;
  animation_timer = lv_timer_create(animation_timer_cb, 1000 / qr_fps, NULL);
  if (!animation_timer)
    return false;
  set_paused(false);
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
  create_playback_controls();
  position_controls();
  if (title) {
    lv_obj_t *msgbox = lv_obj_create(qr_viewer_screen);
    lv_obj_set_size(msgbox, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    theme_apply_frame(msgbox);
    lv_obj_set_style_bg_opa(msgbox, LV_OPA_COVER, 0);
    lv_obj_center(msgbox);
    lv_obj_t *label = theme_create_label(msgbox, title, false);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    message_timer = lv_timer_create(hide_message_timer_cb, 2000, msgbox);
    if (message_timer)
      lv_timer_set_repeat_count(message_timer, 1);
    else
      lv_obj_delete(msgbox);
  }
  return true;
}

bool qr_viewer_page_create_with_format(lv_obj_t *parent, int qr_format,
                                       const char *content, const char *title,
                                       void (*return_cb)(void)) {
  if (!parent || !content)
    return false;
  // Copy before teardown in case content belongs to the previous viewer.
  char *copy = strdup(content);
  if (!copy)
    return false;
  qr_viewer_page_destroy();
  session_cleanup_register(qr_viewer_page_destroy);
  qr_content_copy = copy;
  qr_source_format = qr_format;
  qr_density = settings_get_qr_density();
  qr_shade = settings_get_qr_shade();
  qr_fps = settings_get_qr_fps();
  return_callback = return_cb;
  if (!setup_qr_viewer_ui(parent, title)) {
    qr_viewer_page_destroy();
    return false;
  }
  return true;
}

void qr_viewer_page_create(lv_obj_t *parent, const char *content,
                           const char *title, void (*return_cb)(void)) {
  if (!qr_viewer_page_create_with_format(parent, FORMAT_NONE, content, title,
                                         return_cb))
    dialog_show_error_timeout("Could not display the QR code", return_cb, 0);
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
  session_cleanup_unregister(qr_viewer_page_destroy);
  if (animation_timer)
    lv_timer_del(animation_timer);
  if (message_timer)
    lv_timer_del(message_timer);
  if (controls_timer)
    lv_timer_del(controls_timer);
  animation_timer = message_timer = controls_timer = NULL;
  free_view(view);
  view = NULL;
  free(qr_content_copy);
  qr_content_copy = NULL;
  if (qr_viewer_screen)
    lv_obj_del(qr_viewer_screen);
  qr_viewer_screen = NULL;
  settings_overlay = density_slider = settings_button = done_button = NULL;
  playback_panel = play_label = jump_slider = NULL;
  return_callback = NULL;
  paused = false;
}
