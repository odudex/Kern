#include "dialog.h"
#include "theme.h"
#include <lvgl.h>
#include <stdlib.h>

typedef struct {
  dialog_callback_t callback;
  void *user_data;
  lv_obj_t *root;
} info_context_t;

typedef struct {
  dialog_confirm_callback_t callback;
  void *user_data;
  lv_obj_t *root;
} confirm_context_t;

typedef struct {
  dialog_simple_callback_t callback;
  lv_obj_t *modal;
} error_context_t;

static void info_ok_cb(lv_event_t *e) {
  info_context_t *ctx = lv_event_get_user_data(e);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback(ctx->user_data);
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
}

static void confirm_finish(lv_event_t *e, bool confirmed) {
  confirm_context_t *ctx = lv_event_get_user_data(e);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback(confirmed, ctx->user_data);
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
}

static void confirm_yes_cb(lv_event_t *e) { confirm_finish(e, true); }
static void confirm_no_cb(lv_event_t *e) { confirm_finish(e, false); }

static void error_timer_cb(lv_timer_t *timer) {
  error_context_t *ctx = lv_timer_get_user_data(timer);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback();
  if (ctx->modal)
    lv_obj_del(ctx->modal);
  free(ctx);
}

static void message_close_cb(lv_event_t *e) {
  lv_obj_del(lv_event_get_user_data(e));
}

static lv_obj_t *create_dialog_container(dialog_style_t style,
                                         lv_obj_t **out_root) {
  lv_obj_t *parent = lv_screen_active();
  lv_obj_t *dialog;

  if (style == DIALOG_STYLE_OVERLAY) {
    lv_obj_t *blocker = lv_obj_create(parent);
    lv_obj_remove_style_all(blocker);
    lv_obj_set_size(blocker, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_bg_color(blocker, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(blocker, LV_OPA_50, 0);
    lv_obj_add_flag(blocker, LV_OBJ_FLAG_CLICKABLE);
    *out_root = blocker;

    dialog = lv_obj_create(blocker);
    lv_obj_set_size(dialog, LV_PCT(90), LV_PCT(40));
    lv_obj_center(dialog);
    theme_apply_frame(dialog);
    lv_obj_set_style_bg_opa(dialog, LV_OPA_COVER, 0);
  } else {
    dialog = lv_obj_create(parent);
    lv_obj_set_size(dialog, LV_PCT(100), LV_PCT(100));
    theme_apply_screen(dialog);
    *out_root = dialog;
  }

  return dialog;
}

static lv_obj_t *make_message_label(lv_obj_t *parent, const char *text,
                                    int32_t width_pct) {
  lv_obj_t *label = theme_create_label(parent, text, false);
  lv_obj_set_width(label, LV_PCT(width_pct));
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  return label;
}

static int32_t add_dialog_title(lv_obj_t *dialog, const char *title) {
  lv_obj_t *label = make_message_label(dialog, title, 90);
  lv_obj_set_style_text_color(label, highlight_color(), 0);
  lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 0);
  lv_obj_update_layout(label);
  return lv_obj_get_height(label);
}

/* Fit an overlay box to its text, capped at 80% of screen. Measures the text
   directly, so it needs no layout pass first. */
static void dialog_fit_overlay(lv_obj_t *dialog, dialog_style_t style,
                               const char *text, int32_t extra_h) {
  if (style != DIALOG_STYLE_OVERLAY)
    return;

  int32_t pad_h = lv_obj_get_style_pad_left(dialog, 0) +
                  lv_obj_get_style_pad_right(dialog, 0);
  int32_t pad_v = lv_obj_get_style_pad_top(dialog, 0) +
                  lv_obj_get_style_pad_bottom(dialog, 0);
  int32_t border = lv_obj_get_style_border_width(dialog, 0);
  int32_t content_w = theme_get_screen_width() * 90 / 100 - pad_h - border * 2;
  int32_t label_w = content_w * 90 / 100;

  lv_point_t txt_size;
  lv_text_get_size(&txt_size, text, theme_font_medium(), 0, 0, label_w,
                   LV_TEXT_FLAG_NONE);

  int32_t needed = txt_size.y + extra_h + pad_v + border * 2;
  int32_t max_h = theme_get_screen_height() * 80 / 100;
  lv_obj_set_height(dialog, needed < max_h ? needed : max_h);
}

void dialog_show_info(const char *title, const char *message,
                      dialog_callback_t callback, void *user_data,
                      dialog_style_t style) {
  if (!message)
    return;

  info_context_t *ctx = malloc(sizeof(info_context_t));
  if (!ctx)
    return;

  ctx->callback = callback;
  ctx->user_data = user_data;

  lv_obj_t *dialog = create_dialog_container(style, &ctx->root);

  int32_t gap = theme_get_small_padding();
  int32_t btn_h = theme_get_button_height();
  int32_t msg_y = title ? add_dialog_title(dialog, title) + gap : gap;

  /* Size the box, then carve the space between title and button into a
     scrollable body so a long message never runs under the OK button. */
  dialog_fit_overlay(dialog, style, message, msg_y + btn_h + gap);
  lv_obj_update_layout(dialog);

  int32_t body_h = lv_obj_get_content_height(dialog) - msg_y - btn_h - gap;
  if (body_h < btn_h)
    body_h = btn_h;

  lv_obj_t *body = lv_obj_create(dialog);
  theme_apply_transparent_container(body);
  lv_obj_set_size(body, LV_PCT(100), body_h);
  lv_obj_align(body, LV_ALIGN_TOP_MID, 0, msg_y);
  lv_obj_set_scroll_dir(body, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_AUTO);

  lv_obj_align(make_message_label(body, message, 100), LV_ALIGN_TOP_MID, 0, 0);

  lv_obj_t *ok_btn = theme_create_button(dialog, "OK", true);
  lv_obj_set_size(ok_btn, LV_PCT(50), btn_h);
  lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_add_event_cb(ok_btn, info_ok_cb, LV_EVENT_CLICKED, ctx);
}

void dialog_show_error_timeout(const char *message,
                               dialog_simple_callback_t callback,
                               int timeout_ms) {
  if (!message)
    return;

  if (timeout_ms <= 0)
    timeout_ms = 2000;

  error_context_t *ctx = malloc(sizeof(error_context_t));
  if (!ctx)
    return;

  ctx->callback = callback;
  ctx->modal = lv_obj_create(lv_screen_active());
  lv_obj_set_size(ctx->modal, LV_PCT(80), LV_PCT(80));
  lv_obj_center(ctx->modal);
  theme_apply_frame(ctx->modal);

  lv_obj_t *title = theme_create_label(ctx->modal, "Error", false);
  theme_apply_label(title, true);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *error = theme_create_label(ctx->modal, message, false);
  theme_apply_label(error, false);
  lv_obj_set_style_text_color(error, error_color(), 0);
  lv_obj_set_width(error, LV_PCT(90));
  lv_label_set_long_mode(error, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(error, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(error, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *hint = theme_create_label(ctx->modal, "Returning...", false);
  theme_apply_label(hint, false);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -10);

  lv_timer_t *timer = lv_timer_create(error_timer_cb, timeout_ms, ctx);
  lv_timer_set_repeat_count(timer, 1);
}

static void add_confirm_button(lv_obj_t *dialog, const char *text,
                               lv_align_t align, lv_color_t color,
                               lv_event_cb_t cb, void *ctx) {
  lv_obj_t *btn = theme_create_button(dialog, text, true);
  lv_obj_set_size(btn, LV_PCT(40), theme_get_button_height());
  lv_obj_align(btn, align, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, ctx);

  lv_obj_t *label = lv_obj_get_child(btn, 0);
  if (label)
    lv_obj_set_style_text_color(label, color, 0);
}

static void show_confirm_internal(const char *message,
                                  dialog_confirm_callback_t callback,
                                  void *user_data, dialog_style_t style,
                                  bool danger) {
  if (!message)
    return;

  confirm_context_t *ctx = malloc(sizeof(confirm_context_t));
  if (!ctx)
    return;

  ctx->callback = callback;
  ctx->user_data = user_data;

  lv_obj_t *dialog = create_dialog_container(style, &ctx->root);

  if (danger && style == DIALOG_STYLE_OVERLAY)
    lv_obj_set_style_border_color(dialog, error_color(), 0);

  lv_obj_t *msg_label = make_message_label(dialog, message, 90);
  lv_label_set_recolor(msg_label, true);
  lv_obj_align(msg_label, LV_ALIGN_TOP_MID, 0, 10);

  add_confirm_button(dialog, "No", LV_ALIGN_BOTTOM_LEFT,
                     danger ? yes_color() : no_color(), confirm_no_cb, ctx);
  add_confirm_button(dialog, "Yes", LV_ALIGN_BOTTOM_RIGHT,
                     danger ? no_color() : yes_color(), confirm_yes_cb, ctx);

  dialog_fit_overlay(dialog, style, message, theme_get_button_height() + 20);
}

void dialog_show_confirm(const char *message,
                         dialog_confirm_callback_t callback, void *user_data,
                         dialog_style_t style) {
  show_confirm_internal(message, callback, user_data, style, false);
}

void dialog_show_danger_confirm(const char *message,
                                dialog_confirm_callback_t callback,
                                void *user_data, dialog_style_t style) {
  show_confirm_internal(message, callback, user_data, style, true);
}

lv_obj_t *dialog_show_progress(const char *title, const char *message,
                               dialog_style_t style) {
  lv_obj_t *root;
  lv_obj_t *dialog = create_dialog_container(style, &root);

  int32_t msg_y = title ? add_dialog_title(dialog, title) + 10 : 5;

  if (message)
    lv_obj_align(make_message_label(dialog, message, 90), LV_ALIGN_TOP_MID, 0,
                 msg_y);

  dialog_fit_overlay(dialog, style, message ? message : "", msg_y + 5);

  return root;
}

void dialog_show_message(const char *title, const char *message) {
  lv_obj_t *modal = lv_obj_create(lv_screen_active());
  lv_obj_set_size(modal, 400, 220);
  lv_obj_center(modal);
  theme_apply_frame(modal);

  lv_obj_t *title_label = theme_create_label(modal, title, false);
  lv_obj_set_style_text_font(title_label, theme_font_small(), 0);
  lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 0);

  lv_obj_t *msg_label = theme_create_label(modal, message, false);
  lv_obj_set_width(msg_label, 340);
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, -10);

  lv_obj_t *btn = theme_create_button(modal, "OK", true);
  lv_obj_set_size(btn, 100, theme_get_min_touch_size());
  lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_add_event_cb(btn, message_close_cb, LV_EVENT_CLICKED, modal);
}
