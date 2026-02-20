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

static void confirm_yes_cb(lv_event_t *e) {
  confirm_context_t *ctx = lv_event_get_user_data(e);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback(true, ctx->user_data);
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
}

static void confirm_no_cb(lv_event_t *e) {
  confirm_context_t *ctx = lv_event_get_user_data(e);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback(false, ctx->user_data);
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
}

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
  lv_obj_t *dialog = lv_event_get_user_data(e);
  lv_obj_del(dialog);
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

/* Adjust overlay dialog height to fit content (capped at 80% of screen).
 * Measures text directly — no layout pass needed. */
static void dialog_fit_overlay(lv_obj_t *dialog, dialog_style_t style,
                               const char *text, int32_t extra_h) {
  if (style != DIALOG_STYLE_OVERLAY)
    return;
  const lv_font_t *font = theme_font_medium();
  int32_t screen_w = lv_disp_get_hor_res(NULL);
  int32_t screen_h = lv_disp_get_ver_res(NULL);
  int32_t pad_h = lv_obj_get_style_pad_left(dialog, 0) +
                  lv_obj_get_style_pad_right(dialog, 0);
  int32_t pad_v = lv_obj_get_style_pad_top(dialog, 0) +
                  lv_obj_get_style_pad_bottom(dialog, 0);
  int32_t border = lv_obj_get_style_border_width(dialog, 0);
  int32_t content_w = screen_w * 90 / 100 - pad_h - border * 2;
  int32_t label_w = content_w * 90 / 100;

  lv_point_t txt_size;
  lv_text_get_size(&txt_size, text, font, 0, 0, label_w, LV_TEXT_FLAG_NONE);

  int32_t needed = txt_size.y + extra_h + pad_v + border * 2;
  int32_t max_h = screen_h * 80 / 100;
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

  int32_t msg_y = 10;
  if (title) {
    lv_obj_t *title_label = theme_create_label(dialog, title, false);
    lv_obj_set_width(title_label, LV_PCT(90));
    lv_label_set_long_mode(title_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
    lv_obj_set_style_text_color(title_label, highlight_color(), 0);
    lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 0);
    msg_y = lv_font_get_line_height(theme_font_medium()) + 10;
  }

  lv_obj_t *msg_label = theme_create_label(dialog, message, false);
  lv_obj_set_width(msg_label, LV_PCT(90));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(msg_label, theme_font_medium(), 0);
  lv_obj_align(msg_label, LV_ALIGN_TOP_MID, 0, msg_y);

  lv_obj_t *ok_btn = lv_btn_create(dialog);
  lv_obj_set_size(ok_btn, LV_PCT(50), theme_get_button_height());
  lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
  theme_apply_touch_button(ok_btn, true);
  lv_obj_add_event_cb(ok_btn, info_ok_cb, LV_EVENT_CLICKED, ctx);

  lv_obj_t *ok_label = lv_label_create(ok_btn);
  lv_label_set_text(ok_label, "OK");
  lv_obj_center(ok_label);
  lv_obj_set_style_text_color(ok_label, main_color(), 0);
  lv_obj_set_style_text_font(ok_label, theme_font_medium(), 0);

  dialog_fit_overlay(dialog, style, message,
                     msg_y + theme_get_button_height() + 10);
}

void dialog_show_error(const char *message, dialog_simple_callback_t callback,
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

  lv_obj_t *msg_label = theme_create_label(dialog, message, false);
  lv_label_set_recolor(msg_label, true);
  lv_obj_set_width(msg_label, LV_PCT(90));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(msg_label, theme_font_medium(), 0);
  lv_obj_align(msg_label, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *no_btn = theme_create_button(dialog, "No", false);
  lv_obj_set_size(no_btn, LV_PCT(40), theme_get_button_height());
  lv_obj_align(no_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_obj_add_event_cb(no_btn, confirm_no_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *no_label = lv_obj_get_child(no_btn, 0);
  if (no_label) {
    lv_obj_set_style_text_color(no_label, danger ? yes_color() : no_color(), 0);
    lv_obj_set_style_text_font(no_label, theme_font_medium(), 0);
  }

  lv_obj_t *yes_btn = theme_create_button(dialog, "Yes", true);
  lv_obj_set_size(yes_btn, LV_PCT(40), theme_get_button_height());
  lv_obj_align(yes_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
  lv_obj_add_event_cb(yes_btn, confirm_yes_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *yes_label = lv_obj_get_child(yes_btn, 0);
  if (yes_label) {
    lv_obj_set_style_text_color(yes_label, danger ? no_color() : yes_color(),
                                0);
    lv_obj_set_style_text_font(yes_label, theme_font_medium(), 0);
  }

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

  int32_t msg_y = 5;
  if (title) {
    lv_obj_t *title_label = theme_create_label(dialog, title, false);
    lv_obj_set_width(title_label, LV_PCT(90));
    lv_label_set_long_mode(title_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
    lv_obj_set_style_text_color(title_label, highlight_color(), 0);
    lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 0);
    msg_y = lv_font_get_line_height(theme_font_medium()) + 10;
  }

  if (message) {
    lv_obj_t *msg_label = theme_create_label(dialog, message, false);
    lv_obj_set_width(msg_label, LV_PCT(90));
    lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(msg_label, theme_font_medium(), 0);
    lv_obj_align(msg_label, LV_ALIGN_TOP_MID, 0, msg_y);
  }

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
  lv_obj_set_size(btn, 100, 50);
  lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_add_event_cb(btn, message_close_cb, LV_EVENT_CLICKED, modal);
}
