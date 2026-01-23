#include "info_dialog.h"
#include "lvgl.h"
#include "theme.h"
#include <stdlib.h>

typedef struct {
  info_dialog_callback_t callback;
  void *user_data;
  lv_obj_t *root; // blocker (overlay) or dialog (fullscreen)
} info_dialog_context_t;

static void ok_button_cb(lv_event_t *e) {
  info_dialog_context_t *ctx =
      (info_dialog_context_t *)lv_event_get_user_data(e);
  if (!ctx)
    return;

  if (ctx->callback)
    ctx->callback(ctx->user_data);
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
}

static void create_info_dialog_internal(const char *title, const char *message,
                                        info_dialog_callback_t callback,
                                        void *user_data, bool overlay) {
  if (!message)
    return;

  info_dialog_context_t *ctx = malloc(sizeof(info_dialog_context_t));
  if (!ctx)
    return;

  ctx->callback = callback;
  ctx->user_data = user_data;

  lv_obj_t *parent = lv_screen_active();
  lv_obj_t *dialog;

  if (overlay) {
    lv_obj_t *blocker = lv_obj_create(parent);
    lv_obj_remove_style_all(blocker);
    lv_obj_set_size(blocker, LV_PCT(100), LV_PCT(100));
    lv_obj_set_style_bg_color(blocker, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(blocker, LV_OPA_50, 0);
    lv_obj_add_flag(blocker, LV_OBJ_FLAG_CLICKABLE);
    ctx->root = blocker;

    dialog = lv_obj_create(blocker);
    lv_obj_set_size(dialog, LV_PCT(90), LV_PCT(40));
    lv_obj_center(dialog);
    theme_apply_frame(dialog);
    lv_obj_set_style_bg_opa(dialog, LV_OPA_COVER, 0);
  } else {
    dialog = lv_obj_create(parent);
    lv_obj_set_size(dialog, LV_PCT(100), LV_PCT(100));
    theme_apply_screen(dialog);
    ctx->root = dialog;
  }

  if (title) {
    lv_obj_t *title_label = theme_create_label(dialog, title, false);
    lv_obj_set_width(title_label, LV_PCT(90));
    lv_label_set_long_mode(title_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
    lv_obj_set_style_text_color(title_label, highlight_color(), 0);
    lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 10);
  }

  lv_obj_t *message_label = theme_create_label(dialog, message, false);
  lv_obj_set_width(message_label, LV_PCT(90));
  lv_label_set_long_mode(message_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(message_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(message_label, theme_font_medium(), 0);
  lv_obj_center(message_label);

  lv_obj_t *ok_btn = lv_btn_create(dialog);
  lv_obj_set_size(ok_btn, LV_PCT(50), theme_get_button_height());
  lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
  theme_apply_touch_button(ok_btn, true);
  lv_obj_add_event_cb(ok_btn, ok_button_cb, LV_EVENT_CLICKED, ctx);

  lv_obj_t *ok_label = lv_label_create(ok_btn);
  lv_label_set_text(ok_label, "OK");
  lv_obj_center(ok_label);
  lv_obj_set_style_text_color(ok_label, main_color(), 0);
  lv_obj_set_style_text_font(ok_label, theme_font_medium(), 0);
}

void show_info_dialog(const char *title, const char *message,
                      info_dialog_callback_t callback, void *user_data) {
  create_info_dialog_internal(title, message, callback, user_data, false);
}

void show_info_dialog_overlay(const char *title, const char *message,
                              info_dialog_callback_t callback,
                              void *user_data) {
  create_info_dialog_internal(title, message, callback, user_data, true);
}
