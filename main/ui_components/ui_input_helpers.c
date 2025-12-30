// UI Input Helpers - Shared components for input pages

#include "ui_input_helpers.h"
#include "theme.h"

#define CORNER_BUTTON_PADDING 20

static lv_obj_t *create_top_left_corner_button(lv_obj_t *parent,
                                               const char *symbol,
                                               lv_event_cb_t event_cb) {
  if (!parent)
    return NULL;

  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 60, 60);
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, CORNER_BUTTON_PADDING,
               CORNER_BUTTON_PADDING);
  lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);

  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, symbol);
  lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_center(label);

  if (event_cb)
    lv_obj_add_event_cb(btn, event_cb, LV_EVENT_CLICKED, NULL);

  return btn;
}

lv_obj_t *ui_create_back_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_top_left_corner_button(parent, LV_SYMBOL_LEFT, event_cb);
}

lv_obj_t *ui_create_power_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_top_left_corner_button(parent, LV_SYMBOL_POWER, event_cb);
}

static lv_obj_t *create_top_right_corner_button(lv_obj_t *parent,
                                                const char *symbol,
                                                lv_event_cb_t event_cb) {
  if (!parent)
    return NULL;

  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 60, 60);
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -CORNER_BUTTON_PADDING,
               CORNER_BUTTON_PADDING);
  lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);

  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, symbol);
  lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_center(label);

  if (event_cb)
    lv_obj_add_event_cb(btn, event_cb, LV_EVENT_CLICKED, NULL);

  return btn;
}

lv_obj_t *ui_create_settings_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_top_right_corner_button(parent, LV_SYMBOL_SETTINGS, event_cb);
}
