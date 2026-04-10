// UI Input Helpers - Shared components for input pages

#include "input_helpers.h"
#include "theme.h"

static lv_obj_t *create_top_left_corner_button(lv_obj_t *parent,
                                               const char *symbol,
                                               lv_event_cb_t event_cb) {
  if (!parent)
    return NULL;

  int32_t pad = theme_get_small_padding();

  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, theme_get_corner_button_width(),
                  theme_get_corner_button_height());
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, pad, pad);
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

  int32_t pad = theme_get_small_padding();

  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, theme_get_corner_button_width(),
                  theme_get_corner_button_height());
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -pad, pad);
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

/* ---------- Shared text input component ---------- */

static void ui_text_input_eye_cb(lv_event_t *e) {
  ui_text_input_t *input = lv_event_get_user_data(e);
  if (!input || !input->textarea || !input->eye_label)
    return;
  bool hidden = lv_textarea_get_password_mode(input->textarea);
  lv_textarea_set_password_mode(input->textarea, !hidden);
  lv_label_set_text(input->eye_label,
                    hidden ? LV_SYMBOL_EYE_CLOSE : LV_SYMBOL_EYE_OPEN);
}

void ui_text_input_create(ui_text_input_t *input, lv_obj_t *parent,
                          const char *placeholder, bool password_mode,
                          lv_event_cb_t ready_cb) {
  /* Textarea */
  input->textarea = lv_textarea_create(parent);
  lv_obj_set_size(input->textarea, password_mode ? LV_PCT(80) : LV_PCT(90), 50);
  if (password_mode)
    lv_obj_align(input->textarea, LV_ALIGN_TOP_LEFT, LV_HOR_RES * 5 / 100, 140);
  else
    lv_obj_align(input->textarea, LV_ALIGN_TOP_MID, 0, 140);
  lv_textarea_set_one_line(input->textarea, true);
  lv_textarea_set_password_mode(input->textarea, password_mode);
  lv_textarea_set_placeholder_text(input->textarea, placeholder);
  lv_obj_set_style_text_font(input->textarea, theme_font_small(), 0);
  lv_obj_set_style_bg_color(input->textarea, panel_color(), 0);
  lv_obj_set_style_text_color(input->textarea, main_color(), 0);
  lv_obj_set_style_border_color(input->textarea, secondary_color(), 0);
  lv_obj_set_style_border_width(input->textarea, 1, 0);
  lv_obj_set_style_bg_color(input->textarea, highlight_color(), LV_PART_CURSOR);
  lv_obj_set_style_bg_opa(input->textarea, LV_OPA_COVER, LV_PART_CURSOR);

  /* Eye toggle (password mode only) */
  if (password_mode) {
    input->eye_btn = lv_btn_create(parent);
    lv_obj_set_size(input->eye_btn, theme_get_min_touch_size(),
                    theme_get_min_touch_size());
    lv_obj_align_to(input->eye_btn, input->textarea, LV_ALIGN_OUT_RIGHT_MID, 5,
                    0);
    lv_obj_set_style_bg_opa(input->eye_btn, LV_OPA_TRANSP, 0);
    lv_obj_set_style_shadow_width(input->eye_btn, 0, 0);
    lv_obj_set_style_border_width(input->eye_btn, 0, 0);
    lv_obj_add_event_cb(input->eye_btn, ui_text_input_eye_cb, LV_EVENT_CLICKED,
                        input);

    input->eye_label = lv_label_create(input->eye_btn);
    lv_label_set_text(input->eye_label, LV_SYMBOL_EYE_OPEN);
    lv_obj_set_style_text_color(input->eye_label, secondary_color(), 0);
    lv_obj_set_style_text_font(input->eye_label, theme_font_small(), 0);
    lv_obj_center(input->eye_label);
  } else {
    input->eye_btn = NULL;
    input->eye_label = NULL;
  }

  /* Input group */
  input->input_group = lv_group_create();
  lv_group_add_obj(input->input_group, input->textarea);
  lv_group_focus_obj(input->textarea);

  /* Keyboard on active screen */
  input->keyboard = lv_keyboard_create(lv_screen_active());
  lv_obj_set_size(input->keyboard, LV_HOR_RES, LV_VER_RES * 55 / 100);
  lv_obj_align(input->keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_keyboard_set_textarea(input->keyboard, input->textarea);
  lv_keyboard_set_mode(input->keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);
  lv_obj_add_event_cb(input->keyboard, ready_cb, LV_EVENT_READY, NULL);

  /* Keyboard dark theme */
  lv_obj_set_style_bg_color(input->keyboard, lv_color_black(), 0);
  lv_obj_set_style_border_width(input->keyboard, 0, 0);
  lv_obj_set_style_pad_all(input->keyboard, 4, 0);
  lv_obj_set_style_pad_gap(input->keyboard, 6, 0);
  lv_obj_set_style_bg_color(input->keyboard, disabled_color(), LV_PART_ITEMS);
  lv_obj_set_style_text_color(input->keyboard, main_color(), LV_PART_ITEMS);
  lv_obj_set_style_text_font(input->keyboard, theme_font_small(),
                             LV_PART_ITEMS);
  lv_obj_set_style_border_width(input->keyboard, 0, LV_PART_ITEMS);
  lv_obj_set_style_radius(input->keyboard, 6, LV_PART_ITEMS);
  lv_obj_set_style_bg_color(input->keyboard, highlight_color(),
                            LV_PART_ITEMS | LV_STATE_PRESSED);
  lv_obj_set_style_bg_color(input->keyboard, highlight_color(),
                            LV_PART_ITEMS | LV_STATE_CHECKED);
}

void ui_text_input_show(ui_text_input_t *input) {
  if (input->textarea)
    lv_obj_clear_flag(input->textarea, LV_OBJ_FLAG_HIDDEN);
  if (input->eye_btn)
    lv_obj_clear_flag(input->eye_btn, LV_OBJ_FLAG_HIDDEN);
  if (input->keyboard)
    lv_obj_clear_flag(input->keyboard, LV_OBJ_FLAG_HIDDEN);
}

void ui_text_input_hide(ui_text_input_t *input) {
  if (input->textarea)
    lv_obj_add_flag(input->textarea, LV_OBJ_FLAG_HIDDEN);
  if (input->eye_btn)
    lv_obj_add_flag(input->eye_btn, LV_OBJ_FLAG_HIDDEN);
  if (input->keyboard)
    lv_obj_add_flag(input->keyboard, LV_OBJ_FLAG_HIDDEN);
}

void ui_text_input_destroy(ui_text_input_t *input) {
  if (input->input_group) {
    lv_group_del(input->input_group);
    input->input_group = NULL;
  }
  if (input->keyboard) {
    lv_obj_del(input->keyboard);
    input->keyboard = NULL;
  }
  input->textarea = NULL;
  input->eye_btn = NULL;
  input->eye_label = NULL;
}
