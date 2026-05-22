#include "numeric_keypad.h"
#include "dialog.h"
#include "theme.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ui_numeric_keypad_s {
  ui_numeric_keypad_t **handle;
  ui_numeric_keypad_config_t config;
  lv_obj_t *overlay;
  lv_obj_t *numpad;
  lv_obj_t *input_label;
  char input_buf[12];
  int input_len;
};

static const char *NUMPAD_MAP[] = {"1",
                                   "2",
                                   "3",
                                   "\n",
                                   "4",
                                   "5",
                                   "6",
                                   "\n",
                                   "7",
                                   "8",
                                   "9",
                                   "\n",
                                   LV_SYMBOL_BACKSPACE,
                                   "0",
                                   LV_SYMBOL_OK,
                                   ""};

static uint8_t effective_max_digits(const ui_numeric_keypad_t *keypad) {
  uint8_t max_digits =
      keypad->config.max_digits > 0 ? keypad->config.max_digits : 10;
  uint8_t input_limit = sizeof(keypad->input_buf) - 1;
  return max_digits < input_limit ? max_digits : input_limit;
}

static void update_input_display(ui_numeric_keypad_t *keypad) {
  if (!keypad->input_label)
    return;

  char display[14];
  if (keypad->input_len == 0)
    snprintf(display, sizeof(display), "_");
  else
    snprintf(display, sizeof(display), "%s_", keypad->input_buf);
  lv_label_set_text(keypad->input_label, display);
}

static void update_numpad_buttons(ui_numeric_keypad_t *keypad) {
  if (!keypad->numpad)
    return;

  bool empty = (keypad->input_len == 0);
  if (empty) {
    lv_btnmatrix_set_btn_ctrl(keypad->numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_set_btn_ctrl(keypad->numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  } else {
    lv_btnmatrix_clear_btn_ctrl(keypad->numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_clear_btn_ctrl(keypad->numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  }
}

static bool parse_value(const ui_numeric_keypad_t *keypad,
                        uint32_t *value_out) {
  if (!keypad || keypad->input_len == 0 || !value_out)
    return false;

  uint32_t value = 0;
  for (int i = 0; i < keypad->input_len; i++) {
    uint32_t digit = (uint32_t)(keypad->input_buf[i] - '0');
    if (value > keypad->config.max_value / 10 ||
        (value == keypad->config.max_value / 10 &&
         digit > keypad->config.max_value % 10))
      return false;
    value = value * 10 + digit;
  }

  *value_out = value;
  return true;
}

static void submit_value(ui_numeric_keypad_t *keypad) {
  uint32_t value = 0;
  ui_numeric_keypad_t **handle = keypad->handle;
  ui_numeric_keypad_submit_cb cb = keypad->config.submit_cb;
  void *user_data = keypad->config.user_data;
  const char *invalid_message = keypad->config.invalid_message;

  if (!parse_value(keypad, &value)) {
    if (invalid_message) {
      dialog_show_error(invalid_message, NULL, 0);
    } else {
      ui_numeric_keypad_close(handle);
    }
    return;
  }

  ui_numeric_keypad_close(handle);
  if (cb)
    cb(value, user_data);
}

static void numpad_event_cb(lv_event_t *e) {
  ui_numeric_keypad_t *keypad = lv_event_get_user_data(e);
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    submit_value(keypad);
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (keypad->input_len > 0) {
      keypad->input_len--;
      keypad->input_buf[keypad->input_len] = '\0';
      update_input_display(keypad);
      update_numpad_buttons(keypad);
    }
  } else if (keypad->input_len < effective_max_digits(keypad)) {
    keypad->input_buf[keypad->input_len++] = txt[0];
    keypad->input_buf[keypad->input_len] = '\0';
    update_input_display(keypad);
    update_numpad_buttons(keypad);
  }
}

void ui_numeric_keypad_open(ui_numeric_keypad_t **handle,
                            const ui_numeric_keypad_config_t *config) {
  if (!handle || !config)
    return;

  ui_numeric_keypad_close(handle);

  ui_numeric_keypad_t *keypad = calloc(1, sizeof(*keypad));
  if (!keypad)
    return;

  keypad->handle = handle;
  keypad->config = *config;
  keypad->input_len = snprintf(keypad->input_buf, sizeof(keypad->input_buf),
                               "%u", keypad->config.initial_value);

  keypad->overlay = lv_obj_create(lv_screen_active());
  lv_obj_remove_style_all(keypad->overlay);
  lv_obj_set_size(keypad->overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(keypad->overlay, lv_color_black(), 0);
  lv_obj_set_style_bg_opa(keypad->overlay, LV_OPA_50, 0);
  lv_obj_add_flag(keypad->overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *modal = lv_obj_create(keypad->overlay);
  lv_obj_set_size(modal, LV_PCT(80), LV_PCT(80));
  lv_obj_center(modal);
  theme_apply_frame(modal);
  lv_obj_set_style_bg_opa(modal, LV_OPA_90, 0);
  lv_obj_clear_flag(modal, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(modal, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(modal, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(modal, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(modal, 15, 0);

  lv_obj_t *title = lv_label_create(modal);
  lv_label_set_text(title, keypad->config.title ? keypad->config.title : "");
  lv_obj_set_style_text_font(title, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title, main_color(), 0);

  keypad->input_label = lv_label_create(modal);
  lv_obj_set_style_text_font(keypad->input_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(keypad->input_label, highlight_color(), 0);
  update_input_display(keypad);

  keypad->numpad = lv_btnmatrix_create(modal);
  lv_btnmatrix_set_map(keypad->numpad, NUMPAD_MAP);
  lv_obj_set_size(keypad->numpad, LV_PCT(100), LV_PCT(70));
  lv_obj_set_flex_grow(keypad->numpad, 1);
  theme_apply_btnmatrix(keypad->numpad);
  lv_obj_add_event_cb(keypad->numpad, numpad_event_cb, LV_EVENT_VALUE_CHANGED,
                      keypad);
  update_numpad_buttons(keypad);

  *handle = keypad;
}

void ui_numeric_keypad_close(ui_numeric_keypad_t **handle) {
  if (!handle || !*handle)
    return;

  ui_numeric_keypad_t *keypad = *handle;
  if (keypad->overlay)
    lv_obj_del(keypad->overlay);
  *handle = NULL;
  free(keypad);
}
