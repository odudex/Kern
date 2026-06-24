#include "numeric_keypad.h"
#include "dialog.h"
#include "input_helpers.h"
#include "theme_widgets.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ui_numeric_keypad_s {
  ui_numeric_keypad_t **handle;
  ui_numeric_keypad_config_t config;
  lv_obj_t *container;
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

  if (value < keypad->config.min_value)
    return false;

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
    if (invalid_message)
      dialog_show_error_timeout(invalid_message, NULL, 0);
    return;
  }

  ui_numeric_keypad_close(handle);
  if (cb)
    cb(value, user_data);
}

static void cancel_keypad(ui_numeric_keypad_t *keypad) {
  ui_numeric_keypad_t **handle = keypad->handle;
  ui_numeric_keypad_cancel_cb cb = keypad->config.cancel_cb;
  void *user_data = keypad->config.user_data;

  ui_numeric_keypad_close(handle);
  if (cb)
    cb(user_data);
}

static void back_btn_cb(lv_event_t *e) {
  ui_numeric_keypad_t *keypad = lv_event_get_user_data(e);
  cancel_keypad(keypad);
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

static void seed_initial_value(ui_numeric_keypad_t *keypad) {
  uint32_t initial = keypad->config.initial_value;
  if (initial < keypad->config.min_value) {
    keypad->input_buf[0] = '\0';
    keypad->input_len = 0;
    return;
  }
  if (initial > keypad->config.max_value)
    initial = keypad->config.max_value;

  snprintf(keypad->input_buf, sizeof(keypad->input_buf), "%u",
           (unsigned)initial);

  uint8_t max_digits = effective_max_digits(keypad);
  size_t len = strlen(keypad->input_buf);
  if (len > max_digits) {
    len = max_digits;
    keypad->input_buf[len] = '\0';
  }
  keypad->input_len = (int)len;
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
  seed_initial_value(keypad);

  keypad->container = theme_create_page_container(lv_screen_active());
  if (!keypad->container) {
    free(keypad);
    return;
  }

  lv_obj_t *back_btn = ui_create_back_button(keypad->container, NULL);
  lv_obj_add_event_cb(back_btn, back_btn_cb, LV_EVENT_CLICKED, keypad);

  int32_t pad = theme_default_padding();

  lv_obj_t *title = lv_label_create(keypad->container);
  lv_label_set_text(title, keypad->config.title ? keypad->config.title : "");
  lv_obj_set_style_text_font(title, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title, primary_color(), 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, pad);

  keypad->input_label = lv_label_create(keypad->container);
  lv_obj_set_style_text_font(keypad->input_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(keypad->input_label, highlight_color(), 0);
  lv_obj_align(keypad->input_label, LV_ALIGN_TOP_MID, 0,
               theme_corner_button_height() + pad * 2);
  update_input_display(keypad);

  keypad->numpad = lv_btnmatrix_create(keypad->container);
  lv_btnmatrix_set_map(keypad->numpad, NUMPAD_MAP);
  lv_obj_set_size(keypad->numpad, LV_PCT(90), LV_PCT(60));
  lv_obj_align(keypad->numpad, LV_ALIGN_BOTTOM_MID, 0, -pad);
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
  *handle = NULL;
  if (keypad->container)
    lv_obj_del(keypad->container);
  free(keypad);
}
