// Derivation path keypad — numeric_keypad's overlay shape with "/" and "h"
// (hardened) keys and string (BIP32 path) submission instead of a uint32
// value.

#include "path_keypad.h"
#include "../core/bip32_path.h"
#include "dialog.h"
#include "input_helpers.h"
#include "theme_widgets.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_KEYPAD_PREFIX_LEN 2 // "m/" is fixed
#define PATH_KEYPAD_MAX_INPUT 64
#define PATH_KEYPAD_DEFAULT_DEPTH 10 // KEY_MAX_DERIVATION_DEPTH

struct ui_path_keypad_s {
  ui_path_keypad_t **handle;
  ui_path_keypad_config_t config;
  lv_obj_t *container;
  lv_obj_t *keypad;
  lv_obj_t *input_label;
  char input_buf[PATH_KEYPAD_MAX_INPUT + 1];
  int input_len;
};

static const char *KEYPAD_MAP[] = {
    "1",          "2",  "3", "/", "\n", "4", "5",  "6",
    "h",          "\n", "7", "8", "9",  "0", "\n", LV_SYMBOL_BACKSPACE,
    LV_SYMBOL_OK, ""};
#define KEY_IDX_BACKSPACE 12
#define KEY_IDX_OK 13

static void update_input_display(ui_path_keypad_t *keypad) {
  if (!keypad->input_label)
    return;

  char display[sizeof(keypad->input_buf) + 1];
  snprintf(display, sizeof(display), "%s_", keypad->input_buf);
  lv_label_set_text(keypad->input_label, display);
}

static void update_keypad_buttons(ui_path_keypad_t *keypad) {
  if (!keypad->keypad)
    return;

  if (keypad->input_len <= PATH_KEYPAD_PREFIX_LEN)
    lv_btnmatrix_set_btn_ctrl(keypad->keypad, KEY_IDX_BACKSPACE,
                              LV_BTNMATRIX_CTRL_DISABLED);
  else
    lv_btnmatrix_clear_btn_ctrl(keypad->keypad, KEY_IDX_BACKSPACE,
                                LV_BTNMATRIX_CTRL_DISABLED);
}

static bool parse_path(const ui_path_keypad_t *keypad, uint32_t *components,
                       size_t components_count, size_t *depth_out) {
  size_t max_depth = keypad->config.max_depth > 0 ? keypad->config.max_depth
                                                  : PATH_KEYPAD_DEFAULT_DEPTH;
  if (max_depth > components_count)
    max_depth = components_count;
  return bip32_path_parse(keypad->input_buf, components, depth_out,
                          max_depth) &&
         *depth_out >= 1;
}

static void do_submit(ui_path_keypad_t *keypad) {
  ui_path_keypad_t **handle = keypad->handle;
  ui_path_keypad_submit_cb cb = keypad->config.submit_cb;
  void *user_data = keypad->config.user_data;

  char path[sizeof(keypad->input_buf)];
  strcpy(path, keypad->input_buf);
  ui_path_keypad_close(handle);
  if (cb)
    cb(path, user_data);
}

static void unhardened_confirm_cb(bool confirmed, void *user_data) {
  ui_path_keypad_t *keypad = user_data;
  if (confirmed)
    do_submit(keypad);
}

static void submit_path(ui_path_keypad_t *keypad) {
  uint32_t components[16];
  size_t depth = 0;
  if (!parse_path(keypad, components,
                  sizeof(components) / sizeof(components[0]), &depth)) {
    if (keypad->config.invalid_message)
      dialog_show_error_timeout(keypad->config.invalid_message, NULL, 0);
    return;
  }

  for (size_t i = 0; i < depth; i++) {
    if (!bip32_path_is_hardened(components[i])) {
      dialog_show_confirm("Path has unhardened nodes.\nProceed anyway?",
                          unhardened_confirm_cb, keypad, DIALOG_STYLE_OVERLAY);
      return;
    }
  }

  do_submit(keypad);
}

static void cancel_keypad(ui_path_keypad_t *keypad) {
  ui_path_keypad_t **handle = keypad->handle;
  ui_path_keypad_cancel_cb cb = keypad->config.cancel_cb;
  void *user_data = keypad->config.user_data;

  ui_path_keypad_close(handle);
  if (cb)
    cb(user_data);
}

static void back_btn_cb(lv_event_t *e) {
  ui_path_keypad_t *keypad = lv_event_get_user_data(e);
  cancel_keypad(keypad);
}

static void keypad_event_cb(lv_event_t *e) {
  ui_path_keypad_t *keypad = lv_event_get_user_data(e);
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    submit_path(keypad);
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (keypad->input_len > PATH_KEYPAD_PREFIX_LEN) {
      keypad->input_len--;
      keypad->input_buf[keypad->input_len] = '\0';
      update_input_display(keypad);
      update_keypad_buttons(keypad);
    }
  } else if (keypad->input_len < PATH_KEYPAD_MAX_INPUT) {
    keypad->input_buf[keypad->input_len++] = txt[0];
    keypad->input_buf[keypad->input_len] = '\0';
    update_input_display(keypad);
    update_keypad_buttons(keypad);
  }
}

static void seed_initial_path(ui_path_keypad_t *keypad) {
  const char *initial = keypad->config.initial_path;
  if (initial && strncmp(initial, "m/", PATH_KEYPAD_PREFIX_LEN) == 0 &&
      strlen(initial) <= PATH_KEYPAD_MAX_INPUT)
    strcpy(keypad->input_buf, initial);
  else
    strcpy(keypad->input_buf, "m/");
  keypad->input_len = (int)strlen(keypad->input_buf);
}

void ui_path_keypad_open(ui_path_keypad_t **handle,
                         const ui_path_keypad_config_t *config) {
  if (!handle || !config)
    return;

  ui_path_keypad_close(handle);

  ui_path_keypad_t *keypad = calloc(1, sizeof(*keypad));
  if (!keypad)
    return;

  keypad->handle = handle;
  keypad->config = *config;
  seed_initial_path(keypad);

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
  lv_obj_set_width(keypad->input_label, LV_PCT(90));
  lv_label_set_long_mode(keypad->input_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(keypad->input_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(keypad->input_label, LV_ALIGN_TOP_MID, 0,
               theme_corner_button_height() + pad * 2);
  update_input_display(keypad);

  keypad->keypad = lv_btnmatrix_create(keypad->container);
  lv_btnmatrix_set_map(keypad->keypad, KEYPAD_MAP);
  lv_obj_set_size(keypad->keypad, LV_PCT(90), LV_PCT(60));
  lv_obj_align(keypad->keypad, LV_ALIGN_BOTTOM_MID, 0, -pad);
  theme_apply_btnmatrix(keypad->keypad);
  lv_obj_add_event_cb(keypad->keypad, keypad_event_cb, LV_EVENT_VALUE_CHANGED,
                      keypad);
  update_keypad_buttons(keypad);

  *handle = keypad;
}

void ui_path_keypad_close(ui_path_keypad_t **handle) {
  if (!handle || !*handle)
    return;

  ui_path_keypad_t *keypad = *handle;
  *handle = NULL;
  if (keypad->container)
    lv_obj_del(keypad->container);
  free(keypad);
}
