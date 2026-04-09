// UI Keyboard - QWERTY grid using lv_buttonmatrix

#include "keyboard.h"
#include "theme.h"
#include <stdlib.h>
#include <string.h>

static const char *kb_map[] = {"q",
                               "w",
                               "e",
                               "r",
                               "t",
                               "y",
                               "u",
                               "i",
                               "o",
                               "p",
                               "\n",
                               "a",
                               "s",
                               "d",
                               "f",
                               "g",
                               "h",
                               "j",
                               "k",
                               "l",
                               "\n",
                               "z",
                               "x",
                               "c",
                               "v",
                               "b",
                               "n",
                               "m",
                               LV_SYMBOL_BACKSPACE,
                               LV_SYMBOL_OK,
                               ""};

static const char btn_to_char[] = {
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd',  'f',
    'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c', 'v', 'b', 'n', 'm', '\b', '\n'};

#define BTN_COUNT (sizeof(btn_to_char) / sizeof((btn_to_char)[0]))

static int get_key_index_from_btn(uint32_t btn_id) {
  if (btn_id >= BTN_COUNT)
    return -1;
  char c = btn_to_char[btn_id];
  if (c >= 'a' && c <= 'z')
    return c - 'a';
  if (c == '\b')
    return UI_KB_KEY_BACKSPACE;
  if (c == '\n')
    return UI_KB_KEY_OK;
  return -1;
}

static inline char get_char_for_btn(uint32_t btn_id) {
  return (btn_id < BTN_COUNT) ? btn_to_char[btn_id] : 0;
}

static int get_btn_for_key_index(int key_index) {
  if (key_index == UI_KB_KEY_BACKSPACE)
    return 26;
  if (key_index == UI_KB_KEY_OK)
    return 27;
  if (key_index >= UI_KB_KEY_A && key_index <= UI_KB_KEY_Z) {
    char target = 'a' + key_index;
    for (size_t i = 0; i < BTN_COUNT; i++) {
      if (btn_to_char[i] == target)
        return (int)i;
    }
  }
  return -1;
}

static inline bool is_key_enabled(ui_keyboard_t *kb, int key_index) {
  return (key_index >= 0 && key_index < UI_KB_KEY_COUNT) &&
         kb->enabled_keys[key_index];
}

static void kb_event_handler(lv_event_t *e) {
  lv_event_code_t code = lv_event_get_code(e);
  lv_obj_t *btnm = lv_event_get_target(e);
  ui_keyboard_t *kb = (ui_keyboard_t *)lv_event_get_user_data(e);

  if (code == LV_EVENT_VALUE_CHANGED) {
    uint32_t btn_id = lv_buttonmatrix_get_selected_button(btnm);
    if (btn_id == LV_BUTTONMATRIX_BUTTON_NONE)
      return;

    int key_index = get_key_index_from_btn(btn_id);
    if (key_index < 0 || !is_key_enabled(kb, key_index))
      return;

    char key_char = get_char_for_btn(btn_id);
    if (kb->callback && key_char != 0)
      kb->callback(key_char);
  }
}

ui_keyboard_t *ui_keyboard_create(lv_obj_t *parent, const char *title,
                                  ui_keyboard_callback_t callback) {
  if (!parent)
    return NULL;

  ui_keyboard_t *kb = (ui_keyboard_t *)malloc(sizeof(ui_keyboard_t));
  if (!kb)
    return NULL;
  memset(kb, 0, sizeof(ui_keyboard_t));

  kb->callback = callback;
  kb->container = parent;

  for (int i = 0; i < UI_KB_KEY_COUNT; i++) {
    kb->enabled_keys[i] = (i != UI_KB_KEY_OK);
  }

  kb->title_label = lv_label_create(parent);
  lv_label_set_text(kb->title_label, title ? title : "");
  lv_obj_set_style_text_color(kb->title_label, secondary_color(), 0);
  lv_obj_set_style_text_font(kb->title_label, theme_font_small(), 0);
  lv_obj_align(kb->title_label, LV_ALIGN_TOP_MID, 0,
               theme_get_default_padding());

  kb->input_label = lv_label_create(parent);
  lv_label_set_text(kb->input_label, "_");
  lv_obj_set_style_text_color(kb->input_label, highlight_color(), 0);
  lv_obj_set_style_text_font(kb->input_label, theme_font_medium(), 0);
  lv_obj_align(kb->input_label, LV_ALIGN_TOP_MID, 0, 130);

  kb->btnmatrix = lv_buttonmatrix_create(parent);
  lv_buttonmatrix_set_map(kb->btnmatrix, kb_map);
  lv_obj_align(kb->btnmatrix, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_size(kb->btnmatrix, LV_PCT(100), LV_PCT(50));
  theme_apply_btnmatrix(kb->btnmatrix);

  lv_obj_add_event_cb(kb->btnmatrix, kb_event_handler, LV_EVENT_VALUE_CHANGED,
                      kb);
  lv_buttonmatrix_set_selected_button(kb->btnmatrix, 0);
  lv_buttonmatrix_set_button_ctrl(kb->btnmatrix, 27,
                                  LV_BUTTONMATRIX_CTRL_DISABLED);

  return kb;
}

void ui_keyboard_set_title(ui_keyboard_t *kb, const char *title) {
  if (kb && kb->title_label)
    lv_label_set_text(kb->title_label, title ? title : "");
}

void ui_keyboard_set_input_text(ui_keyboard_t *kb, const char *text) {
  if (!kb || !kb->input_label)
    return;
  if (text && text[0] != '\0') {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s_", text);
    lv_label_set_text(kb->input_label, buf);
  } else {
    lv_label_set_text(kb->input_label, "_");
  }
}

void ui_keyboard_set_key_enabled(ui_keyboard_t *kb, int key_index,
                                 bool enabled) {
  if (!kb || key_index < 0 || key_index >= UI_KB_KEY_COUNT)
    return;

  kb->enabled_keys[key_index] = enabled;

  if (kb->btnmatrix) {
    int btn_pos = get_btn_for_key_index(key_index);
    if (btn_pos < 0)
      return;

    if (enabled) {
      lv_buttonmatrix_clear_button_ctrl(kb->btnmatrix, (uint32_t)btn_pos,
                                        LV_BUTTONMATRIX_CTRL_DISABLED);
    } else {
      lv_buttonmatrix_set_button_ctrl(kb->btnmatrix, (uint32_t)btn_pos,
                                      LV_BUTTONMATRIX_CTRL_DISABLED);
    }
  }
}

void ui_keyboard_set_letters_enabled(ui_keyboard_t *kb, uint32_t letter_mask) {
  if (!kb)
    return;
  for (int i = 0; i < 26; i++) {
    ui_keyboard_set_key_enabled(kb, UI_KB_KEY_A + i,
                                (letter_mask & (1u << i)) != 0);
  }
}

void ui_keyboard_enable_all(ui_keyboard_t *kb) {
  if (!kb)
    return;
  for (int i = 0; i < UI_KB_KEY_COUNT; i++)
    ui_keyboard_set_key_enabled(kb, i, true);
}

void ui_keyboard_set_ok_enabled(ui_keyboard_t *kb, bool enabled) {
  ui_keyboard_set_key_enabled(kb, UI_KB_KEY_OK, enabled);
}

void ui_keyboard_show(ui_keyboard_t *kb) {
  if (!kb)
    return;
  if (kb->title_label)
    lv_obj_clear_flag(kb->title_label, LV_OBJ_FLAG_HIDDEN);
  if (kb->input_label)
    lv_obj_clear_flag(kb->input_label, LV_OBJ_FLAG_HIDDEN);
  if (kb->btnmatrix)
    lv_obj_clear_flag(kb->btnmatrix, LV_OBJ_FLAG_HIDDEN);
}

void ui_keyboard_hide(ui_keyboard_t *kb) {
  if (!kb)
    return;
  if (kb->title_label)
    lv_obj_add_flag(kb->title_label, LV_OBJ_FLAG_HIDDEN);
  if (kb->input_label)
    lv_obj_add_flag(kb->input_label, LV_OBJ_FLAG_HIDDEN);
  if (kb->btnmatrix)
    lv_obj_add_flag(kb->btnmatrix, LV_OBJ_FLAG_HIDDEN);
}

void ui_keyboard_destroy(ui_keyboard_t *kb) {
  if (!kb)
    return;
  if (kb->btnmatrix)
    lv_obj_del(kb->btnmatrix);
  if (kb->input_label)
    lv_obj_del(kb->input_label);
  if (kb->title_label)
    lv_obj_del(kb->title_label);
  free(kb);
}
