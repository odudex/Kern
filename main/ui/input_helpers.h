// UI Input Helpers - Shared components for input pages

#ifndef INPUT_HELPERS_H
#define INPUT_HELPERS_H

#include <lvgl.h>
#include <stdbool.h>

// Shared text input: textarea + optional eye toggle + keyboard
typedef struct {
  lv_obj_t *textarea;
  lv_obj_t *eye_btn;
  lv_obj_t *eye_label;
  lv_obj_t *keyboard;
  lv_group_t *input_group;
} ui_text_input_t;

// Creates textarea + eye toggle (if password_mode) + keyboard with dark theme.
// Struct is caller-owned; reusable after destroy.
void ui_text_input_create(ui_text_input_t *input, lv_obj_t *parent,
                          const char *placeholder, bool password_mode,
                          lv_event_cb_t ready_cb);
void ui_text_input_show(ui_text_input_t *input);
void ui_text_input_hide(ui_text_input_t *input);
void ui_text_input_destroy(ui_text_input_t *input);

// Creates back button at top-left with LV_SYMBOL_LEFT
lv_obj_t *ui_create_back_button(lv_obj_t *parent, lv_event_cb_t event_cb);

// Creates power button at top-left with LV_SYMBOL_POWER
lv_obj_t *ui_create_power_button(lv_obj_t *parent, lv_event_cb_t event_cb);

// Creates settings button at top-right with LV_SYMBOL_SETTINGS
lv_obj_t *ui_create_settings_button(lv_obj_t *parent, lv_event_cb_t event_cb);

#endif
