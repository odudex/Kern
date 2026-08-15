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

// Creates info button at top-right with the circle-info icon
lv_obj_t *ui_create_info_button(lv_obj_t *parent, lv_event_cb_t event_cb);

// Makes obj touchable and splits its touches in two: swipe_cb gets a
// LV_EVENT_GESTURE per swipe, tap_cb a LV_EVENT_CLICKED per tap. Either
// callback may be NULL.
void ui_enable_tap_swipe(lv_obj_t *obj, lv_event_cb_t tap_cb,
                         lv_event_cb_t swipe_cb);

// Direction of a LV_EVENT_GESTURE event, or LV_DIR_NONE if there is none.
// Consumes the touch: without this LVGL still reports a click on release and
// the tap callback would fire on top of the swipe.
lv_dir_t ui_consume_swipe_dir(lv_event_t *e);

#endif
