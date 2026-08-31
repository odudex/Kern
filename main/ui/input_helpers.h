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

// Travel of the touch so far, against the point it went down at. Called on
// every move once the touch is too far along to be a tap, then a last time
// with released set, whether the finger lifted or slid off the object. Use it
// to follow the finger; call ui_drag_is_swipe() on the last one to decide
// whether the drag counts.
typedef void (*ui_drag_cb_t)(int32_t dx, int32_t dy, bool released);

// Makes obj touchable and splits its touches in two: drag_cb follows the
// moving ones, tap_cb gets a LV_EVENT_CLICKED for the still ones. A touch that
// moved reaches tap_cb no more. Either callback may be NULL.
//
// One object at a time: the travel tracking is global, so a second enabled
// object on screen would take over the tracking mid-touch. tap_cb also gets no
// user data of its own, the event carries the callback pointer instead.
void ui_enable_tap_drag(lv_obj_t *obj, lv_event_cb_t tap_cb,
                        ui_drag_cb_t drag_cb);

// True when a drag travelled far enough to count as a swipe, with dir set to
// the axis it went furthest along.
bool ui_drag_is_swipe(int32_t dx, int32_t dy, lv_dir_t *dir);

#endif
