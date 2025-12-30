// UI Input Helpers - Shared components for input pages

#ifndef UI_INPUT_HELPERS_H
#define UI_INPUT_HELPERS_H

#include <lvgl.h>

// Creates 60x60 back button at top-left (5,5) with LV_SYMBOL_LEFT
lv_obj_t *ui_create_back_button(lv_obj_t *parent, lv_event_cb_t event_cb);

// Creates 60x60 power button at top-left (5,5) with LV_SYMBOL_POWER
lv_obj_t *ui_create_power_button(lv_obj_t *parent, lv_event_cb_t event_cb);

// Creates 60x60 settings button at top-right with LV_SYMBOL_SETTINGS
lv_obj_t *ui_create_settings_button(lv_obj_t *parent, lv_event_cb_t event_cb);

#endif // UI_INPUT_HELPERS_H
