#ifndef BATTERY_H
#define BATTERY_H

#include <lvgl.h>

/**
 * Create a battery percentage label with auto-refresh timer.
 * Displays a battery-level icon (LV_SYMBOL_BATTERY_*) alongside the charge
 * percentage. Colour reflects charge state: green (>=76%), white (>=40%),
 * orange (>=20%), red (<20%). When charging, LV_SYMBOL_CHARGE is appended
 * to the battery icon and the whole label turns green.
 * Returns NULL if PMIC is unavailable. The refresh timer is automatically
 * deleted when the label is destroyed.
 *
 * @param parent Parent LVGL object
 * @return Label object, or NULL if battery info is unavailable
 */
lv_obj_t *ui_battery_create(lv_obj_t *parent);

#endif
