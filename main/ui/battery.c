#include "battery.h"
#include "theme.h"
#include <bsp/pmic.h>
#include <stdio.h>

#define BATTERY_REFRESH_MS 30000

static void battery_update(lv_obj_t *label) {
  uint8_t pct;
  if (bsp_pmic_get_battery_percent(&pct) != ESP_OK)
    return;
  bsp_pmic_chg_t chg = BSP_PMIC_CHG_DISCHARGING;
  bsp_pmic_get_charge_status(&chg);

  const char *battery_icon;
  lv_color_t color;
  if (pct >= 76) {
    battery_icon = LV_SYMBOL_BATTERY_FULL;
    color = yes_color();
  } else if (pct >= 40) {
    battery_icon = LV_SYMBOL_BATTERY_3;
    color = main_color();
  } else if (pct >= 20) {
    battery_icon = LV_SYMBOL_BATTERY_2;
    color = highlight_color();
  } else if (pct >= 5) {
    battery_icon = LV_SYMBOL_BATTERY_1;
    color = error_color();
  } else {
    battery_icon = LV_SYMBOL_BATTERY_EMPTY;
    color = error_color();
  }

  char buf[32];
  if (chg == BSP_PMIC_CHG_CHARGING) {
    snprintf(buf, sizeof(buf), "%s%s %u%%", battery_icon, LV_SYMBOL_CHARGE, pct);
    color = yes_color();
  } else {
    snprintf(buf, sizeof(buf), "%s %u%%", battery_icon, pct);
  }
  lv_label_set_text(label, buf);
  lv_obj_set_style_text_color(label, color, 0);
}

static void battery_timer_cb(lv_timer_t *t) {
  battery_update(lv_timer_get_user_data(t));
}

static void battery_label_deleted_cb(lv_event_t *e) {
  lv_timer_t *timer = lv_event_get_user_data(e);
  lv_timer_delete(timer);
}

lv_obj_t *ui_battery_create(lv_obj_t *parent) {
  if (!bsp_pmic_is_available())
    return NULL;

  lv_obj_t *label = lv_label_create(parent);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);

  battery_update(label);

  lv_timer_t *timer =
      lv_timer_create(battery_timer_cb, BATTERY_REFRESH_MS, label);
  lv_obj_add_event_cb(label, battery_label_deleted_cb, LV_EVENT_DELETE, timer);

  return label;
}
