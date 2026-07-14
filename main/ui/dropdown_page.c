// Full-screen dropdown detail page

#include "dropdown_page.h"
#include "input_helpers.h"
#include "theme.h"
#include "theme_widgets.h"

lv_obj_t *ui_dropdown_page_create(const char *title, const char *description,
                                  const char *options, uint16_t selected,
                                  lv_event_cb_t changed_cb,
                                  lv_event_cb_t back_cb) {
  lv_obj_t *screen = theme_create_page_container(lv_screen_active());
  ui_create_back_button(screen, back_cb);
  theme_create_page_title(screen, title);

  int32_t dropdown_y = 0;
  if (description) {
    lv_obj_t *desc = lv_label_create(screen);
    lv_label_set_text(desc, description);
    lv_obj_set_style_text_color(desc, secondary_color(), 0);
    lv_obj_set_style_text_align(desc, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(desc, LV_PCT(80));
    lv_obj_align(desc, LV_ALIGN_CENTER, 0, -40);
    dropdown_y = 20;
  }

  lv_obj_t *dropdown = theme_create_dropdown(screen, options);
  lv_obj_set_width(dropdown, LV_HOR_RES * 40 / 100);
  lv_obj_align(dropdown, LV_ALIGN_CENTER, 0, dropdown_y);
  lv_dropdown_set_selected(dropdown, selected);
  lv_obj_add_event_cb(dropdown, changed_cb, LV_EVENT_VALUE_CHANGED, NULL);
  return screen;
}

uint16_t ui_index_of_u16(const uint16_t *values, size_t count, uint16_t value,
                         uint16_t fallback) {
  for (size_t i = 0; i < count; i++) {
    if (values[i] == value)
      return (uint16_t)i;
  }
  return fallback;
}
