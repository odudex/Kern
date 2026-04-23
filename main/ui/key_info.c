#include "key_info.h"
#include "../core/key.h"
#include "assets/icons_24.h"
#include "theme.h"
#include <stdio.h>

lv_obj_t *ui_icon_text_row_create(lv_obj_t *parent, const char *icon,
                                  const char *text, lv_color_t color) {
  char buf[64];
  snprintf(buf, sizeof(buf), "%s %s", icon, text);

  lv_obj_t *label = lv_label_create(parent);
  lv_label_set_text(label, buf);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_set_style_text_color(label, color, 0);

  return label;
}

lv_obj_t *ui_fingerprint_create(lv_obj_t *parent, lv_color_t color) {
  char fingerprint_hex[9];
  if (!key_get_fingerprint_hex(fingerprint_hex))
    return NULL;
  return ui_icon_text_row_create(parent, ICON_FINGERPRINT, fingerprint_hex,
                                 color);
}

lv_obj_t *ui_derivation_create(lv_obj_t *parent, lv_color_t color) {
  (void)parent;
  (void)color;
  return NULL;
}

lv_obj_t *ui_key_info_create(lv_obj_t *parent) {
  lv_obj_t *cont = theme_create_flex_row(parent);
  lv_obj_set_style_pad_column(cont, theme_get_default_padding(), 0);

  // On small screens the row shares space with corner buttons that are
  // absolutely positioned over the page.  Allow wrapping and constrain
  // the row width so content stays between the buttons.
  int btn_zone = theme_get_corner_button_width();
  lv_obj_set_width(cont, lv_pct(100));
  lv_obj_set_style_pad_left(cont, btn_zone, 0);
  lv_obj_set_style_pad_right(cont, btn_zone, 0);
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_ROW_WRAP);

  if (!ui_fingerprint_create(cont, highlight_color())) {
    lv_obj_del(cont);
    return NULL;
  }

  return cont;
}
