#include "key_info.h"
#include "../core/key.h"
#include "../core/wallet.h"
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
  const char *derivation = wallet_get_derivation();
  if (!derivation)
    return NULL;
  return ui_icon_text_row_create(parent, ICON_DERIVATION, derivation, color);
}

lv_obj_t *ui_key_info_create(lv_obj_t *parent) {
  lv_obj_t *cont = theme_create_flex_row(parent);
  lv_obj_set_style_pad_column(cont, theme_get_default_padding(), 0);

  if (!ui_fingerprint_create(cont, highlight_color()) ||
      !ui_derivation_create(cont, secondary_color())) {
    lv_obj_del(cont);
    return NULL;
  }

  return cont;
}
