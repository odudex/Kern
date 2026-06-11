#include "key_info.h"
#include "../core/key.h"
#include "../core/wallet.h"
#include "assets/icons_24.h"
#include "battery.h"
#include "theme_widgets.h"
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
  lv_obj_set_style_pad_column(cont, theme_default_padding(), 0);

  // The parent (menu nav bar or key info bar) reserves the corner-button
  // zones; wrap as a last resort if the content still doesn't fit.
  lv_obj_set_width(cont, lv_pct(100));
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_ROW_WRAP);

  if (!ui_fingerprint_create(cont, highlight_color())) {
    lv_obj_del(cont);
    return NULL;
  }

  if (wallet_is_initialized() &&
      wallet_get_network() == WALLET_NETWORK_TESTNET) {
    lv_obj_t *net_label = lv_label_create(cont);
    lv_label_set_text(net_label, "testnet");
    lv_obj_set_style_text_font(net_label, theme_font_small(), 0);
    lv_obj_set_style_text_color(net_label, good_color(), 0);
  }

  return cont;
}

lv_obj_t *ui_key_info_bar_create(lv_obj_t *parent) {
  lv_obj_t *bar = lv_obj_create(parent);
  lv_obj_set_size(bar, LV_PCT(100), theme_corner_button_height());
  theme_apply_transparent_container(bar);
  lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(bar, LV_OBJ_FLAG_SCROLLABLE);
  // Same corner-button reservation as the ui_menu nav bar, so headers sit at
  // identical positions on menu and non-menu pages
  lv_obj_set_style_pad_hor(
      bar, theme_small_padding() + theme_corner_button_width(), 0);

  lv_obj_t *header = ui_key_info_create(bar);
  if (!header) {
    lv_obj_del(bar);
    return NULL;
  }
  ui_battery_create(header);
  return bar;
}
