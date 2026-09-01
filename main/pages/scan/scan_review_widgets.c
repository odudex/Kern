/*
 * Review-screen widgets shared by the PSBT, message and BIP322 displays:
 * amount rows, tip-highlighted addresses, warning notes and the action row.
 */

#include "../../ui/assets/icons.h"
#include "../../ui/theme_widgets.h"
#include "scan_internal.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

#define ADDRESS_TIP_CHARS 6

static void back_button_cb(lv_event_t *e);

void scan_create_sign_action_row(lv_obj_t *parent, lv_event_cb_t sign_cb) {
  lv_obj_t *button_container = theme_create_button_row(parent, 10);
  if (!button_container)
    return;

  lv_obj_t *back_button = theme_create_button(button_container, "Back", false);
  lv_obj_set_size(back_button, LV_PCT(45), LV_SIZE_CONTENT);
  lv_obj_add_event_cb(back_button, back_button_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(back_button, LV_OBJ_FLAG_EVENT_BUBBLE);

  lv_obj_t *sign_button = theme_create_button(button_container, "Sign", false);
  lv_obj_set_size(sign_button, LV_PCT(45), LV_SIZE_CONTENT);
  lv_obj_add_event_cb(sign_button, sign_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(sign_button, LV_OBJ_FLAG_EVENT_BUBBLE);
}

// Format satoshis as Bitcoin with visual grouping: "1.00 000 000"
static void format_btc(char *buf, size_t buf_size, uint64_t sats) {
  uint64_t whole = sats / 100000000ULL;
  uint64_t frac = sats % 100000000ULL;
  // Split fraction: first 2 digits, then two groups of 3
  uint32_t frac_first = (uint32_t)(frac / 1000000ULL);
  uint32_t frac_second = (uint32_t)((frac / 1000ULL) % 1000ULL);
  uint32_t frac_third = (uint32_t)(frac % 1000ULL);
  snprintf(buf, buf_size, "%llu.%02u %03u %03u", whole, frac_first, frac_second,
           frac_third);
}

#define ADDRESS_TIP_CHARS 6

static void add_address_tip_overlay(lv_obj_t *parent, lv_obj_t *base_label,
                                    const char *address, size_t index,
                                    lv_color_t highlight, int32_t x_offset) {
  char text[2] = {address[index], '\0'};
  lv_point_t pos;
  lv_label_get_letter_pos(base_label, (uint32_t)index, &pos);

  lv_obj_t *tip = lv_label_create(parent);
  lv_label_set_text(tip, text);
  lv_obj_set_style_text_font(tip, theme_font_small(), 0);
  lv_obj_set_style_text_color(tip, highlight, 0);
  lv_obj_set_pos(tip, x_offset + pos.x, pos.y);
}

// Plain wrapped address label plus colored overlays for the tip chars. This
// keeps wrapping in LVGL's label engine and avoids recolor/span edge cases.
lv_obj_t *scan_create_address_label(lv_obj_t *parent, const char *address,
                                    lv_color_t highlight, int32_t pad_left) {
  size_t len = strlen(address);
  const lv_font_t *font = theme_font_small();
  lv_obj_update_layout(parent);

  lv_obj_t *container = lv_obj_create(parent);
  theme_apply_transparent_container(container);
  lv_obj_clear_flag(container, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_width(container, LV_PCT(100));
  lv_obj_set_height(container, LV_SIZE_CONTENT);

  int32_t label_width = lv_obj_get_content_width(parent) - pad_left;
  if (label_width < 0)
    label_width = 0;

  lv_obj_t *label = lv_label_create(container);
  lv_obj_set_pos(label, pad_left, 0);
  lv_obj_set_width(label, label_width);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_label_set_text(label, address);
  lv_obj_set_style_text_font(label, font, 0);
  lv_obj_set_style_text_color(label, lv_color_hex(0xAAAAAA), 0);

  lv_obj_update_layout(container);
  lv_obj_update_layout(label);
  lv_obj_set_height(container, lv_obj_get_height(label));

  size_t tip_count = len < ADDRESS_TIP_CHARS ? len : ADDRESS_TIP_CHARS;
  for (size_t i = 0; i < tip_count; i++) {
    add_address_tip_overlay(container, label, address, i, highlight, pad_left);
  }
  if (len > ADDRESS_TIP_CHARS) {
    size_t tail_start = len > ADDRESS_TIP_CHARS * 2 ? len - ADDRESS_TIP_CHARS
                                                    : ADDRESS_TIP_CHARS;
    for (size_t i = tail_start; i < len; i++) {
      add_address_tip_overlay(container, label, address, i, highlight,
                              pad_left);
    }
  }

  return container;
}

// Create a row with: [prefix text] [BTC icon] [formatted value]
lv_obj_t *scan_create_btc_value_row(lv_obj_t *parent, const char *prefix,
                                    uint64_t sats, lv_color_t color) {
  lv_obj_t *row = theme_create_flex_row(parent);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_column(row, 4, 0);

  lv_obj_t *prefix_label = lv_label_create(row);
  lv_label_set_text(prefix_label, prefix);
  lv_obj_set_style_text_font(prefix_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(prefix_label, color, 0);

  lv_obj_t *icon_label = lv_label_create(row);
  lv_label_set_text(icon_label, ICON_BITCOIN);
  lv_obj_set_style_text_font(icon_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(icon_label, color, 0);

  char btc_str[32];
  format_btc(btc_str, sizeof(btc_str), sats);
  lv_obj_t *value_label = lv_label_create(row);
  lv_label_set_text(value_label, btc_str);
  lv_obj_set_style_text_font(value_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(value_label, color, 0);

  return row;
}

void scan_create_review_note(lv_obj_t *parent, const char *text,
                             lv_color_t color) {
  lv_obj_t *label = theme_create_label(parent, text, false);
  lv_obj_set_style_text_color(label, color, 0);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(label, LV_PCT(100));
}

static void back_button_cb(lv_event_t *e) {
  if (scan_ctx.return_cb) {
    scan_ctx.return_cb();
  }
}
