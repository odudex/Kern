#include "theme_widgets.h"
#include "theme_palette.h"

void theme_apply_screen(lv_obj_t *obj) {
  if (!obj)
    return;

  lv_obj_set_style_bg_color(obj, COLOR_BG, 0);
  lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
  lv_obj_set_style_text_color(obj, COLOR_WHITE, 0);
  lv_obj_set_style_text_font(obj, theme_font_small(), 0);
  lv_obj_set_style_border_width(obj, 0, 0);
  lv_obj_set_style_outline_width(obj, 0, 0);
}

lv_obj_t *theme_create_page_container(lv_obj_t *parent) {
  if (!parent)
    return NULL;

  lv_obj_t *container = lv_obj_create(parent);
  lv_obj_set_size(container, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(container, COLOR_BG, 0);
  lv_obj_set_style_bg_opa(container, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(container, 0, 0);
  lv_obj_set_style_pad_all(container, 0, 0);
  lv_obj_set_style_radius(container, 0, 0);
  lv_obj_set_style_shadow_width(container, 0, 0);
  lv_obj_clear_flag(container, LV_OBJ_FLAG_SCROLLABLE);

  return container;
}

void theme_apply_frame(lv_obj_t *frame) {
  if (!frame)
    return;

  lv_obj_set_style_bg_color(frame, COLOR_PANEL, 0);
  lv_obj_set_style_bg_opa(frame, LV_OPA_90, 0);
  lv_obj_set_style_border_color(frame, COLOR_WHITE, 0);
  lv_obj_set_style_border_width(frame, 2, 0);
  lv_obj_set_style_radius(frame, 6, 0);
}

void theme_apply_solid_rectangle(lv_obj_t *target_rectangle) {
  if (!target_rectangle)
    return;

  lv_obj_set_style_bg_color(target_rectangle, COLOR_PANEL, 0);
  lv_obj_set_style_bg_opa(target_rectangle, LV_OPA_COVER, 0);
  lv_obj_set_style_radius(target_rectangle, 2, 0);
  lv_obj_set_style_border_width(target_rectangle, 0, 0);
  lv_obj_set_style_outline_width(target_rectangle, 0, 0);
  lv_obj_set_style_pad_all(target_rectangle, 0, 0);
  lv_obj_set_style_shadow_width(target_rectangle, 0, 0);
}

void theme_apply_label(lv_obj_t *label, bool is_secondary) {
  if (!label)
    return;

  lv_obj_set_style_text_color(label, is_secondary ? COLOR_GRAY : COLOR_WHITE,
                              0);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(label, 0, 0);
}

void theme_apply_button_label(lv_obj_t *label, bool is_secondary) {
  if (!label)
    return;

  lv_obj_set_style_text_color(label, is_secondary ? COLOR_GRAY : COLOR_WHITE,
                              0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(label, 0, 0);
}

void theme_apply_touch_button(lv_obj_t *btn, bool is_primary) {
  if (!btn)
    return;

  // Shared geometry/text. Default fill: primary = no fill with a thin orange
  // outline, secondary = solid surface (no border). Both fill orange on press.
  lv_obj_set_style_text_color(btn, COLOR_WHITE, LV_STATE_DEFAULT);
  lv_obj_set_style_radius(btn, 12, LV_STATE_DEFAULT);
  lv_obj_set_style_pad_all(btn, 15, LV_STATE_DEFAULT);
  lv_obj_set_style_shadow_width(btn, 0, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_color(btn, is_primary ? COLOR_BG : COLOR_SURFACE,
                            LV_STATE_DEFAULT);
  lv_obj_set_style_border_color(btn, COLOR_ORANGE, LV_STATE_DEFAULT);
  lv_obj_set_style_border_width(btn, is_primary ? 2 : 0, LV_STATE_DEFAULT);

  // Pressed - both tiers fill orange for unambiguous feedback.
  lv_obj_set_style_bg_color(btn, COLOR_ORANGE, LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, LV_STATE_PRESSED);

  // Disabled - fade out fill and border.
  lv_obj_set_style_text_color(btn, COLOR_SURFACE, LV_STATE_DISABLED);
  lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, LV_STATE_DISABLED);
  lv_obj_set_style_border_width(btn, 0, LV_STATE_DISABLED);

  lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICK_FOCUSABLE);
}

void theme_apply_btnmatrix(lv_obj_t *btnmatrix) {
  if (!btnmatrix)
    return;

  // Container style - transparent background, no border/shadow
  lv_obj_set_style_bg_opa(btnmatrix, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(btnmatrix, 0, 0);
  lv_obj_set_style_shadow_width(btnmatrix, 0, 0);

  // Inter-key gap scales with screen so it stays proportional to key size
  lv_obj_set_style_pad_all(btnmatrix, 4, 0);
  lv_obj_set_style_pad_row(btnmatrix, theme_key_gap(), 0);
  lv_obj_set_style_pad_column(btnmatrix, theme_key_gap(), 0);

  // Button items - normal state
  lv_obj_set_style_bg_color(btnmatrix, COLOR_SURFACE, LV_PART_ITEMS);
  lv_obj_set_style_text_color(btnmatrix, COLOR_WHITE, LV_PART_ITEMS);
  lv_obj_set_style_text_font(btnmatrix, theme_font_small(), LV_PART_ITEMS);
  lv_obj_set_style_radius(btnmatrix, theme_key_gap(), LV_PART_ITEMS);
  lv_obj_set_style_border_width(btnmatrix, 0, LV_PART_ITEMS);
  lv_obj_set_style_shadow_width(btnmatrix, 0, LV_PART_ITEMS);
  lv_obj_set_style_outline_width(btnmatrix, 0, LV_PART_ITEMS);

  // Pressed state
  lv_obj_set_style_bg_color(btnmatrix, COLOR_ORANGE,
                            LV_PART_ITEMS | LV_STATE_PRESSED);
  lv_obj_set_style_bg_color(btnmatrix, COLOR_ORANGE,
                            LV_PART_ITEMS | LV_STATE_CHECKED);

  // Disabled state
  lv_obj_set_style_bg_opa(btnmatrix, LV_OPA_TRANSP,
                          LV_PART_ITEMS | LV_STATE_DISABLED);
  lv_obj_set_style_text_color(btnmatrix, COLOR_SURFACE,
                              LV_PART_ITEMS | LV_STATE_DISABLED);

  // Enable click trigger for all buttons
  lv_btnmatrix_set_btn_ctrl_all(btnmatrix, LV_BTNMATRIX_CTRL_CLICK_TRIG);
}

lv_obj_t *theme_create_button(lv_obj_t *parent, const char *text,
                              bool is_primary) {
  if (!parent)
    return NULL;

  lv_obj_t *btn = lv_btn_create(parent);
  theme_apply_touch_button(btn, is_primary);

  if (text) {
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    theme_apply_button_label(label, false);
  }

  return btn;
}

lv_obj_t *theme_create_label(lv_obj_t *parent, const char *text,
                             bool is_secondary) {
  if (!parent)
    return NULL;

  lv_obj_t *label = lv_label_create(parent);
  if (text) {
    lv_label_set_text(label, text);
  }
  theme_apply_label(label, is_secondary);

  return label;
}

lv_obj_t *theme_create_page_title(lv_obj_t *parent, const char *text) {
  // Secondary (grey) so titles read as quiet section headers and don't compete
  // with the white button text below them. Matches the ui_menu title colour.
  lv_obj_t *label = theme_create_label(parent, text ? text : "", true);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  // Constrained to the space between the corner buttons and wrapped, so long
  // titles can't overlap the back button on narrow displays.
  int32_t reserved = 2 * theme_small_padding() + theme_corner_button_width();
  lv_obj_set_width(label, LV_HOR_RES - 2 * reserved);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
  // Centered within the corner-button band, matching the ui_menu nav bar, so
  // page and menu titles align with the back/power button beside them. The
  // band is measured from the parent's border so padded containers place the
  // title at the same screen position as standard zero-padding pages.
  lv_obj_update_layout(label);
  int32_t band_y = theme_small_padding() - lv_obj_get_style_pad_top(parent, 0);
  int32_t y =
      band_y + (theme_corner_button_height() - lv_obj_get_height(label)) / 2;
  if (y < band_y)
    y = band_y;
  lv_obj_align(label, LV_ALIGN_TOP_MID, 0, y);
  return label;
}

void theme_apply_transparent_container(lv_obj_t *obj) {
  if (!obj)
    return;

  lv_obj_set_style_bg_opa(obj, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(obj, 0, 0);
  lv_obj_set_style_pad_all(obj, 0, 0);
}

lv_obj_t *theme_create_scroll_column(lv_obj_t *parent, int32_t pad,
                                     int32_t gap) {
  if (!parent)
    return NULL;

  lv_obj_t *cont = lv_obj_create(parent);
  lv_obj_set_size(cont, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(cont, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(cont, pad, 0);
  lv_obj_set_style_pad_gap(cont, gap, 0);
  theme_apply_screen(cont);
  lv_obj_add_flag(cont, LV_OBJ_FLAG_SCROLLABLE);
  return cont;
}

lv_obj_t *theme_create_separator(lv_obj_t *parent, lv_color_t color) {
  if (!parent)
    return NULL;

  lv_obj_t *separator = lv_obj_create(parent);
  lv_obj_set_size(separator, LV_PCT(100), 2);
  lv_obj_set_style_bg_color(separator, color, 0);
  lv_obj_set_style_bg_opa(separator, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(separator, 0, 0);
  lv_obj_clear_flag(separator, LV_OBJ_FLAG_SCROLLABLE);
  return separator;
}

lv_obj_t *theme_create_button_row(lv_obj_t *parent, int32_t gap) {
  if (!parent)
    return NULL;

  lv_obj_t *row = lv_obj_create(parent);
  lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_set_style_pad_gap(row, gap, 0);
  lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(row, 0, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  return row;
}

lv_obj_t *theme_create_flex_row(lv_obj_t *parent) {
  if (!parent)
    return NULL;

  lv_obj_t *cont = lv_obj_create(parent);
  lv_obj_set_size(cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  theme_apply_transparent_container(cont);
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(cont, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(cont, LV_OBJ_FLAG_SCROLLABLE);
  return cont;
}

lv_obj_t *theme_create_flex_column(lv_obj_t *parent) {
  if (!parent)
    return NULL;

  lv_obj_t *cont = lv_obj_create(parent);
  lv_obj_set_size(cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  theme_apply_transparent_container(cont);
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(cont, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(cont, LV_OBJ_FLAG_SCROLLABLE);
  return cont;
}

static void dropdown_open_cb(lv_event_t *e) {
  lv_obj_t *list = lv_dropdown_get_list(lv_event_get_target(e));
  if (list) {
    lv_obj_set_style_bg_color(list, COLOR_SURFACE, 0);
    lv_obj_set_style_text_color(list, COLOR_WHITE, 0);
    lv_obj_set_style_bg_color(list, COLOR_ORANGE,
                              LV_PART_SELECTED | LV_STATE_CHECKED);
    lv_obj_set_style_bg_color(list, COLOR_ORANGE,
                              LV_PART_SELECTED | LV_STATE_PRESSED);
  }
}

lv_obj_t *theme_create_dropdown(lv_obj_t *parent, const char *options) {
  if (!parent)
    return NULL;

  lv_obj_t *dd = lv_dropdown_create(parent);
  if (options)
    lv_dropdown_set_options(dd, options);
  lv_obj_set_style_bg_color(dd, COLOR_SURFACE, 0);
  lv_obj_set_style_text_color(dd, COLOR_WHITE, 0);
  lv_obj_set_style_text_font(dd, theme_font_small(), 0);
  lv_obj_set_style_border_color(dd, COLOR_ORANGE, 0);
  lv_obj_add_event_cb(dd, dropdown_open_cb, LV_EVENT_READY, NULL);
  return dd;
}

lv_obj_t *theme_create_qr_container(lv_obj_t *parent, int32_t size,
                                    int32_t inner_pad) {
  if (!parent)
    return NULL;

  lv_obj_t *cont = lv_obj_create(parent);
  lv_obj_set_size(cont, size, size);
  lv_obj_set_style_bg_color(cont, COLOR_WHITE, 0);
  lv_obj_set_style_bg_opa(cont, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(cont, 0, 0);
  lv_obj_set_style_pad_all(cont, inner_pad, 0);
  lv_obj_set_style_radius(cont, 0, 0);
  lv_obj_clear_flag(cont, LV_OBJ_FLAG_SCROLLABLE);
  return cont;
}
