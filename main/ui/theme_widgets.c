#include "theme_widgets.h"
#include "theme_palette.h"

typedef struct {
  bool initialized;
  lv_style_t screen;
  lv_style_t page_container;
  lv_style_t frame;
  lv_style_t solid_rectangle;
  lv_style_t transparent_container;
  lv_style_t touch_primary;
  lv_style_t touch_secondary;
  lv_style_t touch_pressed;
  lv_style_t touch_disabled;
  lv_style_t btnmatrix_main;
  lv_style_t btnmatrix_items;
  lv_style_t btnmatrix_active;
  lv_style_t btnmatrix_disabled;
} theme_widget_styles_t;

static theme_widget_styles_t styles;

static void init_container_styles(void) {
  lv_style_t *style = &styles.screen;
  lv_style_init(style);
  lv_style_set_bg_color(style, COLOR_BG);
  lv_style_set_bg_opa(style, LV_OPA_COVER);
  lv_style_set_text_color(style, COLOR_WHITE);
  lv_style_set_text_font(style, theme_font_small());
  lv_style_set_border_width(style, 0);
  lv_style_set_outline_width(style, 0);

  style = &styles.page_container;
  lv_style_init(style);
  lv_style_set_size(style, LV_PCT(100), LV_PCT(100));
  lv_style_set_bg_color(style, COLOR_BG);
  lv_style_set_bg_opa(style, LV_OPA_COVER);
  lv_style_set_border_width(style, 0);
  lv_style_set_pad_all(style, 0);
  lv_style_set_radius(style, 0);
  lv_style_set_shadow_width(style, 0);

  style = &styles.frame;
  lv_style_init(style);
  lv_style_set_bg_color(style, COLOR_PANEL);
  lv_style_set_bg_opa(style, LV_OPA_90);
  lv_style_set_border_color(style, COLOR_WHITE);
  lv_style_set_border_width(style, 2);
  lv_style_set_radius(style, 6);

  style = &styles.solid_rectangle;
  lv_style_init(style);
  lv_style_set_bg_color(style, COLOR_PANEL);
  lv_style_set_bg_opa(style, LV_OPA_COVER);
  lv_style_set_radius(style, 2);
  lv_style_set_border_width(style, 0);
  lv_style_set_outline_width(style, 0);
  lv_style_set_pad_all(style, 0);
  lv_style_set_shadow_width(style, 0);

  style = &styles.transparent_container;
  lv_style_init(style);
  lv_style_set_bg_opa(style, LV_OPA_TRANSP);
  lv_style_set_border_width(style, 0);
  lv_style_set_pad_all(style, 0);
}

static void init_touch_styles(void) {
  lv_style_t *style = &styles.touch_primary;
  lv_style_init(style);
  lv_style_set_text_color(style, COLOR_WHITE);
  lv_style_set_radius(style, 12);
  lv_style_set_pad_all(style, 15);
  lv_style_set_shadow_width(style, 0);
  lv_style_set_bg_opa(style, LV_OPA_COVER);
  lv_style_set_bg_color(style, COLOR_BG);
  lv_style_set_border_color(style, COLOR_ORANGE);
  lv_style_set_border_width(style, 2);

  lv_style_init(&styles.touch_secondary);
  lv_style_copy(&styles.touch_secondary, style);
  lv_style_set_bg_color(&styles.touch_secondary, COLOR_SURFACE);
  lv_style_set_border_width(&styles.touch_secondary, 0);

  style = &styles.touch_pressed;
  lv_style_init(style);
  lv_style_set_bg_color(style, COLOR_ORANGE);
  lv_style_set_bg_opa(style, LV_OPA_COVER);

  style = &styles.touch_disabled;
  lv_style_init(style);
  lv_style_set_text_color(style, COLOR_SURFACE);
  lv_style_set_bg_opa(style, LV_OPA_TRANSP);
  lv_style_set_border_width(style, 0);
}

static void init_btnmatrix_styles(void) {
  lv_style_t *style = &styles.btnmatrix_main;
  lv_style_init(style);
  lv_style_set_bg_opa(style, LV_OPA_TRANSP);
  lv_style_set_border_width(style, 0);
  lv_style_set_shadow_width(style, 0);
  lv_style_set_pad_all(style, 4);
  lv_style_set_pad_row(style, theme_key_gap());
  lv_style_set_pad_column(style, theme_key_gap());

  style = &styles.btnmatrix_items;
  lv_style_init(style);
  lv_style_set_bg_color(style, COLOR_SURFACE);
  lv_style_set_text_color(style, COLOR_WHITE);
  lv_style_set_text_font(style, theme_font_small());
  lv_style_set_radius(style, theme_key_gap());
  lv_style_set_border_width(style, 0);
  lv_style_set_shadow_width(style, 0);
  lv_style_set_outline_width(style, 0);

  lv_style_init(&styles.btnmatrix_active);
  lv_style_set_bg_color(&styles.btnmatrix_active, COLOR_ORANGE);

  lv_style_init(&styles.btnmatrix_disabled);
  lv_style_set_bg_opa(&styles.btnmatrix_disabled, LV_OPA_TRANSP);
  lv_style_set_text_color(&styles.btnmatrix_disabled, COLOR_SURFACE);
}

static void apply_variant(lv_obj_t *obj, const lv_style_t *primary,
                          const lv_style_t *secondary, bool use_secondary,
                          lv_style_selector_t selector) {
  const lv_style_t *selected = use_secondary ? secondary : primary;
  const lv_style_t *opposite = use_secondary ? primary : secondary;
  lv_obj_remove_style(obj, opposite, selector);
  lv_obj_add_style(obj, selected, selector);
}

void theme_widgets_init(void) {
  if (styles.initialized)
    return;

  init_container_styles();
  init_touch_styles();
  init_btnmatrix_styles();
  styles.initialized = true;
}

void theme_apply_screen(lv_obj_t *obj) {
  if (obj)
    lv_obj_add_style(obj, &styles.screen, 0);
}

lv_obj_t *theme_create_page_container(lv_obj_t *parent) {
  if (!parent)
    return NULL;

  lv_obj_t *container = lv_obj_create(parent);
  lv_obj_add_style(container, &styles.page_container, 0);
  lv_obj_clear_flag(container, LV_OBJ_FLAG_SCROLLABLE);

  return container;
}

void theme_apply_frame(lv_obj_t *frame) {
  if (frame)
    lv_obj_add_style(frame, &styles.frame, 0);
}

void theme_apply_solid_rectangle(lv_obj_t *target_rectangle) {
  if (target_rectangle)
    lv_obj_add_style(target_rectangle, &styles.solid_rectangle, 0);
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

  apply_variant(btn, &styles.touch_primary, &styles.touch_secondary,
                !is_primary, LV_STATE_DEFAULT);
  lv_obj_add_style(btn, &styles.touch_pressed, LV_STATE_PRESSED);
  lv_obj_add_style(btn, &styles.touch_disabled, LV_STATE_DISABLED);

  lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICK_FOCUSABLE);
}

void theme_apply_btnmatrix(lv_obj_t *btnmatrix) {
  if (!btnmatrix)
    return;

  lv_obj_add_style(btnmatrix, &styles.btnmatrix_main, 0);
  lv_obj_add_style(btnmatrix, &styles.btnmatrix_items, LV_PART_ITEMS);
  lv_obj_add_style(btnmatrix, &styles.btnmatrix_active,
                   LV_PART_ITEMS | LV_STATE_PRESSED);
  lv_obj_add_style(btnmatrix, &styles.btnmatrix_active,
                   LV_PART_ITEMS | LV_STATE_CHECKED);
  lv_obj_add_style(btnmatrix, &styles.btnmatrix_disabled,
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
  if (obj)
    lv_obj_add_style(obj, &styles.transparent_container, 0);
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
