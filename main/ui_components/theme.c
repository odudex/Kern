#include "theme.h"

// Minimalist theme colors
#define COLOR_BG lv_color_hex(0x000000)       // Black background
#define COLOR_PANEL lv_color_hex(0x1a1a1a)    // Dark gray panels
#define COLOR_WHITE lv_color_hex(0xFFFFFF)    // White text/borders
#define COLOR_GRAY lv_color_hex(0x888888)     // Gray info text
#define COLOR_ORANGE lv_color_hex(0xff6600)   // Orange accent
#define COLOR_DISABLED lv_color_hex(0x333333) // Gray disabled
#define COLOR_ERROR lv_color_hex(0xFF0000)    // Red for errors
#define COLOR_NO lv_color_hex(0xFF0000)       // Red for negative
#define COLOR_YES lv_color_hex(0x00FF00)      // Green for positive
#define COLOR_CYAN lv_color_hex(0x00FFFF)     // Cyan accent

// Spacing constants
#define DEFAULT_PADDING 30

void theme_init(void) {}

lv_color_t bg_color(void) { return COLOR_BG; }

lv_color_t main_color(void) { return COLOR_WHITE; }

lv_color_t secondary_color(void) { return COLOR_GRAY; }

lv_color_t highlight_color(void) { return COLOR_ORANGE; }

lv_color_t disabled_color(void) { return COLOR_DISABLED; }

lv_color_t panel_color(void) { return COLOR_PANEL; }

lv_color_t error_color(void) { return COLOR_ERROR; }

lv_color_t yes_color(void) { return COLOR_YES; }

lv_color_t no_color(void) { return COLOR_NO; }

lv_color_t cyan_color(void) { return COLOR_CYAN; }

// Theme fonts
const lv_font_t *theme_font_small(void) { return &lv_font_montserrat_24; }

const lv_font_t *theme_font_medium(void) { return &lv_font_montserrat_36; }

int theme_get_button_width(void) { return 150; }

int theme_get_button_height(void) { return 100; }

int theme_get_button_spacing(void) { return 20; }

int theme_get_default_padding(void) { return DEFAULT_PADDING; }

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

void theme_apply_frame(lv_obj_t *target_frame) {
  if (!target_frame)
    return;

  lv_obj_set_style_bg_color(target_frame, COLOR_PANEL, 0);
  lv_obj_set_style_bg_opa(target_frame, LV_OPA_90, 0);
  lv_obj_set_style_border_color(target_frame, COLOR_WHITE, 0);
  lv_obj_set_style_border_width(target_frame, 2, 0);
  lv_obj_set_style_radius(target_frame, 6, 0);
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

  lv_obj_set_style_text_color(label, COLOR_GRAY, 0);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(label, 0, 0);
}

void theme_apply_button_label(lv_obj_t *label, bool is_secondary) {
  if (!label)
    return;

  lv_obj_set_style_text_color(label, COLOR_WHITE, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_bg_opa(label, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(label, 0, 0);
}

void theme_apply_touch_button(lv_obj_t *btn, bool is_primary) {
  if (!btn)
    return;

  // Default state - minimal transparent background
  lv_obj_set_style_bg_color(btn, COLOR_BG, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_opa(btn, LV_OPA_30, LV_STATE_DEFAULT);
  lv_obj_set_style_text_color(btn, COLOR_WHITE, LV_STATE_DEFAULT);
  lv_obj_set_style_border_width(btn, 0, LV_STATE_DEFAULT);
  lv_obj_set_style_radius(btn, 12, LV_STATE_DEFAULT);
  lv_obj_set_style_pad_all(btn, 15, LV_STATE_DEFAULT);
  lv_obj_set_style_shadow_width(btn, 0, LV_STATE_DEFAULT);

  // Pressed state - orange background
  lv_obj_set_style_bg_color(btn, COLOR_ORANGE, LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(btn, LV_OPA_50, LV_STATE_PRESSED);

  // Disabled state
  lv_obj_set_style_text_color(btn, COLOR_DISABLED, LV_STATE_DISABLED);
  lv_obj_set_style_bg_opa(btn, LV_OPA_10, LV_STATE_DISABLED);

  lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICK_FOCUSABLE);
}

void theme_apply_btnmatrix(lv_obj_t *btnmatrix) {
  if (!btnmatrix)
    return;

  // Container style - transparent background, no border/shadow
  lv_obj_set_style_bg_opa(btnmatrix, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(btnmatrix, 0, 0);
  lv_obj_set_style_shadow_width(btnmatrix, 0, 0);

  // Padding
  lv_obj_set_style_pad_all(btnmatrix, 4, 0);
  lv_obj_set_style_pad_row(btnmatrix, 6, 0);
  lv_obj_set_style_pad_column(btnmatrix, 6, 0);

  // Button items - normal state
  lv_obj_set_style_bg_color(btnmatrix, COLOR_DISABLED, LV_PART_ITEMS);
  lv_obj_set_style_text_color(btnmatrix, COLOR_WHITE, LV_PART_ITEMS);
  lv_obj_set_style_text_font(btnmatrix, theme_font_small(), LV_PART_ITEMS);
  lv_obj_set_style_radius(btnmatrix, 6, LV_PART_ITEMS);
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
  lv_obj_set_style_text_color(btnmatrix, COLOR_DISABLED,
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
    theme_apply_label(label, false);
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
  lv_obj_t *label = theme_create_label(parent, text ? text : "", false);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_align(label, LV_ALIGN_TOP_MID, 0, theme_get_default_padding());
  return label;
}

void theme_apply_transparent_container(lv_obj_t *obj) {
  if (!obj)
    return;

  lv_obj_set_style_bg_opa(obj, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(obj, 0, 0);
  lv_obj_set_style_pad_all(obj, 0, 0);
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

lv_obj_t *theme_create_separator(lv_obj_t *parent) {
  if (!parent)
    return NULL;

  lv_obj_t *separator = lv_obj_create(parent);
  lv_obj_set_size(separator, LV_PCT(90), 1);
  lv_obj_set_style_bg_color(separator, COLOR_WHITE, 0);
  lv_obj_set_style_bg_opa(separator, LV_OPA_50, 0);
  lv_obj_set_style_border_width(separator, 0, 0);
  lv_obj_set_style_radius(separator, 0, 0);

  return separator;
}
