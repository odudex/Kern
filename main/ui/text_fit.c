#include "text_fit.h"
#include "theme_widgets.h"
#include <stdio.h>
#include <string.h>

int32_t ui_text_width_px(const char *text, const lv_font_t *font) {
  lv_point_t size = {0};
  lv_text_get_size(&size, text, font, 0, 0, LV_COORD_MAX, LV_TEXT_FLAG_NONE);
  return size.x;
}

ui_text_fit_t ui_text_fit_middle(const char *text, const lv_font_t *font,
                                 int32_t max_width) {
  ui_text_fit_t fit = {0};
  size_t len = strlen(text);
  int32_t ellipsis_w = ui_text_width_px("...", font);

  snprintf(fit.prefix, sizeof(fit.prefix), "%s", text);
  if (ui_text_width_px(fit.prefix, font) <= max_width)
    return fit;
  if (ellipsis_w > max_width)
    return (ui_text_fit_t){0};

  for (size_t visible = len - 1; visible > 1; visible--) {
    size_t prefix = visible * 55 / 100;
    size_t suffix = visible - prefix;
    snprintf(fit.prefix, sizeof(fit.prefix), "%.*s", (int)prefix, text);
    snprintf(fit.suffix, sizeof(fit.suffix), "%s", text + len - suffix);
    if (ui_text_width_px(fit.prefix, font) + ellipsis_w +
            ui_text_width_px(fit.suffix, font) <=
        max_width)
      return fit;
  }

  return (ui_text_fit_t){0};
}

static lv_obj_t *create_part_label(lv_obj_t *parent, const char *text,
                                   const lv_font_t *font, lv_color_t color,
                                   lv_text_align_t align) {
  lv_obj_t *label = lv_label_create(parent);
  lv_label_set_text(label, text);
  lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
  lv_obj_set_style_text_align(label, align, 0);
  lv_obj_set_style_text_font(label, font, 0);
  lv_obj_set_style_text_color(label, color, 0);
  return label;
}

lv_obj_t *ui_text_fit_row_create(lv_obj_t *parent, const ui_text_fit_t *fit,
                                 const lv_font_t *font, int32_t width,
                                 lv_color_t color) {
  lv_obj_t *row = lv_obj_create(parent);
  lv_obj_set_size(row, width, LV_SIZE_CONTENT);
  theme_apply_transparent_container(row);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

  create_part_label(row, fit->prefix, font, color, LV_TEXT_ALIGN_LEFT);
  if (fit->suffix[0] != '\0') {
    create_part_label(row, "...", font, color, LV_TEXT_ALIGN_CENTER);
    create_part_label(row, fit->suffix, font, color, LV_TEXT_ALIGN_RIGHT);
  }
  return row;
}
