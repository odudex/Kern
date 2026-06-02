#ifndef THEME_WIDGETS_H
#define THEME_WIDGETS_H

#include "theme.h"

// Widget factory: builders and stylers that assemble LVGL objects from the
// theme tokens (colours, fonts, sizes) declared in theme.h.

void theme_apply_screen(lv_obj_t *obj);
lv_obj_t *theme_create_page_container(lv_obj_t *parent);
void theme_apply_frame(lv_obj_t *frame);
void theme_apply_solid_rectangle(lv_obj_t *target_rectangle);
void theme_apply_label(lv_obj_t *label, bool is_secondary);
void theme_apply_button_label(lv_obj_t *label, bool is_secondary);
void theme_apply_touch_button(lv_obj_t *btn, bool is_primary);
void theme_apply_btnmatrix(lv_obj_t *btnmatrix);
lv_obj_t *theme_create_button(lv_obj_t *parent, const char *text,
                              bool is_primary);
lv_obj_t *theme_create_label(lv_obj_t *parent, const char *text,
                             bool is_secondary);
lv_obj_t *theme_create_page_title(lv_obj_t *parent, const char *text);
void theme_apply_transparent_container(lv_obj_t *obj);
lv_obj_t *theme_create_scroll_column(lv_obj_t *parent, int32_t pad,
                                     int32_t gap);
lv_obj_t *theme_create_separator(lv_obj_t *parent, lv_color_t color);
lv_obj_t *theme_create_button_row(lv_obj_t *parent, int32_t gap);
lv_obj_t *theme_create_flex_row(lv_obj_t *parent);
lv_obj_t *theme_create_flex_column(lv_obj_t *parent);
lv_obj_t *theme_create_dropdown(lv_obj_t *parent, const char *options);
// Square white-background container for hosting an lv_qrcode. `inner_pad` is
// the QR's white quiet zone (in pixels).
lv_obj_t *theme_create_qr_container(lv_obj_t *parent, int32_t size,
                                    int32_t inner_pad);

#endif // THEME_WIDGETS_H
