/**
 * Width-aware middle-ellipsis cropping for long strings (addresses, xpubs).
 *
 * Cropping by rendered pixel width keeps proportional-font rows visually
 * aligned and lets the text span the full available width instead of a fixed
 * character count.
 */

#ifndef UI_TEXT_FIT_H
#define UI_TEXT_FIT_H

#include "lvgl.h"

#define UI_TEXT_FIT_PART_LEN 128

typedef struct {
  char prefix[UI_TEXT_FIT_PART_LEN];
  char suffix[UI_TEXT_FIT_PART_LEN];
} ui_text_fit_t;

/** Rendered width of text in pixels for the given font. */
int32_t ui_text_width_px(const char *text, const lv_font_t *font);

/**
 * Split text with a middle ellipsis so that prefix + "..." + suffix fits within
 * max_width pixels. If the whole string already fits, prefix holds it and
 * suffix is empty. Returns an all-empty result if even "..." doesn't fit.
 */
ui_text_fit_t ui_text_fit_middle(const char *text, const lv_font_t *font,
                                 int32_t max_width);

/**
 * Create a fixed-width row rendering a fitted string as prefix ... suffix,
 * laid out with SPACE_BETWEEN so the text spans the full width. A single-piece
 * result (empty suffix) renders as one left-aligned label.
 *
 * @return the row container (so callers can tweak padding/grow).
 */
lv_obj_t *ui_text_fit_row_create(lv_obj_t *parent, const ui_text_fit_t *fit,
                                 const lv_font_t *font, int32_t width,
                                 lv_color_t color);

#endif // UI_TEXT_FIT_H
