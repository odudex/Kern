#ifndef THEME_H
#define THEME_H

#include <lvgl.h>
#include <stdbool.h>

void theme_init(void);
lv_color_t bg_color(void);
lv_color_t primary_color(void);
lv_color_t secondary_color(void);
lv_color_t highlight_color(void);
lv_color_t disabled_color(void);
lv_color_t panel_color(void);
lv_color_t error_color(void);
// Action-choice colors (encourage = green, discourage = red), independent of
// the button's "Yes"/"No" label.
lv_color_t encourage_color(void);
lv_color_t discourage_color(void);
// State/value colors (good = green, bad = red) for indicators like battery
// level or password strength.
lv_color_t good_color(void);
lv_color_t bad_color(void);
lv_color_t accent_color(void);

// Theme fonts
const lv_font_t *theme_font_small(void);
const lv_font_t *theme_font_medium(void);

// Screen dimensions (cached, never changes at runtime)
int theme_screen_width(void);
int theme_screen_height(void);
// Smaller of width/height — use as the sizing reference for content that must
// fit both directions (logos, QR codes) so landscape displays don't overflow.
int theme_min_dim(void);
// True when the display is wider than tall.
bool theme_is_landscape(void);

// Theme sizing constants, all proportional to min_dim (the shorter screen
// axis) so they stay compact and tappable in either orientation.
int theme_button_width(void);
int theme_button_height(void);
int theme_button_spacing(void);
int theme_default_padding(void);
int theme_min_touch_size(void);
int theme_corner_button_width(void);
int theme_corner_button_height(void);
int theme_small_padding(void);
int theme_logo_size(void);

// Widget builders (theme_create_*/theme_apply_*) live in theme_widgets.h.

#endif // THEME_H
