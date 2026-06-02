#ifndef THEME_PALETTE_H
#define THEME_PALETTE_H

#include <lvgl.h>

// Minimalist theme palette: one macro per distinct value. The semantic
// accessors in theme.h map intent onto these, so several may share a macro
// (e.g. error/discourage/bad all return COLOR_RED). Private to the theme
// implementation (theme.c / theme_widgets.c) — UI code uses the accessor
// functions, never these macros.
#define COLOR_BG lv_color_hex(0x000000)      // Black background
#define COLOR_PANEL lv_color_hex(0x1a1a1a)   // Dark gray panels
#define COLOR_SURFACE lv_color_hex(0x333333) // Neutral control fill / disabled
#define COLOR_WHITE lv_color_hex(0xFFFFFF)   // White text/borders
#define COLOR_GRAY lv_color_hex(0x888888)    // Gray secondary text
#define COLOR_ORANGE lv_color_hex(0xff6600)  // Orange accent
#define COLOR_RED lv_color_hex(0xFF0000)     // Error / discouraged / bad
#define COLOR_GREEN lv_color_hex(0x00FF00)   // Encouraged / good
#define COLOR_CYAN lv_color_hex(0x00FFFF)    // Cyan accent

#endif // THEME_PALETTE_H
