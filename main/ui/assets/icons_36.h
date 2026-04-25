/**
 * Icon font for 36px UI icons
 * Generated with lv_font_conv from FontAwesome 7 Free-Solid-900
 * Size: 36px, Bpp: 4
 *
 * Generation command:
 *   lv_font_conv --bpp 4 --size 36 --no-compress
 *     --font "Font Awesome 7 Free-Solid-900.otf"
 *     --range 0xF128,0xF577
 *     --format lvgl --lv-font-name icons_36 -o icons_36.c
 */

#ifndef ICONS_36_H
#define ICONS_36_H

#include "lvgl.h"

// Declare the icon font (defined in icons_36.c)
LV_FONT_DECLARE(icons_36);

// Icon symbol definitions (UTF-8 encoded)
#define ICON_QRCODE_36 "\xEF\x80\xA9" // FontAwesome U+F029 = qrcode
#define ICON_HELP_36 "\xEF\x84\xA8"   // FontAwesome U+F128 = question-circle
#define ICON_FINGERPRINT_36 "\xEF\x95\xB7" // FontAwesome U+F577 = fingerprint

#endif // ICONS_36_H
