/**
 * Icon font for 24px UI icons
 * Generated with lv_font_conv from FontAwesome 7 Free-Solid-900
 * Size: 24px, Bpp: 4
 *
 * Generation command:
 *   lv_font_conv --bpp 4 --size 24 --no-compress
 *     --font "Font Awesome 7 Free-Solid-900.otf"
 *     --range 0xE0B4,0xF029,0xF126,0xF128,0xF577
 *     --format lvgl --lv-font-name icons_24 -o icons_24.c
 */

#ifndef ICONS_24_H
#define ICONS_24_H

#include "lvgl.h"

// Declare the icon font (defined in icons_24.c)
LV_FONT_DECLARE(icons_24);

// Icon symbol definitions (UTF-8 encoded)
#define ICON_DERIVATION "\xEF\x84\xA6"  // FontAwesome U+F126 = code-branch
#define ICON_FINGERPRINT "\xEF\x95\xB7" // FontAwesome U+F577 = fingerprint
#define ICON_BITCOIN "\xEE\x82\xB4"     // FontAwesome U+E0B4 = Bitcoin
#define ICON_QR_CODE "\xEF\x80\xA9"     // FontAwesome U+F029 = QR code
#define ICON_HELP "\xEF\x84\xA8"        // FontAwesome U+F128 = question-circle

#endif // ICONS_24_H
