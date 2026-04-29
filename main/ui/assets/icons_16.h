/**
 * Icon font for 16px UI icons
 * Generated with lv_font_conv from FontAwesome
 * Size: 16px, Bpp: 4
 *
 * Generation command:
 * lv_font_conv --bpp 4 --size 16 --no-compress --stride 1 --align 1
 *   --font "Font Awesome 7 Free-Solid-900.otf"
 *   --range 0xE0B4,0xF029,0xF126,0xF577,0xF240,0xF242,0xF243,0xF244,0xF0E7
 *   --format lvgl -o icons_16.c
 */

#ifndef ICONS_16_H
#define ICONS_16_H

#include "lvgl.h"

// Declare the icon font (defined in icons_16.c)
LV_FONT_DECLARE(icons_16);

// Icon symbol definitions (UTF-8 encoded)
#define ICON_DERIVATION "\xEF\x84\xA6"  // FontAwesome U+F126 = code-branch
#define ICON_FINGERPRINT "\xEF\x95\xB7" // FontAwesome U+F577 = fingerprint
#define ICON_BITCOIN "\xEE\x82\xB4"     // FontAwesome U+E0B4 = Bitcoin
#define ICON_QR_CODE "\xEF\x80\xA9"     // FontAwesome U+F029 = QR code

// Battery icon family (FontAwesome 7 Free Solid)
#define ICON_BATTERY_FULL            "\xEF\x89\x80" // FontAwesome U+F240 = battery-full
#define ICON_BATTERY_HALF            "\xEF\x89\x82" // FontAwesome U+F242 = battery-half
#define ICON_BATTERY_QUARTER         "\xEF\x89\x83" // FontAwesome U+F243 = battery-quarter
#define ICON_BATTERY_EMPTY           "\xEF\x89\x84" // FontAwesome U+F244 = battery-empty
#define ICON_BATTERY_CHARGING_BOLT   "\xEF\x83\xA7" // FontAwesome U+F0E7 = bolt

#endif // ICONS_16_H
