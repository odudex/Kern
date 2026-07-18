#ifndef KERN_THEME_H
#define KERN_THEME_H

#include <lvgl.h>

// Design tokens for the home-screen menu card redesign. Orange here is
// reserved for interaction feedback (hover/focus/press) only -- resting
// cards are uniform and quiet. See kern_card_style.h for the styles built
// from these tokens.
#define KERN_COLOR_CANVAS lv_color_hex(0x000000)
// Same as canvas -- no card should read as a filled gray/charcoal rectangle
// against the black screen background. Rank is conveyed by border color
// only (see kern_card_style.h), never by fill.
#define KERN_COLOR_CARD_BG lv_color_hex(0x000000)
#define KERN_COLOR_HAIRLINE lv_color_hex(0x4A4A4A)
#define KERN_COLOR_ORANGE lv_color_hex(0xFF7A00)
#define KERN_COLOR_ORANGE_HOT lv_color_hex(0xFF9A33)
#define KERN_COLOR_WARM_TINT lv_color_hex(0x2A1505)
#define KERN_COLOR_WARM_TINT_PRESS lv_color_hex(0x351A06)

#define KERN_RADIUS_CARD 12
#define KERN_BORDER_W 1
#define KERN_PAD_CARD 16
#define KERN_GAP_GRID 14

#endif // KERN_THEME_H
