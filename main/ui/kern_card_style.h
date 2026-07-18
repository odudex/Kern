#ifndef KERN_CARD_STYLE_H
#define KERN_CARD_STYLE_H

#include <lvgl.h>
#include <stdbool.h>

// Menu-card styling for the KERN home (login) screen.
//
// Resting : black fill for every card, always -- no gray fill anywhere.
//           Border color marks rank: orange for prominent cards (Scan,
//           Load Mnemonic), grey hairline for muted ones (New Mnemonic,
//           Settings).
// Hover   : orange border + top-biased outer glow + warm interior wash,
//           regardless of resting rank. Same style is bound to
//           LV_STATE_HOVERED (simulator mouse) and LV_STATE_FOCUS_KEY
//           (encoder/keypad, if ever wired up on device -- this codebase has
//           no encoder indev today, so that binding is currently
//           unreachable in practice but costs nothing to keep).
// Pressed : same idea as hover but tighter/brighter -- this is what real
//           touch hardware actually shows, since touch never reports hover.

// Called once, after lv_init() / theme_init().
void kern_card_styles_init(void);

// `prominent` sets the resting border color (orange vs grey hairline); it's
// fixed at creation time, not state-dependent.
lv_obj_t *kern_card_create(lv_obj_t *parent, const char *icon_symbol,
                           const char *label_text, bool prominent);

// Borderless tertiary info button (top-right): no fill/border at rest, a
// faint orange tint on hover/press. Distinct from ui_create_info_button()
// (input_helpers.c), which still serves every other screen's corner
// buttons -- this one is home-card-specific per the redesign scope.
lv_obj_t *kern_info_button_create(lv_obj_t *parent, lv_event_cb_t click_cb);

#endif // KERN_CARD_STYLE_H
