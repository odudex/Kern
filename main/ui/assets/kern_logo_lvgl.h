/**
 * kern_logo_lvgl.h
 *
 * Kern Logo rendering for LVGL-based embedded displays
 * Minimal "Essential Point" design
 */

#ifndef KERN_LOGO_LVGL_H
#define KERN_LOGO_LVGL_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a Kern logo on a canvas
 *
 * @param parent Parent LVGL object
 * @param x X coordinate
 * @param y Y coordinate
 * @param size Logo size in pixels (recommended: 60-200)
 * @return Pointer to created canvas object
 */
lv_obj_t *kern_logo_create(lv_obj_t *parent, lv_coord_t x, lv_coord_t y,
                           lv_coord_t size);

/**
 * Run one staggered fade-in/out cycle on a logo's three rings. When the cycle
 * ends, done_cb fires (with user_data set on the animation) — loop it for a
 * continuous pulse, or use it to reposition and restart.
 *
 * @param logo Logo container from kern_logo_create
 * @param done_cb Completion callback, or NULL for a single one-shot cycle
 * @param user_data Passed through to done_cb via lv_anim_get_user_data
 */
void kern_logo_fade_cycle(lv_obj_t *logo, lv_anim_completed_cb_t done_cb,
                          void *user_data);

/**
 * Stop a fade cycle started by kern_logo_fade_cycle, removing the opacity
 * animations from the logo's rings. Call before hiding or destroying a logo so
 * a lingering animation can't keep invalidating the screen.
 *
 * @param logo Logo container from kern_logo_create
 */
void kern_logo_stop_fade(lv_obj_t *logo);

/**
 * Create the logo + "KERN" wordmark as a flex-friendly child, with an explicit
 * logo diameter (px) so the caller can scale the symbol+wordmark block to fit a
 * layout budget.
 *
 * @param parent Parent LVGL object (typically a flex container)
 * @param sz Logo diameter in pixels
 */
lv_obj_t *kern_logo_with_text_inline_sized(lv_obj_t *parent, lv_coord_t sz);

/**
 * Create animated logo with pulse effect
 * Great for boot/splash screens
 *
 * @param parent Parent LVGL object
 */
void kern_logo_animated(lv_obj_t *parent);

#ifdef __cplusplus
}
#endif

#endif /* KERN_LOGO_LVGL_H */
