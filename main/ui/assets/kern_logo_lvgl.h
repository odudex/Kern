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
 * Create a logo symbol whose rings continuously fade in and out in place,
 * mirroring the screensaver pulse. Useful as a small animated brand mark.
 *
 * @param parent Parent LVGL object
 * @param size Logo diameter in pixels
 * @return Pointer to created logo container
 */
lv_obj_t *kern_logo_create_pulsing(lv_obj_t *parent, lv_coord_t size);

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
 * Create logo with "KERN" text combo
 * This matches the "Minimal variant" from Typography Combinations
 *
 * @param parent Parent LVGL object
 * @param x X coordinate
 * @param y Y coordinate
 * @return Pointer to created container object
 */
lv_obj_t *kern_logo_with_text(lv_obj_t *parent, lv_coord_t x, lv_coord_t y);

/**
 * Create logo with text as a flex-friendly child (no forced alignment)
 *
 * @param parent Parent LVGL object (typically a flex container)
 * @return Pointer to created container object
 */
lv_obj_t *kern_logo_with_text_inline(lv_obj_t *parent);

/**
 * Same as kern_logo_with_text_inline, but with an explicit logo diameter (px)
 * so the caller can scale the symbol+wordmark block to fit a layout budget.
 */
lv_obj_t *kern_logo_with_text_inline_sized(lv_obj_t *parent, lv_coord_t sz);

/**
 * Create animated logo with pulse effect
 * Great for boot/splash screens
 *
 * @param parent Parent LVGL object
 */
void kern_logo_animated(lv_obj_t *parent);

/**
 * Example usage function
 */
void kern_logo_example(void);

#ifdef __cplusplus
}
#endif

#endif /* KERN_LOGO_LVGL_H */
