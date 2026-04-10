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
