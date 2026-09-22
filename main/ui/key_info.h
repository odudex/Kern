/**
 * Reusable UI component for displaying the key fingerprint with an icon.
 */

#ifndef KEY_INFO_H
#define KEY_INFO_H

#include "lvgl.h"

/**
 * Create a generic icon + text row.
 * Low-level helper for custom displays.
 *
 * @param parent Parent LVGL object
 * @param icon   Icon symbol (e.g., ICON_FINGERPRINT, ICON_DERIVATION)
 * @param text   Text to display
 * @param color  Text and icon color
 * @return Container object with icon and label
 */
lv_obj_t *ui_icon_text_row_create(lv_obj_t *parent, const char *icon,
                                  const char *text, lv_color_t color);

/**
 * Create a fingerprint display row with icon and hex value.
 * Uses the currently loaded key's fingerprint.
 *
 * @param parent Parent LVGL object
 * @param color  Text and icon color
 * @return Container object with icon and label, or NULL on failure
 */
lv_obj_t *ui_fingerprint_create(lv_obj_t *parent, lv_color_t color);

/**
 * Create the key info header: the fingerprint in highlight_color(), followed
 * by a "testnet" label when the wallet is on testnet.
 *
 * @param parent Parent LVGL object
 * @return Container object, or NULL on failure
 */
lv_obj_t *ui_key_info_create(lv_obj_t *parent);

/**
 * Create the top key-info bar: a band the height of the corner button holding
 * the fingerprint header and battery, vertically centered so it aligns with
 * the back/power/settings corner buttons. Add as the first child of a page and
 * set the page's pad_top to theme_small_padding() so the band lines up.
 *
 * @param parent Parent LVGL object
 * @return The bar container, or NULL on failure
 */
lv_obj_t *ui_key_info_bar_create(lv_obj_t *parent);

#endif
