#ifndef ADDRESSES_H
#define ADDRESSES_H

#include <lvgl.h>

/**
 * Create the addresses page
 * @param parent Parent LVGL object
 * @param return_cb Callback function to call when returning to home
 */
void addresses_page_create(lv_obj_t *parent, void (*return_cb)(void));

/**
 * Open the next addresses_page_create directly on a single registered
 * descriptor in descriptors-only mode (no singlesig options, no account /
 * settings / scan buttons). Used by the watch-only login flow. One-shot: the
 * setting is consumed and reset by the following create.
 * @param registry_index Registry slot to preselect.
 */
void addresses_page_set_descriptor_only(size_t registry_index);

/**
 * Show the addresses page
 */
void addresses_page_show(void);

/**
 * Hide the addresses page
 */
void addresses_page_hide(void);

/**
 * Destroy the addresses page and free resources
 */
void addresses_page_destroy(void);

#endif // ADDRESSES_H
