/*
 * Store Descriptor Page
 *
 * Saves the loaded descriptor to flash or SD card.
 * Encrypted: KEF encrypt flow -> save as .kef
 * Plaintext: ID prompt -> save as .txt
 */

#ifndef STORE_DESCRIPTOR_H
#define STORE_DESCRIPTOR_H

#include "../core/storage.h"
#include <lvgl.h>

struct wally_descriptor;

void store_descriptor_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                  storage_location_t location, bool encrypted);
void store_descriptor_page_create_for_descriptor(
    lv_obj_t *parent, void (*return_cb)(void), storage_location_t location,
    bool encrypted, const struct wally_descriptor *descriptor);
void store_descriptor_page_show(void);
void store_descriptor_page_hide(void);
void store_descriptor_page_destroy(void);

#endif /* STORE_DESCRIPTOR_H */
