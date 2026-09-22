/*
 * Store Descriptor Page
 *
 * Saves a descriptor to flash or SD card.
 * KEF: password prompt -> save as .kef
 * BIP138: name prompt -> encrypt to the descriptor's keys -> .bip138(.txt)
 * Plaintext: name prompt -> save as .txt
 */

#ifndef STORE_DESCRIPTOR_H
#define STORE_DESCRIPTOR_H

#include "../core/storage.h"
#include <lvgl.h>

struct wally_descriptor;

void store_descriptor_page_create_for_descriptor(
    lv_obj_t *parent, void (*return_cb)(void), storage_location_t location,
    storage_descriptor_format_t format,
    const struct wally_descriptor *descriptor);
void store_descriptor_page_show(void);
void store_descriptor_page_hide(void);
void store_descriptor_page_destroy(void);

#endif /* STORE_DESCRIPTOR_H */
