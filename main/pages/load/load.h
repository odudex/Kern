/*
 * Load Page — browse the SD card and load a file
 *
 * Lets the user navigate SD-card directories and pick a file, whose contents
 * are then routed through the same classify-and-route pipeline as a scanned QR
 * (PSBT, signed message, descriptor, address or mnemonic) via
 * scan_load_content().
 */

#ifndef LOAD_H
#define LOAD_H

#include <lvgl.h>

/**
 * Create the load page.
 * @param parent Parent LVGL object
 * @param return_cb Callback invoked when returning to home
 */
void load_page_create(lv_obj_t *parent, void (*return_cb)(void));

void load_page_show(void);
void load_page_hide(void);
void load_page_destroy(void);

#endif // LOAD_H
