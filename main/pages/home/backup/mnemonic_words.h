/*
 * Mnemonic Words Backup Page
 * Displays BIP39 mnemonic words for backup
 */

#ifndef MNEMONIC_WORDS_H
#define MNEMONIC_WORDS_H

#include <lvgl.h>

/**
 * Create the mnemonic words page
 * @param parent Parent LVGL object
 * @param return_cb Callback to call when returning from this page
 */
void mnemonic_words_page_create(lv_obj_t *parent, void (*return_cb)(void));

/**
 * Show the mnemonic words page
 */
void mnemonic_words_page_show(void);

/**
 * Hide the mnemonic words page
 */
void mnemonic_words_page_hide(void);

/**
 * Destroy the mnemonic words page and free resources
 */
void mnemonic_words_page_destroy(void);

#endif // MNEMONIC_WORDS_H
