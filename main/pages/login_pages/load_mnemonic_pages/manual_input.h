/*
 * Manual Mnemonic Input Page Header
 * Allows users to enter BIP39 mnemonic words one by one
 */

#ifndef MANUAL_INPUT_H
#define MANUAL_INPUT_H

#include <lvgl.h>
#include <stdbool.h>

/**
 * @brief Create the manual input page
 *
 * @param parent Parent LVGL object where the page will be created
 * @param return_cb Callback function to call when returning to previous page
 * @param success_cb Callback function to call when mnemonic is successfully
 * loaded
 * @param checksum_filter_last_word If true, only show checksum-valid words for
 * the last word position (used when creating new mnemonic from manual input)
 */
void manual_input_page_create(lv_obj_t *parent, void (*return_cb)(void),
                              void (*success_cb)(void),
                              bool checksum_filter_last_word);

/**
 * @brief Show the manual input page
 */
void manual_input_page_show(void);

/**
 * @brief Hide the manual input page
 */
void manual_input_page_hide(void);

/**
 * @brief Destroy the manual input page and free resources
 */
void manual_input_page_destroy(void);

#endif // MANUAL_INPUT_H
