#ifndef KEY_CONFIRMATION_H
#define KEY_CONFIRMATION_H

#include <lvgl.h>
#include <stddef.h>

/**
 * @brief Create the key confirmation page
 *
 * Validates and processes mnemonic content from QR codes.
 * Supports multiple formats (auto-detected):
 * - Plaintext: Space-separated BIP39 words
 * - Compact SeedQR: 16/32 bytes binary entropy
 * - SeedQR: 48/96 digit numeric string (4 digits per word index)
 *
 * @param parent Parent LVGL object
 * @param return_cb Callback when user wants to go back
 * @param success_cb Callback when mnemonic is successfully loaded
 * @param content QR content (plaintext, binary, or numeric)
 * @param content_len Length of content (required for binary detection)
 */
void key_confirmation_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                  void (*success_cb)(void), const char *content,
                                  size_t content_len);
void key_confirmation_page_show(void);
void key_confirmation_page_hide(void);
void key_confirmation_page_destroy(void);

#endif // KEY_CONFIRMATION_H
