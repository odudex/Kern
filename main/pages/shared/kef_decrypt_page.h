/*
 * KEF Decrypt Page
 * Key entry UI for decrypting KEF-encrypted data (e.g. mnemonic backups)
 */

#ifndef KEF_DECRYPT_PAGE_H
#define KEF_DECRYPT_PAGE_H

#include <lvgl.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*kef_decrypt_success_cb_t)(const uint8_t *data, size_t len);

void kef_decrypt_page_create(lv_obj_t *parent, void (*return_cb)(void),
                             kef_decrypt_success_cb_t success_cb,
                             const uint8_t *envelope, size_t envelope_len);
void kef_decrypt_page_show(void);
void kef_decrypt_page_hide(void);
void kef_decrypt_page_destroy(void);

#endif // KEF_DECRYPT_PAGE_H
