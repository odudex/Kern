/*
 * KEF Encrypt Page
 * ID selection + key entry + encryption for KEF data.
 */

#ifndef KEF_ENCRYPT_PAGE_H
#define KEF_ENCRYPT_PAGE_H

#include <lvgl.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Success callback — receives the KEF ID used and a pointer to the
 * encrypted envelope.  Both pointers remain valid until
 * kef_encrypt_page_destroy() is called; copy if needed longer.
 */
typedef void (*kef_encrypt_success_cb_t)(const char *id,
                                         const uint8_t *envelope, size_t len);

/**
 * @param suggested_id  When non-NULL, offered as the default backup ID
 *                      (e.g. a descriptor checksum).  When NULL the wallet
 *                      fingerprint is used instead.
 */
void kef_encrypt_page_create(lv_obj_t *parent, void (*return_cb)(void),
                             kef_encrypt_success_cb_t success_cb,
                             const uint8_t *data, size_t data_len,
                             const char *suggested_id);
void kef_encrypt_page_show(void);
void kef_encrypt_page_hide(void);
void kef_encrypt_page_destroy(void);

#endif /* KEF_ENCRYPT_PAGE_H */
