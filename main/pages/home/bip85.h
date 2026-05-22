#ifndef BIP85_PAGE_H
#define BIP85_PAGE_H

#include <lvgl.h>

void bip85_page_create(lv_obj_t *parent, void (*return_cb)(void),
                       void (*success_cb)(void));
void bip85_page_show(void);
void bip85_page_hide(void);
void bip85_page_destroy(void);

#endif // BIP85_PAGE_H
