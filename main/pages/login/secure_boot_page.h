#ifndef SECURE_BOOT_PAGE_H
#define SECURE_BOOT_PAGE_H

#include <lvgl.h>

void secure_boot_page_create(lv_obj_t *parent, void (*return_cb)(void));
void secure_boot_page_show(void);
void secure_boot_page_hide(void);
void secure_boot_page_destroy(void);

#endif // SECURE_BOOT_PAGE_H
