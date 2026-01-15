#ifndef DEV_MENU_H
#define DEV_MENU_H

#include <lvgl.h>

void dev_menu_page_create(lv_obj_t *parent, void (*return_cb)(void));
void dev_menu_page_show(void);
void dev_menu_page_hide(void);
void dev_menu_page_destroy(void);

#endif
