#ifndef FIRMWARE_UPDATE_H
#define FIRMWARE_UPDATE_H

#include <lvgl.h>

void firmware_update_page_create(lv_obj_t *parent, void (*return_cb)(void));
void firmware_update_page_show(void);
void firmware_update_page_hide(void);
void firmware_update_page_destroy(void);

#endif // FIRMWARE_UPDATE_H
