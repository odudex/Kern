#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <lvgl.h>

void snapshot_page_create(lv_obj_t *parent, void (*return_cb)(void));
void snapshot_page_show(void);
void snapshot_page_hide(void);
void snapshot_page_destroy(void);

#endif
