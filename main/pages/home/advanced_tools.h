#ifndef ADVANCED_TOOLS_H
#define ADVANCED_TOOLS_H

#include <lvgl.h>

void advanced_tools_page_create(lv_obj_t *parent, void (*return_cb)(void));
void advanced_tools_page_show(void);
void advanced_tools_page_hide(void);
void advanced_tools_page_destroy(void);

#endif // ADVANCED_TOOLS_H
