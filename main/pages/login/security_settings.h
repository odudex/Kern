// Security Settings Page - PIN management and session timeout

#ifndef SECURITY_SETTINGS_H
#define SECURITY_SETTINGS_H

#include <lvgl.h>

void security_settings_page_create(lv_obj_t *parent, void (*return_cb)(void));
void security_settings_page_show(void);
void security_settings_page_hide(void);
void security_settings_page_destroy(void);

#endif // SECURITY_SETTINGS_H
