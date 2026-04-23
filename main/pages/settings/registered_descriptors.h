#ifndef REGISTERED_DESCRIPTORS_H
#define REGISTERED_DESCRIPTORS_H

#include <lvgl.h>

void registered_descriptors_page_create(lv_obj_t *parent,
                                        void (*return_cb)(void));
void registered_descriptors_page_show(void);
void registered_descriptors_page_hide(void);
void registered_descriptors_page_destroy(void);

#endif // REGISTERED_DESCRIPTORS_H
