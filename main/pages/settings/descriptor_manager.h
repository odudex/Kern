#ifndef DESCRIPTOR_MANAGER_H
#define DESCRIPTOR_MANAGER_H

#include <lvgl.h>
#include <stdbool.h>

void descriptor_manager_page_create(lv_obj_t *parent, void (*return_cb)(void));
void descriptor_manager_page_show(void);
void descriptor_manager_page_hide(void);
void descriptor_manager_page_destroy(void);

// Returns true (and resets) if a descriptor was loaded during the last visit.
bool descriptor_manager_was_changed(void);

#endif // DESCRIPTOR_MANAGER_H
