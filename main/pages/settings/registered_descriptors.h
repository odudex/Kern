#ifndef REGISTERED_DESCRIPTORS_H
#define REGISTERED_DESCRIPTORS_H

#include <lvgl.h>
#include <stddef.h>

typedef enum {
  REGISTERED_DESCRIPTOR_ACTION_EXPORT_QR,
  REGISTERED_DESCRIPTOR_ACTION_SAVE_FLASH,
  REGISTERED_DESCRIPTOR_ACTION_SAVE_SD,
} registered_descriptor_action_t;

typedef void (*registered_descriptor_action_cb_t)(
    size_t index, registered_descriptor_action_t action);

void registered_descriptors_page_create(
    lv_obj_t *parent, void (*return_cb)(void),
    registered_descriptor_action_cb_t action_cb);
void registered_descriptors_page_show(void);
void registered_descriptors_page_hide(void);
void registered_descriptors_page_destroy(void);

#endif // REGISTERED_DESCRIPTORS_H
