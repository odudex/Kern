// PIN entry page — split-PIN unlock, setup, and change flows

#ifndef PIN_PAGE_H
#define PIN_PAGE_H

#include <lvgl.h>

typedef enum {
  PIN_PAGE_UNLOCK,
  PIN_PAGE_SETUP, // also used to change the PIN (caller verifies first)
} pin_page_mode_t;

typedef void (*pin_page_complete_cb_t)(void);
typedef void (*pin_page_cancel_cb_t)(void);

void pin_page_create(lv_obj_t *parent, pin_page_mode_t mode,
                     pin_page_complete_cb_t complete_cb,
                     pin_page_cancel_cb_t cancel_cb);
void pin_page_show(void);
void pin_page_hide(void);
void pin_page_destroy(void);

#endif // PIN_PAGE_H
