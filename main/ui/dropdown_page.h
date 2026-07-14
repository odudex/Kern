// Full-screen dropdown detail page: back button, title, optional description,
// and a dropdown pre-set to the current selection

#ifndef DROPDOWN_PAGE_H
#define DROPDOWN_PAGE_H

#include <lvgl.h>
#include <stddef.h>
#include <stdint.h>

/* The change callback reads the dropdown from the event target. Returns the
 * page container; delete it to destroy the page. */
lv_obj_t *ui_dropdown_page_create(const char *title, const char *description,
                                  const char *options, uint16_t selected,
                                  lv_event_cb_t changed_cb,
                                  lv_event_cb_t back_cb);

/* Index of `value` in `values`, or `fallback` if absent. */
uint16_t ui_index_of_u16(const uint16_t *values, size_t count, uint16_t value,
                         uint16_t fallback);

#endif // DROPDOWN_PAGE_H
