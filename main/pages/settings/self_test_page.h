#ifndef SELF_TEST_PAGE_H
#define SELF_TEST_PAGE_H

#include <lvgl.h>

void self_test_page_create(lv_obj_t *parent, void (*return_cb)(void));
void self_test_page_show(void);
void self_test_page_hide(void);
void self_test_page_destroy(void);

#endif // SELF_TEST_PAGE_H
