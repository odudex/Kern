#ifndef WORD_NUMBERS_INPUT_H
#define WORD_NUMBERS_INPUT_H

#include <lvgl.h>

void word_numbers_input_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                    void (*success_cb)(void));
void word_numbers_input_page_show(void);
void word_numbers_input_page_hide(void);
void word_numbers_input_page_destroy(void);

#endif // WORD_NUMBERS_INPUT_H
