// Mnemonic Editor Page - Review and edit mnemonic words before loading

#ifndef MNEMONIC_EDITOR_H
#define MNEMONIC_EDITOR_H

#include <lvgl.h>
#include <stdbool.h>

void mnemonic_editor_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                 void (*success_cb)(void), const char *mnemonic,
                                 bool new_mnemonic);
void mnemonic_editor_page_show(void);
void mnemonic_editor_page_hide(void);
void mnemonic_editor_page_destroy(void);
char *
mnemonic_editor_get_mnemonic(void); // Returns edited mnemonic (caller frees)

#endif // MNEMONIC_EDITOR_H
