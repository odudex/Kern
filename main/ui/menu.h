// UI Menu Component - Touch menu for LVGL

#ifndef MENU_H
#define MENU_H

#include <lvgl.h>
#include <stdbool.h>

#define UI_MENU_MAX_ENTRIES 10

typedef void (*ui_menu_callback_t)(void);
typedef void (*ui_menu_action_callback_t)(int index);

typedef struct ui_menu_t ui_menu_t;

ui_menu_t *ui_menu_create(lv_obj_t *parent, const char *title,
                          ui_menu_callback_t back_cb);
bool ui_menu_add_entry(ui_menu_t *menu, const char *name,
                       ui_menu_callback_t callback);
bool ui_menu_set_entry_enabled(ui_menu_t *menu, int index, bool enabled);
bool ui_menu_set_entry_label(ui_menu_t *menu, int index, const char *name);
bool ui_menu_set_entry_text_color(ui_menu_t *menu, int index, lv_color_t color);
int ui_menu_get_entry_count(const ui_menu_t *menu);
int ui_menu_get_selected(ui_menu_t *menu);
void ui_menu_set_title_visible(ui_menu_t *menu, bool visible);
lv_obj_t *ui_menu_get_container(ui_menu_t *menu);
/* Top band (height of the corner button) holding the centered title.
 * Pass to a custom header so it aligns with the corner nav button. */
lv_obj_t *ui_menu_get_nav_bar(ui_menu_t *menu);
void ui_menu_show(ui_menu_t *menu);
void ui_menu_hide(ui_menu_t *menu);
bool ui_menu_add_entry_with_action(ui_menu_t *menu, const char *name,
                                   ui_menu_callback_t callback,
                                   const char *action_icon,
                                   ui_menu_action_callback_t action_cb);
void ui_menu_destroy(ui_menu_t *menu);

#endif
