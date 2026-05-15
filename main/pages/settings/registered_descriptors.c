// Session Descriptors sub-page — list, view, and remove registry entries

#include "registered_descriptors.h"
#include "../../core/descriptor_checksum.h"
#include "../../core/registry.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static lv_obj_t *rd_screen = NULL;
static ui_menu_t *rd_menu = NULL;
static void (*return_callback)(void) = NULL;
static int pending_remove_index = -1;

static void build_rd_menu(void);

static void view_descriptor_cb(void) {
  int idx = ui_menu_get_selected(rd_menu);
  if (idx < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)idx);
  if (!entry)
    return;
  char *desc_str = NULL;
  if (!descriptor_string_from_descriptor(entry->desc, &desc_str))
    return;
  dialog_show_info(entry->label[0] ? entry->label : entry->id, desc_str, NULL,
                   NULL, DIALOG_STYLE_OVERLAY);
  free(desc_str);
}

static void remove_confirmed_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed || pending_remove_index < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)pending_remove_index);
  if (entry)
    registry_remove(entry->id);
  pending_remove_index = -1;
  build_rd_menu();
}

static void remove_action_cb(int index) {
  pending_remove_index = index;
  dialog_show_danger_confirm("Remove this session descriptor?",
                             remove_confirmed_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void rd_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void build_rd_menu(void) {
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  rd_menu = ui_menu_create(rd_screen, "Session Descriptors", rd_back_cb);
  if (!rd_menu)
    return;

  size_t count = registry_count();
  if (count == 0) {
    ui_menu_add_entry(rd_menu, "(no session descriptors)", NULL);
    ui_menu_set_entry_enabled(rd_menu, 0, false);
  } else {
    for (size_t i = 0; i < count; i++) {
      const registry_entry_t *entry = registry_get(i);
      if (!entry)
        continue;
      ui_menu_add_entry_with_action(
          rd_menu, entry->label[0] ? entry->label : entry->id,
          view_descriptor_cb, LV_SYMBOL_TRASH, remove_action_cb);
    }
  }
  ui_menu_show(rd_menu);
}

void registered_descriptors_page_create(lv_obj_t *parent,
                                        void (*return_cb)(void)) {
  if (!parent)
    return;
  return_callback = return_cb;
  rd_screen = theme_create_page_container(parent);
  build_rd_menu();
}

void registered_descriptors_page_show(void) {
  if (rd_screen)
    lv_obj_clear_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (rd_menu)
    ui_menu_show(rd_menu);
}

void registered_descriptors_page_hide(void) {
  if (rd_screen)
    lv_obj_add_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (rd_menu)
    ui_menu_hide(rd_menu);
}

void registered_descriptors_page_destroy(void) {
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  if (rd_screen) {
    lv_obj_del(rd_screen);
    rd_screen = NULL;
  }
  pending_remove_index = -1;
  return_callback = NULL;
}
