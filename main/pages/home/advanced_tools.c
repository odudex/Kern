#include "advanced_tools.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "bip85.h"
#include <lvgl.h>

static ui_menu_t *advanced_tools_menu = NULL;
static lv_obj_t *advanced_tools_screen = NULL;
static void (*return_callback)(void) = NULL;

static void return_from_bip85_cb(void) {
  bip85_page_destroy();
  advanced_tools_page_show();
}

static void success_from_bip85_cb(void) {
  bip85_page_destroy();
  advanced_tools_page_hide();
  if (return_callback)
    return_callback();
}

static void bip85_cb(void) {
  bip85_page_create(lv_screen_active(), return_from_bip85_cb,
                    success_from_bip85_cb);
  bip85_page_show();
}

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  advanced_tools_page_hide();
  if (callback)
    callback();
}

void advanced_tools_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  advanced_tools_screen = theme_create_page_container(parent);

  advanced_tools_menu =
      ui_menu_create(advanced_tools_screen, "Advanced Tools", back_cb);
  if (!advanced_tools_menu) {
    lv_obj_del(advanced_tools_screen);
    advanced_tools_screen = NULL;
    return_callback = NULL;
    return;
  }

  ui_menu_add_entry(advanced_tools_menu, "Derive BIP85>BIP39", bip85_cb);
  ui_menu_show(advanced_tools_menu);
}

void advanced_tools_page_show(void) {
  if (advanced_tools_screen)
    lv_obj_clear_flag(advanced_tools_screen, LV_OBJ_FLAG_HIDDEN);
  if (advanced_tools_menu)
    ui_menu_show(advanced_tools_menu);
}

void advanced_tools_page_hide(void) {
  if (advanced_tools_screen)
    lv_obj_add_flag(advanced_tools_screen, LV_OBJ_FLAG_HIDDEN);
  if (advanced_tools_menu)
    ui_menu_hide(advanced_tools_menu);
}

void advanced_tools_page_destroy(void) {
  if (advanced_tools_menu) {
    ui_menu_destroy(advanced_tools_menu);
    advanced_tools_menu = NULL;
  }
  if (advanced_tools_screen) {
    lv_obj_del(advanced_tools_screen);
    advanced_tools_screen = NULL;
  }
  return_callback = NULL;
}
