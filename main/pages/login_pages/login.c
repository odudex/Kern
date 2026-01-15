#include "login.h"

#include <lvgl.h>

#include "../../ui_components/simple_dialog.h"
#include "../../ui_components/theme.h"
#include "../../ui_components/ui_menu.h"
#include "about.h"
#include "developer_tools/dev_menu.h"
#include "load_mnemonic_pages/load_menu.h"
#include "new_mnemonic_pages/new_mnemonic_menu.h"

static ui_menu_t *login_menu = NULL;
static lv_obj_t *login_screen = NULL;

static void return_to_login_cb(void) {
  about_page_destroy();
  login_page_show();
}

static void return_from_load_menu_cb(void) { login_page_show(); }

static void return_from_new_mnemonic_menu_cb(void) { login_page_show(); }

static void return_from_dev_menu_cb(void) { login_page_show(); }

static void load_mnemonic_cb(void) {
  login_page_hide();
  load_menu_page_create(lv_screen_active(), return_from_load_menu_cb);
  load_menu_page_show();
}

static void new_mnemonic_cb(void) {
  login_page_hide();
  new_mnemonic_menu_page_create(lv_screen_active(),
                                return_from_new_mnemonic_menu_cb);
  new_mnemonic_menu_page_show();
}

static void settings_cb(void) {
  show_simple_dialog("Login", "Settings not implemented yet");
}

static void dev_tools_cb(void) {
  login_page_hide();
  dev_menu_page_create(lv_screen_active(), return_from_dev_menu_cb);
  dev_menu_page_show();
}

static void about_cb(void) {
  login_page_hide();
  about_page_create(lv_screen_active(), return_to_login_cb);
  about_page_show();
}

void login_page_create(lv_obj_t *parent) {
  login_screen = theme_create_page_container(parent);

  login_menu = ui_menu_create(login_screen, "Login", NULL);
  ui_menu_add_entry(login_menu, "Load Mnemonic", load_mnemonic_cb);
  ui_menu_add_entry(login_menu, "New Mnemonic", new_mnemonic_cb);
  // ui_menu_add_entry(login_menu, "Settings", settings_cb);
  ui_menu_add_entry(login_menu, "Developer Tools", dev_tools_cb);
  ui_menu_add_entry(login_menu, "About", about_cb);
  ui_menu_show(login_menu);
}

void login_page_show(void) {
  if (login_menu)
    ui_menu_show(login_menu);
}

void login_page_hide(void) {
  if (login_menu)
    ui_menu_hide(login_menu);
}

void login_page_destroy(void) {
  if (login_menu) {
    ui_menu_destroy(login_menu);
    login_menu = NULL;
  }
  if (login_screen) {
    lv_obj_del(login_screen);
    login_screen = NULL;
  }
}
