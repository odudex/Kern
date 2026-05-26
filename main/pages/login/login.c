#include "login.h"

#include <lvgl.h>

#include "../../ui/battery.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/power.h"
#include "../../ui/theme.h"
#include <bsp/pmic.h>
#ifdef DEV_TOOLS_ENABLED
#include "../dev_tools/dev_menu.h"
#endif
#include "../load_mnemonic/load_menu.h"
#include "../new_mnemonic/new_mnemonic_menu.h"
#include "about.h"
#include "login_settings.h"

static ui_menu_t *login_menu = NULL;
static lv_obj_t *login_screen = NULL;
static lv_obj_t *power_button = NULL;

static void power_button_cb(lv_event_t *e) {
  (void)e;
  // Pass NULL user_data to signal "no key to unload"
  dialog_show_confirm("Power off?", ui_power_off_confirmed_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

static void return_from_settings_cb(void) {
  login_settings_page_destroy();
  login_page_show();
}

static void return_to_login_cb(void) {
  about_page_destroy();
  login_page_show();
}

static void return_from_load_menu_cb(void) { login_page_show(); }

static void return_from_new_mnemonic_menu_cb(void) { login_page_show(); }

#ifdef DEV_TOOLS_ENABLED
static void return_from_dev_menu_cb(void) { login_page_show(); }
#endif

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
  login_page_hide();
  login_settings_page_create(lv_screen_active(), return_from_settings_cb);
  login_settings_page_show();
}

#ifdef DEV_TOOLS_ENABLED
static void dev_tools_cb(void) {
  login_page_hide();
  dev_menu_page_create(lv_screen_active(), return_from_dev_menu_cb);
  dev_menu_page_show();
}
#endif

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
  ui_menu_add_entry(login_menu, "Settings", settings_cb);
#ifdef DEV_TOOLS_ENABLED
  ui_menu_add_entry(login_menu, "Developer Tools", dev_tools_cb);
#endif
  ui_menu_add_entry(login_menu, "About", about_cb);
  ui_menu_show(login_menu);

  // Power button at top-left (only useful with PMIC; without it there's
  // no loaded key to unload, so rebooting from login is pointless)
  if (bsp_pmic_is_available()) {
    power_button = ui_create_power_button(login_screen, power_button_cb);
  }

  // Battery indicator at the right of the title row, vertically centered on it.
  lv_obj_t *bat = ui_battery_create(login_screen);
  if (bat) {
    lv_obj_update_layout(login_screen);
    lv_obj_align_to(bat, ui_menu_get_nav_bar(login_menu), LV_ALIGN_RIGHT_MID, 0,
                    0);
  }
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
  if (power_button) {
    lv_obj_del(power_button);
    power_button = NULL;
  }
  if (login_menu) {
    ui_menu_destroy(login_menu);
    login_menu = NULL;
  }
  if (login_screen) {
    lv_obj_del(login_screen);
    login_screen = NULL;
  }
}
