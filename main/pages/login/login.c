#include "login.h"

#include <lvgl.h>

#include "../../ui/assets/icons.h"
#include "../../ui/assets/kern_logo_lvgl.h"
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
static lv_obj_t *about_button = NULL;

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

static void about_cb(lv_event_t *e) {
  (void)e;
  login_page_hide();
  about_page_create(lv_screen_active(), return_to_login_cb);
  about_page_show();
}

void login_page_create(lv_obj_t *parent) {
  login_screen = theme_create_page_container(parent);

  // Match the brand wordmark exactly: white uppercase "KERN" in the medium
  // font, with a static Kern logo to its left.
  login_menu = ui_menu_create(login_screen, "KERN", NULL);
  lv_obj_t *title = ui_menu_get_title_label(login_menu);
  if (title) {
    lv_obj_set_style_text_font(title, theme_font_medium(), 0);
    lv_obj_set_style_text_color(title, main_color(), 0);
  }
  ui_menu_add_entry_with_icon(login_menu, ICON_KEY, "Load Mnemonic",
                              load_mnemonic_cb);
  ui_menu_add_entry_with_icon(login_menu, ICON_DICE, "New Mnemonic",
                              new_mnemonic_cb);
  ui_menu_add_entry_with_icon(login_menu, LV_SYMBOL_SETTINGS, "Settings",
                              settings_cb);
#ifdef DEV_TOOLS_ENABLED
  ui_menu_add_entry(login_menu, "Developer Tools", dev_tools_cb);
#endif

  // Visual hierarchy: Load / New Mnemonic are the primary actions (orange
  // outline); everything below is utility, rendered with the secondary style so
  // it recedes against the background.
  for (int i = 2; i < ui_menu_get_entry_count(login_menu); i++)
    ui_menu_set_entry_secondary(login_menu, i, true);
  ui_menu_show(login_menu);

  // Power button at top-left (only useful with PMIC; without it there's
  // no loaded key to unload, so rebooting from login is pointless)
  if (bsp_pmic_is_available()) {
    power_button = ui_create_power_button(login_screen, power_button_cb);
  }

  // About moved out of the menu into a top-right info button (rarely used, so
  // it doesn't deserve a full-width tile).
  about_button = ui_create_info_button(login_screen, about_cb);

  // Static Kern logo to the left of the title, sized to the title cap height.
  if (title) {
    int32_t logo_sz = lv_font_get_line_height(theme_font_medium());
    lv_obj_t *logo = kern_logo_create(login_screen, 0, 0, logo_sz);
    lv_obj_update_layout(login_screen);
    lv_obj_align_to(logo, title, LV_ALIGN_OUT_LEFT_MID,
                    -theme_get_small_padding(), 0);
  }

  // Battery indicator just left of the info button, vertically centered on the
  // title row.
  lv_obj_t *bat = ui_battery_create(login_screen);
  if (bat) {
    lv_obj_update_layout(login_screen);
    lv_obj_align_to(bat, about_button, LV_ALIGN_OUT_LEFT_MID,
                    -theme_get_small_padding(), 0);
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
  if (about_button) {
    lv_obj_del(about_button);
    about_button = NULL;
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
