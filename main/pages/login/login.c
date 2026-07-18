#include "login.h"

#include <lvgl.h>

#include "../../ui/assets/icons.h"
#include "../../ui/assets/kern_logo_lvgl.h"
#include "../../ui/battery.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/kern_card_style.h"
#include "../../ui/kern_theme.h"
#include "../../ui/power.h"
#include "../../ui/theme_widgets.h"
#include <bsp/pmic.h>
#ifdef DEV_TOOLS_ENABLED
#include "../dev_tools/dev_menu.h"
#endif
#include "../load_mnemonic/load_menu.h"
#include "../new_mnemonic/new_mnemonic_menu.h"
#include "about.h"
#include "login_scan.h"
#include "login_settings.h"

static lv_obj_t *login_screen = NULL;
static lv_obj_t *nav_bar = NULL;
static lv_obj_t *grid = NULL;
static lv_obj_t *card_scan = NULL;
static lv_obj_t *card_load = NULL;
static lv_obj_t *card_new = NULL;
static lv_obj_t *card_settings = NULL;
static lv_obj_t *power_button = NULL;
static lv_obj_t *info_button = NULL;
#ifdef DEV_TOOLS_ENABLED
static lv_obj_t *dev_tools_button = NULL;
#endif

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

static void load_mnemonic_cb(lv_event_t *e) {
  (void)e;
  login_page_hide();
  load_menu_page_create(lv_screen_active(), return_from_load_menu_cb);
  load_menu_page_show();
}

static void scan_cb(lv_event_t *e) {
  (void)e;
  login_page_hide();
  login_scan_start(login_page_show);
}

static void new_mnemonic_cb(lv_event_t *e) {
  (void)e;
  login_page_hide();
  new_mnemonic_menu_page_create(lv_screen_active(),
                                return_from_new_mnemonic_menu_cb);
  new_mnemonic_menu_page_show();
}

static void settings_cb(lv_event_t *e) {
  (void)e;
  login_page_hide();
  login_settings_page_create(lv_screen_active(), return_from_settings_cb);
  login_settings_page_show();
}

#ifdef DEV_TOOLS_ENABLED
static void dev_tools_cb(lv_event_t *e) {
  (void)e;
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
  kern_card_styles_init();

  // Full-screen flex-column wrapper holding the nav band + grid. Corner
  // buttons/logo/battery are separate siblings positioned by lv_obj_align,
  // same pattern ui_menu_create() uses elsewhere in this app: a non-flex
  // page_container as the root, with one flex child for the flowed content
  // and absolutely-aligned children for the chrome around it.
  lv_obj_t *content = lv_obj_create(login_screen);
  lv_obj_remove_style_all(content);
  lv_obj_set_size(content, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(content, theme_default_padding(), 0);
  lv_obj_set_style_pad_top(content, theme_small_padding(), 0);
  lv_obj_set_style_pad_gap(content, theme_default_padding(), 0);
  lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);

  // Top nav band: a row the height of the corner button, so the centered
  // title sits beside (vertically aligned with) the power/info buttons
  // rather than above them.
  nav_bar = lv_obj_create(content);
  lv_obj_set_size(nav_bar, LV_PCT(100), theme_corner_button_height());
  theme_apply_transparent_container(nav_bar);
  lv_obj_set_flex_flow(nav_bar, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(nav_bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(nav_bar, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_pad_hor(
      nav_bar, theme_small_padding() + theme_corner_button_width(), 0);

  // Match the brand wordmark exactly: white uppercase "KERN" in the medium
  // font, with a static Kern logo to its left.
  lv_obj_t *title = lv_label_create(nav_bar);
  lv_label_set_text(title, "KERN");
  lv_obj_set_style_text_font(title, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title, primary_color(), 0);

  int32_t logo_sz = lv_font_get_line_height(theme_font_medium());
  lv_obj_t *logo = kern_logo_create(login_screen, 0, 0, logo_sz);
  lv_obj_update_layout(login_screen);
  lv_obj_align_to(logo, title, LV_ALIGN_OUT_LEFT_MID, -theme_small_padding(),
                  0);

  // Info button (top-right): borderless tertiary per the card redesign.
  info_button = kern_info_button_create(login_screen, about_cb);
  lv_obj_align(info_button, LV_ALIGN_TOP_RIGHT, -theme_small_padding(),
               theme_small_padding());

  // Battery indicator just left of the info button, vertically centered on
  // the title row.
  lv_obj_t *bat = ui_battery_create(login_screen);
  if (bat) {
    lv_obj_update_layout(login_screen);
    lv_obj_align_to(bat, info_button, LV_ALIGN_OUT_LEFT_MID,
                    -theme_small_padding(), 0);
  }

  // Power button at top-left (only useful with PMIC; without it there's
  // no loaded key to unload, so rebooting from login is pointless)
  if (bsp_pmic_can_power_off()) {
    power_button = ui_create_power_button(login_screen, power_button_cb);
  }

  // 2x2 card grid below the nav band.
  grid = lv_obj_create(content);
  lv_obj_remove_style_all(grid);
  lv_obj_set_width(grid, LV_PCT(100));
  lv_obj_set_flex_grow(grid, 1);
  lv_obj_set_style_pad_gap(grid, KERN_GAP_GRID, 0);
  lv_obj_clear_flag(grid, LV_OBJ_FLAG_SCROLLABLE);

  static int32_t grid_cols[] = {LV_GRID_FR(1), LV_GRID_FR(1),
                                LV_GRID_TEMPLATE_LAST};
  static int32_t grid_rows[] = {LV_GRID_FR(1), LV_GRID_FR(1),
                                LV_GRID_TEMPLATE_LAST};
  lv_obj_set_grid_dsc_array(grid, grid_cols, grid_rows);

  // Scan / Load Mnemonic are the primary actions (orange border); New
  // Mnemonic / Settings are utility (grey hairline border). Fixed, not
  // state-dependent -- fill is black for all four either way.
  card_scan = kern_card_create(grid, ICON_QR_CODE, "Scan", true);
  lv_obj_add_event_cb(card_scan, scan_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_set_grid_cell(card_scan, LV_GRID_ALIGN_STRETCH, 0, 1,
                       LV_GRID_ALIGN_STRETCH, 0, 1);

  card_load = kern_card_create(grid, ICON_KEY, "Load Mnemonic", true);
  lv_obj_add_event_cb(card_load, load_mnemonic_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_set_grid_cell(card_load, LV_GRID_ALIGN_STRETCH, 1, 1,
                       LV_GRID_ALIGN_STRETCH, 0, 1);

  card_new = kern_card_create(grid, ICON_DICE, "New Mnemonic", false);
  lv_obj_add_event_cb(card_new, new_mnemonic_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_set_grid_cell(card_new, LV_GRID_ALIGN_STRETCH, 0, 1,
                       LV_GRID_ALIGN_STRETCH, 1, 1);

  card_settings = kern_card_create(grid, LV_SYMBOL_SETTINGS, "Settings", false);
  lv_obj_add_event_cb(card_settings, settings_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_set_grid_cell(card_settings, LV_GRID_ALIGN_STRETCH, 1, 1,
                       LV_GRID_ALIGN_STRETCH, 1, 1);

#ifdef DEV_TOOLS_ENABLED
  // Utility escape hatch, not part of the 2x2 grid the redesign specifies:
  // a plain text link under the cards, same as before.
  dev_tools_button = lv_label_create(login_screen);
  lv_label_set_text(dev_tools_button, "Developer Tools");
  lv_obj_set_style_text_color(dev_tools_button, secondary_color(), 0);
  lv_obj_add_flag(dev_tools_button, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(dev_tools_button, dev_tools_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_align(dev_tools_button, LV_ALIGN_BOTTOM_MID, 0,
               -theme_small_padding());
#endif
}

void login_page_show(void) {
  if (login_screen)
    lv_obj_clear_flag(login_screen, LV_OBJ_FLAG_HIDDEN);
}

void login_page_hide(void) {
  if (login_screen)
    lv_obj_add_flag(login_screen, LV_OBJ_FLAG_HIDDEN);
}

void login_page_destroy(void) {
  if (login_screen) {
    lv_obj_del(login_screen);
    login_screen = NULL;
  }
  nav_bar = NULL;
  grid = NULL;
  card_scan = NULL;
  card_load = NULL;
  card_new = NULL;
  card_settings = NULL;
  power_button = NULL;
  info_button = NULL;
#ifdef DEV_TOOLS_ENABLED
  dev_tools_button = NULL;
#endif
}
