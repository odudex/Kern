// Login Settings Page - Pre-login configuration (default wallet preferences)

#include "login_settings.h"
#include "../../core/pin.h"
#include "../../core/session.h"
#include "../../core/settings.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include "../pin/pin_page.h"
#include "../pin/pin_settings.h"
#include <bsp/display.h>
#include <lvgl.h>

// -- Top-level settings menu --
static ui_menu_t *settings_menu = NULL;
static lv_obj_t *settings_screen = NULL;
static void (*return_callback)(void) = NULL;

// -- Default Wallet detail page --
static lv_obj_t *detail_screen = NULL;
static lv_obj_t *network_dropdown = NULL;

// -- Brightness detail page --
static lv_obj_t *brightness_screen = NULL;
static lv_obj_t *brightness_slider = NULL;
static lv_obj_t *brightness_label = NULL;

// Forward declarations
static void show_detail_page(void);
static void destroy_detail_page(void);
static void show_brightness_page(void);
static void destroy_brightness_page(void);

// ── Default Wallet detail page ──

static void network_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  wallet_network_t net =
      (sel == 0) ? WALLET_NETWORK_MAINNET : WALLET_NETWORK_TESTNET;
  settings_set_default_network(net);
}

static void detail_back_cb(lv_event_t *e) {
  (void)e;
  destroy_detail_page();
  ui_menu_show(settings_menu);
}

static void show_detail_page(void) {
  ui_menu_hide(settings_menu);

  detail_screen = theme_create_page_container(lv_screen_active());

  ui_create_back_button(detail_screen, detail_back_cb);
  theme_create_page_title(detail_screen, "Default Wallet");

  int32_t dd_width = LV_HOR_RES * 35 / 100;

  // Network label + dropdown
  lv_obj_t *net_label = theme_create_label(detail_screen, "Network", true);
  lv_obj_align(net_label, LV_ALIGN_CENTER, -(LV_HOR_RES / 4), -30);

  network_dropdown = theme_create_dropdown(detail_screen, "Mainnet\nTestnet");
  wallet_network_t cur_net = settings_get_default_network();
  lv_dropdown_set_selected(network_dropdown,
                           (cur_net == WALLET_NETWORK_MAINNET) ? 0 : 1);
  lv_obj_set_width(network_dropdown, dd_width);
  lv_obj_add_event_cb(network_dropdown, network_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);
  lv_obj_align_to(network_dropdown, net_label, LV_ALIGN_OUT_BOTTOM_MID, 0, 5);
}

static void destroy_detail_page(void) {
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  network_dropdown = NULL;
}

// ── Screen Brightness detail page ──

static void brightness_slider_cb(lv_event_t *e) {
  lv_obj_t *slider = lv_event_get_target(e);
  int32_t val = lv_slider_get_value(slider);
  bsp_display_brightness_set(val);
  lv_label_set_text_fmt(brightness_label, "%d%%", (int)val);
}

static void brightness_back_cb(lv_event_t *e) {
  (void)e;
  int32_t val = lv_slider_get_value(brightness_slider);
  settings_set_brightness((uint8_t)val);
  destroy_brightness_page();
  ui_menu_show(settings_menu);
}

static void show_brightness_page(void) {
  ui_menu_hide(settings_menu);

  brightness_screen = theme_create_page_container(lv_screen_active());

  ui_create_back_button(brightness_screen, brightness_back_cb);
  theme_create_page_title(brightness_screen, "Screen Brightness");

  // Percentage label
  uint8_t cur = settings_get_brightness();
  brightness_label = lv_label_create(brightness_screen);
  lv_label_set_text_fmt(brightness_label, "%d%%", (int)cur);
  lv_obj_set_style_text_font(brightness_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(brightness_label, main_color(), 0);
  lv_obj_align(brightness_label, LV_ALIGN_CENTER, 0, -30);

  // Slider
  brightness_slider = lv_slider_create(brightness_screen);
  lv_slider_set_range(brightness_slider, 1, 100);
  lv_slider_set_value(brightness_slider, cur, LV_ANIM_OFF);
  lv_obj_set_width(brightness_slider, LV_HOR_RES * 60 / 100);
  lv_obj_set_height(brightness_slider, 10);
  lv_obj_align(brightness_slider, LV_ALIGN_CENTER, 0, 20);

  // Style: orange knob and indicator, dark track
  lv_obj_set_style_bg_color(brightness_slider, highlight_color(),
                            LV_PART_INDICATOR);
  lv_obj_set_style_bg_color(brightness_slider, highlight_color(), LV_PART_KNOB);
  lv_obj_set_style_bg_color(brightness_slider, panel_color(), LV_PART_MAIN);
  lv_obj_set_style_pad_all(brightness_slider, 8, LV_PART_KNOB);

  lv_obj_add_event_cb(brightness_slider, brightness_slider_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);
}

static void destroy_brightness_page(void) {
  if (brightness_screen) {
    lv_obj_del(brightness_screen);
    brightness_screen = NULL;
  }
  brightness_slider = NULL;
  brightness_label = NULL;
}

// ── PIN setup/settings ──

static void rebuild_menu(void);

static void pin_setup_complete(void) {
  pin_page_destroy();
  // Start session timeout after PIN setup
  uint16_t timeout = pin_get_session_timeout();
  if (timeout > 0)
    session_start(timeout);
  rebuild_menu();
}

static void pin_setup_cancel(void) {
  pin_page_destroy();
  ui_menu_show(settings_menu);
}

static void setup_pin_cb(void) {
  ui_menu_hide(settings_menu);
  pin_page_create(lv_screen_active(), PIN_PAGE_SETUP, pin_setup_complete,
                  pin_setup_cancel);
}

static void pin_settings_return(void) {
  pin_settings_page_destroy();
  rebuild_menu();
}

static void pin_settings_verified(void) {
  pin_page_destroy();
  pin_settings_page_create(lv_screen_active(), pin_settings_return);
}

static void pin_settings_cancel(void) {
  pin_page_destroy();
  ui_menu_show(settings_menu);
}

static void pin_settings_cb(void) {
  ui_menu_hide(settings_menu);
  pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, pin_settings_verified,
                  pin_settings_cancel);
}

// ── Category menu callbacks ──

static void default_wallet_cb(void) { show_detail_page(); }
static void brightness_cb(void) { show_brightness_page(); }

static void settings_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void rebuild_menu(void) {
  if (settings_menu) {
    ui_menu_destroy(settings_menu);
    settings_menu = NULL;
  }
  settings_menu = ui_menu_create(settings_screen, "Settings", settings_back_cb);
  if (pin_is_configured()) {
    ui_menu_add_entry(settings_menu, "PIN Settings", pin_settings_cb);
  } else {
    ui_menu_add_entry(settings_menu, "Set Up PIN", setup_pin_cb);
  }
  ui_menu_add_entry(settings_menu, "Default Wallet", default_wallet_cb);
  ui_menu_add_entry(settings_menu, "Screen Brightness", brightness_cb);
}

// ── Public lifecycle ──

void login_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  return_callback = return_cb;
  settings_screen = theme_create_page_container(parent);
  rebuild_menu();
}

void login_settings_page_show(void) {
  if (settings_menu)
    ui_menu_show(settings_menu);
}

void login_settings_page_hide(void) {
  if (settings_menu)
    ui_menu_hide(settings_menu);
}

void login_settings_page_destroy(void) {
  pin_settings_page_destroy();
  destroy_detail_page();
  destroy_brightness_page();
  if (settings_menu) {
    ui_menu_destroy(settings_menu);
    settings_menu = NULL;
  }
  if (settings_screen) {
    lv_obj_del(settings_screen);
    settings_screen = NULL;
  }
  return_callback = NULL;
}
