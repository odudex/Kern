// Security Settings Page - PIN management and session timeout

#include "security_settings.h"
#include "../../core/pin.h"
#include "../../core/settings.h"
#include "../../ui/dropdown_page.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session.h"
#include "../pin/pin_page.h"
#include "../pin/pin_settings.h"
#include <lvgl.h>

// -- Top-level security menu --
static ui_menu_t *security_menu = NULL;
static lv_obj_t *security_screen = NULL;
static void (*return_callback)(void) = NULL;

// -- Session timeout detail page --
static lv_obj_t *timeout_screen = NULL;

static void rebuild_menu(void);
static void destroy_timeout_page(void);

// ── PIN setup/settings ──

static void pin_setup_complete(void) {
  pin_page_destroy();
  rebuild_menu();
  ui_menu_show(security_menu);
}

static void pin_setup_cancel(void) {
  pin_page_destroy();
  ui_menu_show(security_menu);
}

static void setup_pin_cb(void) {
  ui_menu_hide(security_menu);
  pin_page_create(lv_screen_active(), PIN_PAGE_SETUP, pin_setup_complete,
                  pin_setup_cancel);
}

static void pin_settings_return(void) {
  pin_settings_page_destroy();
  rebuild_menu();
  ui_menu_show(security_menu);
}

static void pin_settings_verified(void) {
  pin_page_destroy();
  pin_settings_page_create(lv_screen_active(), pin_settings_return);
  pin_settings_page_show();
}

static void pin_settings_cancel(void) {
  pin_page_destroy();
  ui_menu_show(security_menu);
}

static void pin_settings_cb(void) {
  ui_menu_hide(security_menu);
  pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, pin_settings_verified,
                  pin_settings_cancel);
}

// ── Session timeout detail page ──

// Timeout options: index → seconds (0=off)
static const uint16_t timeout_values[] = {0, 60, 300, 900, 1800};
static const char *timeout_options = "Off\n1 min\n5 min\n15 min\n30 min";

static void timeout_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel < sizeof(timeout_values) / sizeof(timeout_values[0])) {
    settings_set_session_timeout(timeout_values[sel]);
    session_set_timeout(timeout_values[sel]);
  }
}

static void timeout_back_cb(lv_event_t *e) {
  (void)e;
  destroy_timeout_page();
  ui_menu_show(security_menu);
}

static void show_timeout_page(void) {
  ui_menu_hide(security_menu);
  uint16_t sel = ui_index_of_u16(
      timeout_values, sizeof(timeout_values) / sizeof(timeout_values[0]),
      settings_get_session_timeout(), 2 /* 5 min */);
  timeout_screen =
      ui_dropdown_page_create("Session Timeout", NULL, timeout_options, sel,
                              timeout_dropdown_cb, timeout_back_cb);
}

static void destroy_timeout_page(void) {
  if (timeout_screen) {
    lv_obj_delete(timeout_screen);
    timeout_screen = NULL;
  }
}

// ── Menu ──

static void security_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void rebuild_menu(void) {
  if (security_menu) {
    ui_menu_destroy(security_menu);
    security_menu = NULL;
  }
  security_menu = ui_menu_create(security_screen, "Security", security_back_cb);
  if (pin_is_configured()) {
    ui_menu_add_entry(security_menu, "PIN Settings", pin_settings_cb);
  } else {
    ui_menu_add_entry(security_menu, "Set Up PIN", setup_pin_cb);
  }
  ui_menu_add_entry(security_menu, "Session Timeout", show_timeout_page);
}

// ── Public lifecycle ──

void security_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  security_menu = NULL;
  timeout_screen = NULL;
  return_callback = return_cb;
  security_screen = theme_create_page_container(parent);
  rebuild_menu();
}

void security_settings_page_show(void) {
  if (security_menu)
    ui_menu_show(security_menu);
}

void security_settings_page_hide(void) {
  if (security_menu)
    ui_menu_hide(security_menu);
}

void security_settings_page_destroy(void) {
  pin_settings_page_destroy();
  destroy_timeout_page();
  if (security_menu) {
    ui_menu_destroy(security_menu);
    security_menu = NULL;
  }
  if (security_screen) {
    lv_obj_delete(security_screen);
    security_screen = NULL;
  }
  return_callback = NULL;
}
