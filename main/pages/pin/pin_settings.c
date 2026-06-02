// PIN settings page — manage PIN, timeout, wipe threshold

#include "pin_settings.h"
#include "../../core/pin.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session.h"
#include "pin_page.h"

#include <lvgl.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static ui_menu_t *settings_menu = NULL;
static lv_obj_t *settings_screen = NULL;
static void (*return_callback)(void) = NULL;

// Timeout detail page
static lv_obj_t *timeout_screen = NULL;
static lv_obj_t *timeout_dropdown = NULL;

// Wipe threshold detail page
static lv_obj_t *threshold_screen = NULL;
static lv_obj_t *threshold_dropdown = NULL;

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

static void show_timeout_page(void);
static void destroy_timeout_page(void);
static void show_threshold_page(void);
static void destroy_threshold_page(void);

// ---------------------------------------------------------------------------
// Change PIN
// ---------------------------------------------------------------------------

static void change_pin_done(void) {
  pin_page_destroy();
  if (settings_menu)
    ui_menu_show(settings_menu);
}

static void change_pin_cb(void) {
  ui_menu_hide(settings_menu);
  pin_page_create(lv_screen_active(), PIN_PAGE_CHANGE, change_pin_done,
                  change_pin_done);
}

// ---------------------------------------------------------------------------
// Session timeout
// ---------------------------------------------------------------------------

// Timeout options: index → seconds (0=off)
static const uint16_t timeout_values[] = {0, 60, 300, 900, 1800};
static const char *timeout_options = "Off\n1 min\n5 min\n15 min\n30 min";

static void timeout_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel < sizeof(timeout_values) / sizeof(timeout_values[0])) {
    pin_set_session_timeout(timeout_values[sel]);
    // Restart session with new timeout
    session_stop();
    if (timeout_values[sel] > 0)
      session_start(timeout_values[sel]);
  }
}

static void timeout_back_cb(lv_event_t *e) {
  (void)e;
  destroy_timeout_page();
  ui_menu_show(settings_menu);
}

static void show_timeout_page(void) {
  ui_menu_hide(settings_menu);

  timeout_screen = theme_create_page_container(lv_screen_active());
  ui_create_back_button(timeout_screen, timeout_back_cb);
  theme_create_page_title(timeout_screen, "Session Timeout");

  timeout_dropdown = theme_create_dropdown(timeout_screen, timeout_options);
  lv_obj_set_width(timeout_dropdown, LV_HOR_RES * 40 / 100);
  lv_obj_align(timeout_dropdown, LV_ALIGN_CENTER, 0, 0);

  // Select current value
  uint16_t current = pin_get_session_timeout();
  uint16_t sel = 2; // Default: 5 min
  for (int i = 0; i < (int)(sizeof(timeout_values) / sizeof(timeout_values[0]));
       i++) {
    if (timeout_values[i] == current) {
      sel = i;
      break;
    }
  }
  lv_dropdown_set_selected(timeout_dropdown, sel);
  lv_obj_add_event_cb(timeout_dropdown, timeout_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);
}

static void destroy_timeout_page(void) {
  if (timeout_screen) {
    lv_obj_delete(timeout_screen);
    timeout_screen = NULL;
  }
  timeout_dropdown = NULL;
}

// ---------------------------------------------------------------------------
// Wipe threshold
// ---------------------------------------------------------------------------

// Threshold options
static const uint8_t threshold_values[] = {5, 10, 15, 20, 30, 50};
static const char *threshold_options = "5\n10\n15\n20\n30\n50";

static void threshold_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel < sizeof(threshold_values) / sizeof(threshold_values[0])) {
    pin_set_max_failures(threshold_values[sel]);
  }
}

static void threshold_back_cb(lv_event_t *e) {
  (void)e;
  destroy_threshold_page();
  ui_menu_show(settings_menu);
}

static void show_threshold_page(void) {
  ui_menu_hide(settings_menu);

  threshold_screen = theme_create_page_container(lv_screen_active());
  ui_create_back_button(threshold_screen, threshold_back_cb);
  theme_create_page_title(threshold_screen, "Wipe Threshold");

  lv_obj_t *desc = lv_label_create(threshold_screen);
  lv_label_set_text(desc, "Number of wrong PIN attempts before wiping "
                          "all data");
  lv_obj_set_style_text_color(desc, secondary_color(), 0);
  lv_obj_set_style_text_align(desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(desc, LV_PCT(80));
  lv_obj_align(desc, LV_ALIGN_CENTER, 0, -40);

  threshold_dropdown =
      theme_create_dropdown(threshold_screen, threshold_options);
  lv_obj_set_width(threshold_dropdown, LV_HOR_RES * 30 / 100);
  lv_obj_align(threshold_dropdown, LV_ALIGN_CENTER, 0, 20);

  // Select current value
  uint8_t current = pin_get_max_failures();
  uint16_t sel = 1; // Default: 10
  for (int i = 0;
       i < (int)(sizeof(threshold_values) / sizeof(threshold_values[0])); i++) {
    if (threshold_values[i] == current) {
      sel = i;
      break;
    }
  }
  lv_dropdown_set_selected(threshold_dropdown, sel);
  lv_obj_add_event_cb(threshold_dropdown, threshold_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);
}

static void destroy_threshold_page(void) {
  if (threshold_screen) {
    lv_obj_delete(threshold_screen);
    threshold_screen = NULL;
  }
  threshold_dropdown = NULL;
}

// ---------------------------------------------------------------------------
// Disable PIN
// ---------------------------------------------------------------------------

static void disable_confirm_result(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  pin_remove();
  session_stop();
  if (return_callback)
    return_callback();
}

static void disable_pin_cb(void) {
  dialog_show_danger_confirm("Disable PIN protection?\n\n"
                             "All PIN data will be removed.",
                             disable_confirm_result, NULL,
                             DIALOG_STYLE_OVERLAY);
}

// ---------------------------------------------------------------------------
// Menu callbacks
// ---------------------------------------------------------------------------

static void settings_back_cb(void) {
  if (return_callback)
    return_callback();
}

// ---------------------------------------------------------------------------
// Public lifecycle
// ---------------------------------------------------------------------------

void pin_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  return_callback = return_cb;
  settings_screen = theme_create_page_container(parent);
  settings_menu =
      ui_menu_create(settings_screen, "PIN Settings", settings_back_cb);
  ui_menu_add_entry(settings_menu, "Change PIN", change_pin_cb);
  ui_menu_add_entry(settings_menu, "Session Timeout", show_timeout_page);
  ui_menu_add_entry(settings_menu, "Wipe Threshold", show_threshold_page);
  ui_menu_add_entry(settings_menu, "Disable PIN", disable_pin_cb);
}

void pin_settings_page_show(void) {
  if (settings_menu)
    ui_menu_show(settings_menu);
}

void pin_settings_page_hide(void) {
  if (settings_menu)
    ui_menu_hide(settings_menu);
}

void pin_settings_page_destroy(void) {
  destroy_timeout_page();
  destroy_threshold_page();
  if (settings_menu) {
    ui_menu_destroy(settings_menu);
    settings_menu = NULL;
  }
  if (settings_screen) {
    lv_obj_delete(settings_screen);
    settings_screen = NULL;
  }
  return_callback = NULL;
}
