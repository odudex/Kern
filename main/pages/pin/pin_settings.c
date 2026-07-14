// PIN settings page — manage PIN, wipe threshold

#include "pin_settings.h"
#include "../../core/pin.h"
#include "../../ui/dialog.h"
#include "../../ui/dropdown_page.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "pin_page.h"

#include <lvgl.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static ui_menu_t *settings_menu = NULL;
static lv_obj_t *settings_screen = NULL;
static void (*return_callback)(void) = NULL;

// Wipe threshold detail page
static lv_obj_t *threshold_screen = NULL;

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

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
// Wipe threshold
// ---------------------------------------------------------------------------

// Threshold options
static const uint16_t threshold_values[] = {5, 10, 15, 20, 30, 50};
static const char *threshold_options = "5\n10\n15\n20\n30\n50";

static void threshold_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel < sizeof(threshold_values) / sizeof(threshold_values[0])) {
    pin_set_max_failures((uint8_t)threshold_values[sel]);
  }
}

static void threshold_back_cb(lv_event_t *e) {
  (void)e;
  destroy_threshold_page();
  ui_menu_show(settings_menu);
}

static void show_threshold_page(void) {
  ui_menu_hide(settings_menu);
  uint16_t sel = ui_index_of_u16(
      threshold_values, sizeof(threshold_values) / sizeof(threshold_values[0]),
      pin_get_max_failures(), 1 /* 10 */);
  threshold_screen = ui_dropdown_page_create(
      "Wipe Threshold", "Number of wrong PIN attempts before wiping all data",
      threshold_options, sel, threshold_dropdown_cb, threshold_back_cb);
}

static void destroy_threshold_page(void) {
  if (threshold_screen) {
    lv_obj_delete(threshold_screen);
    threshold_screen = NULL;
  }
}

// ---------------------------------------------------------------------------
// Disable PIN
// ---------------------------------------------------------------------------

static void disable_confirm_result(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  pin_remove();
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
  // Statics may dangle if session expiry cleaned the screen while a detail
  // page was open; drop them so destroy doesn't delete freed objects.
  settings_menu = NULL;
  threshold_screen = NULL;
  return_callback = return_cb;
  settings_screen = theme_create_page_container(parent);
  settings_menu =
      ui_menu_create(settings_screen, "PIN Settings", settings_back_cb);
  ui_menu_add_entry(settings_menu, "Change PIN", change_pin_cb);
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
