// Load Menu Page

#include "load_menu.h"
#include "../../../ui_components/theme.h"
#include "../../../ui_components/ui_menu.h"
#include "../../home_pages/home.h"
#include "../../qr_scanner.h"
#include "../key_confirmation.h"
#include "manual_input.h"
#include <lvgl.h>
#include <stdlib.h>

static ui_menu_t *load_menu = NULL;
static lv_obj_t *load_menu_screen = NULL;
static void (*return_callback)(void) = NULL;

static void return_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  load_menu_page_show();
}

static void success_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  load_menu_page_destroy();
  home_page_create(lv_screen_active());
  home_page_show();
}

static void return_from_qr_scanner_cb(void) {
  size_t content_len = 0;
  char *scanned_content =
      qr_scanner_get_completed_content_with_len(&content_len);

  qr_scanner_page_destroy();

  if (scanned_content) {
    key_confirmation_page_create(
        lv_screen_active(), return_from_key_confirmation_cb,
        success_from_key_confirmation_cb, scanned_content, content_len);
    key_confirmation_page_show();
    free(scanned_content);
  } else {
    load_menu_page_show();
  }
}

static void return_from_manual_input_cb(void) {
  manual_input_page_destroy();
  load_menu_page_show();
}

static void success_from_manual_input_cb(void) {
  key_confirmation_page_destroy();
  manual_input_page_destroy();
  load_menu_page_destroy();
  home_page_create(lv_screen_active());
  home_page_show();
}

static void from_qr_code_cb(void) {
  load_menu_page_hide();
  qr_scanner_page_create(lv_screen_active(), return_from_qr_scanner_cb);
  qr_scanner_page_show();
}

static void from_manual_input_cb(void) {
  load_menu_page_hide();
  manual_input_page_create(lv_screen_active(), return_from_manual_input_cb,
                           success_from_manual_input_cb, false);
  manual_input_page_show();
}

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  load_menu_page_hide();
  load_menu_page_destroy();
  if (callback)
    callback();
}

void load_menu_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  load_menu_screen = theme_create_page_container(parent);

  load_menu = ui_menu_create(load_menu_screen, "Load Mnemonic", back_cb);
  if (!load_menu)
    return;

  ui_menu_add_entry(load_menu, "From QR Code", from_qr_code_cb);
  ui_menu_add_entry(load_menu, "From Manual Input", from_manual_input_cb);
  ui_menu_show(load_menu);
}

void load_menu_page_show(void) {
  if (load_menu)
    ui_menu_show(load_menu);
}

void load_menu_page_hide(void) {
  if (load_menu)
    ui_menu_hide(load_menu);
}

void load_menu_page_destroy(void) {
  if (load_menu) {
    ui_menu_destroy(load_menu);
    load_menu = NULL;
  }
  if (load_menu_screen) {
    lv_obj_del(load_menu_screen);
    load_menu_screen = NULL;
  }
  return_callback = NULL;
}
