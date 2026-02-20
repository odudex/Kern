// Load Menu Page

#include "load_menu.h"
#include "../../core/base43.h"
#include "../../core/kef.h"
#include "../../core/storage.h"
#include "../../qr/scanner.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include "../home/home.h"
#include "../shared/kef_decrypt_page.h"
#include "../shared/key_confirmation.h"
#include "load_storage.h"
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

static void return_from_kef_decrypt_cb(void) {
  kef_decrypt_page_destroy();
  load_menu_page_show();
}

static void success_from_kef_decrypt_cb(const uint8_t *data, size_t len) {
  /* key_confirmation_page_create copies data, so call it before destroy */
  key_confirmation_page_create(
      lv_screen_active(), return_from_key_confirmation_cb,
      success_from_key_confirmation_cb, (const char *)data, len);
  key_confirmation_page_show();
  kef_decrypt_page_destroy();
}

static void return_from_qr_scanner_cb(void) {
  size_t content_len = 0;
  char *scanned_content =
      qr_scanner_get_completed_content_with_len(&content_len);

  qr_scanner_page_destroy();

  if (scanned_content) {
    const uint8_t *envelope = (const uint8_t *)scanned_content;
    size_t envelope_len = content_len;
    uint8_t *decoded = NULL;
    bool is_kef = kef_is_envelope(envelope, envelope_len);

    if (!is_kef) {
      /* Try base43 decode (Krux encodes KEF envelopes as base43 for QR) */
      size_t decoded_len = 0;
      if (base43_decode(scanned_content, content_len, &decoded, &decoded_len) &&
          kef_is_envelope(decoded, decoded_len)) {
        envelope = decoded;
        envelope_len = decoded_len;
        is_kef = true;
      } else {
        free(decoded);
        decoded = NULL;
      }
    }

    if (is_kef) {
      kef_decrypt_page_create(lv_screen_active(), return_from_kef_decrypt_cb,
                              success_from_kef_decrypt_cb, envelope,
                              envelope_len);
      kef_decrypt_page_show();
    } else {
      key_confirmation_page_create(
          lv_screen_active(), return_from_key_confirmation_cb,
          success_from_key_confirmation_cb, scanned_content, content_len);
      key_confirmation_page_show();
    }
    free(decoded);
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

/* --- Load from Flash / SD --- */

static void return_from_storage_cb(void) {
  load_storage_page_destroy();
  load_menu_page_show();
}

static void success_from_storage_cb(void) {
  load_storage_page_destroy();
  load_menu_page_destroy();
  home_page_create(lv_screen_active());
  home_page_show();
}

static void from_flash_cb(void) {
  load_menu_page_hide();
  load_storage_page_create(lv_screen_active(), return_from_storage_cb,
                           success_from_storage_cb, STORAGE_FLASH);
  load_storage_page_show();
}

static void from_sd_cb(void) {
  load_menu_page_hide();
  load_storage_page_create(lv_screen_active(), return_from_storage_cb,
                           success_from_storage_cb, STORAGE_SD);
  load_storage_page_show();
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
  ui_menu_add_entry(load_menu, "From Flash", from_flash_cb);
  ui_menu_add_entry(load_menu, "From SD Card", from_sd_cb);
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
