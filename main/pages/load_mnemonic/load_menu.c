// Load Menu Page

#include "load_menu.h"
#include "../../core/kef.h"
#include "../../core/storage.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../home/home.h"
#include "../shared/kef_decrypt_page.h"
#include "../shared/key_confirmation.h"
#include "../shared/mnemonic_editor.h"
#include "load_storage.h"
#include "manual_input.h"
#include "word_numbers_input.h"
#include <lvgl.h>
#include <stdlib.h>

static ui_menu_t *load_menu = NULL;
static lv_obj_t *load_menu_screen = NULL;
static ui_menu_t *manual_method_menu = NULL;
static lv_obj_t *manual_method_screen = NULL;
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
    size_t envelope_len = 0;
    uint8_t *envelope = kef_envelope_from_bytes(
        (const uint8_t *)scanned_content, content_len, &envelope_len);

    if (envelope) {
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
    free(envelope);
    free(scanned_content);
  } else {
    load_menu_page_show();
  }
}

static void show_manual_method_menu(void);

static void return_from_words_input_cb(void) {
  mnemonic_editor_page_destroy();
  manual_input_page_destroy();
  show_manual_method_menu();
}

static void return_from_word_numbers_cb(void) {
  mnemonic_editor_page_destroy();
  word_numbers_input_page_destroy();
  show_manual_method_menu();
}

static void destroy_manual_method_menu(void) {
  if (manual_method_menu) {
    ui_menu_destroy(manual_method_menu);
    manual_method_menu = NULL;
  }
  if (manual_method_screen) {
    lv_obj_del(manual_method_screen);
    manual_method_screen = NULL;
  }
}

static void success_from_manual_input_cb(void) {
  key_confirmation_page_destroy();
  mnemonic_editor_page_destroy();
  manual_input_page_destroy();
  word_numbers_input_page_destroy();
  destroy_manual_method_menu();
  load_menu_page_destroy();
  home_page_create(lv_screen_active());
  home_page_show();
}

static void from_qr_code_cb(void) {
  load_menu_page_hide();
  qr_scanner_page_create(lv_screen_active(), return_from_qr_scanner_cb);
  qr_scanner_page_show();
}

static void start_words_input(int word_count) {
  if (manual_method_menu)
    ui_menu_hide(manual_method_menu);
  manual_input_page_create_with_word_count(
      lv_screen_active(), return_from_words_input_cb,
      success_from_manual_input_cb, false, word_count);
  manual_input_page_show();
}

static void words_12_input_cb(void) { start_words_input(12); }

static void words_24_input_cb(void) { start_words_input(24); }

static void word_numbers_input_cb(void) {
  if (manual_method_menu)
    ui_menu_hide(manual_method_menu);
  word_numbers_input_page_create(lv_screen_active(),
                                 return_from_word_numbers_cb,
                                 success_from_manual_input_cb);
  word_numbers_input_page_show();
}

static void manual_method_back_cb(void) {
  destroy_manual_method_menu();
  load_menu_page_show();
}

static void show_manual_method_menu(void) {
  if (!manual_method_screen) {
    manual_method_screen = theme_create_page_container(lv_screen_active());
    if (!manual_method_screen) {
      load_menu_page_show();
      return;
    }
    manual_method_menu = ui_menu_create(manual_method_screen, "Manual Input",
                                        manual_method_back_cb);
    if (!manual_method_menu) {
      lv_obj_del(manual_method_screen);
      manual_method_screen = NULL;
      load_menu_page_show();
      return;
    }
    ui_menu_add_entry(manual_method_menu, "12 Words", words_12_input_cb);
    ui_menu_add_entry(manual_method_menu, "24 Words", words_24_input_cb);
    ui_menu_add_entry(manual_method_menu, "Input as Numbers",
                      word_numbers_input_cb);
    ui_menu_set_entry_secondary(manual_method_menu, 2, true);
  }
  ui_menu_show(manual_method_menu);
}

static void from_manual_input_cb(void) {
  load_menu_page_hide();
  show_manual_method_menu();
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

  ui_menu_add_entry_with_icon(load_menu, ICON_QR_CODE, "From QR Code",
                              from_qr_code_cb);
  ui_menu_add_entry_with_icon(load_menu, LV_SYMBOL_KEYBOARD,
                              "From Manual Input", from_manual_input_cb);
  ui_menu_add_entry_with_icon(load_menu, LV_SYMBOL_DRIVE, "From Flash",
                              from_flash_cb);
  ui_menu_add_entry_with_icon(load_menu, ICON_SD_CARD, "From SD Card",
                              from_sd_cb);
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
  destroy_manual_method_menu();
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
