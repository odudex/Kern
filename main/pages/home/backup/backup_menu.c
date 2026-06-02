// Backup Menu Page

#include "backup_menu.h"
#include "../../../core/storage.h"
#include "../../../ui/dialog.h"
#include "../../../ui/menu.h"
#include "../../../ui/theme_widgets.h"
#include "../../store_mnemonic.h"
#include "mnemonic_qr.h"
#include "mnemonic_words.h"
#include <lvgl.h>

static ui_menu_t *backup_menu = NULL;
static lv_obj_t *backup_menu_screen = NULL;
static void (*return_callback)(void) = NULL;

/* --- Words / QR Code callbacks --- */

static void return_from_mnemonic_words_cb(void) {
  mnemonic_words_page_destroy();
  backup_menu_page_show();
}

static void return_from_mnemonic_qr_cb(void) {
  mnemonic_qr_page_destroy();
  backup_menu_page_show();
}

static void (*pending_action)(void) = NULL;

static void launch_words(void) {
  mnemonic_words_page_create(lv_screen_active(), return_from_mnemonic_words_cb);
  mnemonic_words_page_show();
}

static void launch_qr(void) {
  mnemonic_qr_page_create(lv_screen_active(), return_from_mnemonic_qr_cb);
  mnemonic_qr_page_show();
}

static void danger_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  backup_menu_page_hide();
  pending_action();
}

static void warn_and_launch(void (*action)(void)) {
  pending_action = action;
  dialog_show_danger_confirm(DIALOG_SENSITIVE_DATA_WARNING, danger_confirm_cb,
                             NULL, DIALOG_STYLE_OVERLAY);
}

static void menu_words_cb(void) { warn_and_launch(launch_words); }

static void menu_qr_cb(void) { warn_and_launch(launch_qr); }

/* --- Save to Flash / SD callbacks --- */

static void return_from_store_cb(void) {
  store_mnemonic_page_destroy();
  backup_menu_page_show();
}

static void menu_save_flash_cb(void) {
  backup_menu_page_hide();
  store_mnemonic_page_create(lv_screen_active(), return_from_store_cb,
                             STORAGE_FLASH);
  store_mnemonic_page_show();
}

static void menu_save_sd_cb(void) {
  backup_menu_page_hide();
  store_mnemonic_page_create(lv_screen_active(), return_from_store_cb,
                             STORAGE_SD);
  store_mnemonic_page_show();
}

/* --- Back --- */

static void back_cb(void) {
  if (return_callback) {
    return_callback();
  }
}

void backup_menu_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;

  backup_menu_screen = theme_create_page_container(parent);

  backup_menu = ui_menu_create(backup_menu_screen, "Back Up", back_cb);
  if (!backup_menu)
    return;

  ui_menu_add_entry(backup_menu, "Words", menu_words_cb);
  ui_menu_add_entry(backup_menu, "QR Code", menu_qr_cb);
  ui_menu_add_entry(backup_menu, "Save to Flash", menu_save_flash_cb);
  ui_menu_add_entry(backup_menu, "Save to SD", menu_save_sd_cb);
}

void backup_menu_page_show(void) {
  if (backup_menu_screen) {
    lv_obj_clear_flag(backup_menu_screen, LV_OBJ_FLAG_HIDDEN);
  }
  if (backup_menu) {
    ui_menu_show(backup_menu);
  }
}

void backup_menu_page_hide(void) {
  if (backup_menu_screen) {
    lv_obj_add_flag(backup_menu_screen, LV_OBJ_FLAG_HIDDEN);
  }
  if (backup_menu) {
    ui_menu_hide(backup_menu);
  }
}

void backup_menu_page_destroy(void) {
  if (backup_menu) {
    ui_menu_destroy(backup_menu);
    backup_menu = NULL;
  }

  if (backup_menu_screen) {
    lv_obj_del(backup_menu_screen);
    backup_menu_screen = NULL;
  }

  return_callback = NULL;
}
