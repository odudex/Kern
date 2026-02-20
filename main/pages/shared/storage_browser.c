// Storage Browser — shared file listing, selection, delete, and wipe flow

#include "storage_browser.h"
#include "../../core/storage.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include "wipe_flash_dialog.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DISPLAYED_ITEMS 10

static storage_browser_config_t cfg;
static ui_menu_t *browser_menu = NULL;
static lv_obj_t *browser_screen = NULL;
static lv_obj_t *loading_label = NULL;
static lv_timer_t *init_timer = NULL;

/* File listing */
static char **stored_filenames = NULL;
static int allocated_file_count = 0;
static char *display_names[MAX_DISPLAYED_ITEMS] = {0};
static int displayed_count = 0;

/* ---------- Cleanup ---------- */

static void cleanup_file_data(void) {
  if (stored_filenames) {
    storage_free_file_list(stored_filenames, allocated_file_count);
    stored_filenames = NULL;
  }
  allocated_file_count = 0;

  for (int i = 0; i < MAX_DISPLAYED_ITEMS; i++) {
    free(display_names[i]);
    display_names[i] = NULL;
  }
  displayed_count = 0;
}

/* ---------- Forward declarations ---------- */

static void build_menu(void);
static void back_cb(void);

/* ---------- Entry selection ---------- */

static void entry_selected_cb(void) {
  int idx = ui_menu_get_selected(browser_menu);
  if (idx < 0 || idx >= displayed_count)
    return;

  if (cfg.load_selected)
    cfg.load_selected(idx, stored_filenames[idx]);
}

/* ---------- Back ---------- */

static void back_cb(void) {
  if (cfg.return_cb)
    cfg.return_cb();
}

/* ---------- Inline delete ---------- */

static int pending_delete_index = -1;

static void populate_list(char **raw_filenames, int raw_count) {
  stored_filenames = raw_filenames;
  allocated_file_count = raw_count;
  displayed_count =
      raw_count > MAX_DISPLAYED_ITEMS ? MAX_DISPLAYED_ITEMS : raw_count;

  for (int i = 0; i < displayed_count; i++)
    display_names[i] = cfg.get_display_name(cfg.location, stored_filenames[i]);

  build_menu();
}

static void inline_delete_refresh_cb(void *user_data) {
  (void)user_data;

  if (browser_menu) {
    ui_menu_destroy(browser_menu);
    browser_menu = NULL;
  }
  cleanup_file_data();

  char **raw_filenames = NULL;
  int raw_count = 0;
  esp_err_t ret = cfg.list_files(cfg.location, &raw_filenames, &raw_count);

  if (ret != ESP_OK || raw_count == 0) {
    storage_free_file_list(raw_filenames, raw_count);
    const char *loc_name =
        (cfg.location == STORAGE_FLASH) ? "flash" : "SD card";
    char msg[64];
    snprintf(msg, sizeof(msg), "No %ss found on %s", cfg.item_type_name,
             loc_name);
    dialog_show_error(msg, back_cb, 0);
    return;
  }

  populate_list(raw_filenames, raw_count);
}

static void inline_delete_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;

  esp_err_t ret =
      cfg.delete_file(cfg.location, stored_filenames[pending_delete_index]);
  if (ret == ESP_OK) {
    /* Capitalize item type for display */
    char type_cap[16];
    snprintf(type_cap, sizeof(type_cap), "%s", cfg.item_type_name);
    type_cap[0] = (char)(type_cap[0] - 32); /* toupper */

    if (cfg.location == STORAGE_FLASH) {
      char detail[80];
      snprintf(detail, sizeof(detail),
               "%s deleted.\nFor irrecoverable deletion\nuse Wipe Flash.",
               type_cap);
      dialog_show_info("Deleted", detail, inline_delete_refresh_cb, NULL,
                       DIALOG_STYLE_OVERLAY);
    } else {
      char detail[40];
      snprintf(detail, sizeof(detail), "%s deleted", type_cap);
      dialog_show_info("Deleted", detail, inline_delete_refresh_cb, NULL,
                       DIALOG_STYLE_OVERLAY);
    }
  } else {
    dialog_show_error("Failed to delete", NULL, 0);
  }
}

static void delete_action_cb(int idx) {
  if (idx < 0 || idx >= displayed_count)
    return;

  pending_delete_index = idx;
  char msg[80];
  snprintf(msg, sizeof(msg), "Delete \"%s\"?",
           display_names[idx] ? display_names[idx] : stored_filenames[idx]);
  dialog_show_confirm(msg, inline_delete_confirm_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

/* ---------- Wipe flash ---------- */

static void wipe_flash_cb(void) { wipe_flash_dialog_start(back_cb); }

/* ---------- Menu building ---------- */

static void build_menu(void) {
  const char *title =
      (cfg.location == STORAGE_FLASH) ? "Load from Flash" : "Load from SD Card";

  browser_menu = ui_menu_create(browser_screen, title, back_cb);
  if (!browser_menu)
    return;

  for (int i = 0; i < displayed_count; i++) {
    const char *label =
        display_names[i] ? display_names[i] : stored_filenames[i];
    ui_menu_add_entry_with_action(browser_menu, label, entry_selected_cb,
                                  LV_SYMBOL_TRASH, delete_action_cb);
  }

  if (cfg.location == STORAGE_FLASH) {
    ui_menu_add_entry(browser_menu, "Wipe Flash", wipe_flash_cb);
    int wipe_idx = browser_menu->config.entry_count - 1;
    lv_obj_t *wipe_label = lv_obj_get_child(browser_menu->buttons[wipe_idx], 0);
    lv_obj_set_style_text_color(wipe_label, error_color(), 0);
  }

  ui_menu_show(browser_menu);
}

/* ---------- Deferred initialization ---------- */

static void deferred_list_cb(lv_timer_t *timer) {
  (void)timer;
  init_timer = NULL;

  char **raw_filenames = NULL;
  int raw_count = 0;
  esp_err_t ret = cfg.list_files(cfg.location, &raw_filenames, &raw_count);

  if (loading_label) {
    lv_obj_del(loading_label);
    loading_label = NULL;
  }

  if (ret != ESP_OK || raw_count == 0) {
    storage_free_file_list(raw_filenames, raw_count);
    const char *loc_name =
        (cfg.location == STORAGE_FLASH) ? "flash" : "SD card";
    char msg[64];
    snprintf(msg, sizeof(msg), "No %ss found on %s", cfg.item_type_name,
             loc_name);
    dialog_show_error(msg, back_cb, 0);
    return;
  }

  populate_list(raw_filenames, raw_count);
}

/* ---------- Public lifecycle ---------- */

void storage_browser_create(lv_obj_t *parent,
                            const storage_browser_config_t *config) {
  if (!parent || !config)
    return;

  cfg = *config;

  browser_screen = theme_create_page_container(parent);

  loading_label = lv_label_create(browser_screen);
  lv_label_set_text(loading_label, "Preparing storage...");
  lv_obj_set_style_text_font(loading_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(loading_label, main_color(), 0);
  lv_obj_align(loading_label, LV_ALIGN_CENTER, 0, 0);

  init_timer = lv_timer_create(deferred_list_cb, 50, NULL);
  lv_timer_set_repeat_count(init_timer, 1);
}

void storage_browser_show(void) {
  if (browser_screen)
    lv_obj_clear_flag(browser_screen, LV_OBJ_FLAG_HIDDEN);
  if (browser_menu)
    ui_menu_show(browser_menu);
}

void storage_browser_hide(void) {
  if (browser_screen)
    lv_obj_add_flag(browser_screen, LV_OBJ_FLAG_HIDDEN);
  if (browser_menu)
    ui_menu_hide(browser_menu);
}

storage_location_t storage_browser_get_location(void) { return cfg.location; }

void storage_browser_destroy(void) {
  wipe_flash_dialog_cleanup();
  if (init_timer) {
    lv_timer_del(init_timer);
    init_timer = NULL;
  }
  if (browser_menu) {
    ui_menu_destroy(browser_menu);
    browser_menu = NULL;
  }
  if (browser_screen) {
    lv_obj_del(browser_screen);
    browser_screen = NULL;
  }
  loading_label = NULL;

  cleanup_file_data();
  pending_delete_index = -1;
  memset(&cfg, 0, sizeof(cfg));
}
