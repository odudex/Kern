// SD File Browser — reusable browse-anywhere SD-card file picker

#include "sd_file_browser.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* When a directory holds more entries than the menu can display, one slot is
 * given to a "More..." entry that pages through the listing (wrapping back to
 * the first page). */
#define BROWSER_MAX_DISPLAYED UI_MENU_MAX_ENTRIES
#define BROWSER_PAGE_SIZE (BROWSER_MAX_DISPLAYED - 1)

#define BROWSER_MAX_FILE_SIZE (256 * 1024)

static lv_obj_t *browser_screen = NULL;
static ui_menu_t *browser_menu = NULL;
static lv_obj_t *loading_label = NULL;
static lv_timer_t *init_timer = NULL;
static sd_file_browser_config_t cfg;

static char current_path[512] = SD_CARD_MOUNT_POINT;

/* Directory listing (files + subdirs), ordered directories-first so a menu
 * position maps straight onto it as page_start + index. */
static char **raw_names = NULL;
static bool *raw_is_dir = NULL;
static int raw_count = 0;

static int page_start = 0;
static int shown_count = 0;

/* ---------- Forward declarations ---------- */

static void back_cb(void);
static void entry_selected_cb(void);

/* ---------- Cleanup ---------- */

static void cleanup_listing(void) {
  if (raw_names) {
    sd_card_free_file_list(raw_names, raw_count);
    raw_names = NULL;
  }
  free(raw_is_dir);
  raw_is_dir = NULL;
  raw_count = 0;
  shown_count = 0;
}

/* ---------- Path navigation ---------- */

static bool at_root(void) {
  return strcmp(current_path, SD_CARD_MOUNT_POINT) == 0;
}

static void navigate_into(const char *name) {
  size_t cur = strlen(current_path);
  int n = snprintf(current_path + cur, sizeof(current_path) - cur, "/%s", name);
  if (n < 0 || (size_t)n >= sizeof(current_path) - cur) {
    current_path[cur] = '\0';
    dialog_show_error_timeout("Path too long", NULL, 0);
    return;
  }
  page_start = 0;
  sd_file_browser_refresh();
}

static void navigate_up(void) {
  char *slash = strrchr(current_path, '/');
  if (slash && slash != current_path)
    *slash = '\0';
  page_start = 0;
  sd_file_browser_refresh();
}

static void back_cb(void) {
  if (at_root()) {
    if (cfg.return_cb)
      cfg.return_cb();
    return;
  }
  navigate_up();
}

/* ---------- File selection ---------- */

static void open_file(const char *name) {
  char full[512];
  int n = snprintf(full, sizeof(full), "%s/%s", current_path, name);
  if (n < 0 || (size_t)n >= sizeof(full)) {
    dialog_show_error_timeout("Path too long", NULL, 0);
    return;
  }

  // Anything loadable (PSBT, descriptor, mnemonic, message, address) is far
  // smaller — the cap keeps a mis-tapped photo or log from stalling the UI.
  size_t size = 0;
  if (sd_card_file_size(full, &size) == ESP_OK &&
      size > BROWSER_MAX_FILE_SIZE) {
    dialog_show_error_timeout("File too large", NULL, 0);
    return;
  }

  if (cfg.on_file_selected)
    cfg.on_file_selected(full, current_path, name);
}

static void entry_selected_cb(void) {
  int idx = ui_menu_get_selected(browser_menu);
  if (idx < 0 || idx >= shown_count)
    return;

  int r = page_start + idx;
  if (raw_is_dir[r])
    navigate_into(raw_names[r]);
  else
    open_file(raw_names[r]);
}

/* ---------- Menu building ---------- */

static void build_menu(void);

static void more_cb(void) {
  page_start += shown_count;
  if (page_start >= raw_count)
    page_start = 0;
  if (browser_menu) {
    ui_menu_destroy(browser_menu);
    browser_menu = NULL;
  }
  build_menu();
}

/* Stable-partition the listing so directories come first. */
static void order_dirs_first(void) {
  if (raw_count <= 1)
    return;
  char **names = malloc((size_t)raw_count * sizeof(char *));
  bool *dirs = malloc((size_t)raw_count * sizeof(bool));
  if (!names || !dirs) { // keep raw order when memory is tight
    free(names);
    free(dirs);
    return;
  }
  int n = 0;
  for (int pass = 0; pass < 2; pass++) {
    bool want_dir = (pass == 0);
    for (int r = 0; r < raw_count; r++) {
      if (raw_is_dir[r] == want_dir) {
        names[n] = raw_names[r];
        dirs[n] = raw_is_dir[r];
        n++;
      }
    }
  }
  memcpy(raw_names, names, (size_t)raw_count * sizeof(char *));
  memcpy(raw_is_dir, dirs, (size_t)raw_count * sizeof(bool));
  free(names);
  free(dirs);
}

static void build_menu(void) {
  browser_menu = ui_menu_create(browser_screen,
                                cfg.title ? cfg.title : current_path, back_cb);
  if (!browser_menu)
    return;

  bool paged = raw_count > BROWSER_MAX_DISPLAYED;
  if (page_start >= raw_count)
    page_start = 0;
  shown_count = raw_count - page_start;
  if (paged && shown_count > BROWSER_PAGE_SIZE)
    shown_count = BROWSER_PAGE_SIZE;

  for (int i = 0; i < shown_count; i++) {
    int r = page_start + i;
    ui_menu_add_entry_with_icon(
        browser_menu, raw_is_dir[r] ? LV_SYMBOL_DIRECTORY : LV_SYMBOL_FILE,
        raw_names[r], entry_selected_cb);
  }

  if (raw_count == 0) {
    ui_menu_add_entry(browser_menu, "(empty)", entry_selected_cb);
    ui_menu_set_entry_enabled(browser_menu, 0, false);
  } else if (paged) {
    char more[32];
    int pages = (raw_count + BROWSER_PAGE_SIZE - 1) / BROWSER_PAGE_SIZE;
    snprintf(more, sizeof(more), "More... (%d/%d)",
             page_start / BROWSER_PAGE_SIZE + 1, pages);
    ui_menu_add_entry(browser_menu, more, more_cb);
  }

  ui_menu_show(browser_menu);
}

void sd_file_browser_refresh(void) {
  if (browser_menu) {
    ui_menu_destroy(browser_menu);
    browser_menu = NULL;
  }
  cleanup_listing();

  esp_err_t ret =
      sd_card_list_entries(current_path, &raw_names, &raw_is_dir, &raw_count);
  if (ret != ESP_OK) {
    dialog_show_error_timeout("Cannot read directory", back_cb, 0);
    return;
  }

  order_dirs_first();
  build_menu();
}

/* ---------- Deferred initialization ---------- */

static void deferred_init_cb(lv_timer_t *timer) {
  (void)timer;
  init_timer = NULL;

  if (loading_label) {
    lv_obj_del(loading_label);
    loading_label = NULL;
  }

  /* Remount fresh each time the page opens: the card may have been swapped
   * since a previous visit and there is no card-detect line to notice. */
  if (sd_card_remount() != ESP_OK) {
    dialog_show_error_timeout("No SD card", cfg.return_cb, 0);
    return;
  }

  sd_file_browser_refresh();
}

/* ---------- Public lifecycle ---------- */

void sd_file_browser_create(lv_obj_t *parent,
                            const sd_file_browser_config_t *config) {
  if (!parent || !config)
    return;

  cfg = *config;
  snprintf(current_path, sizeof(current_path), "%s", SD_CARD_MOUNT_POINT);
  page_start = 0;

  browser_screen = theme_create_page_container(parent);

  loading_label = lv_label_create(browser_screen);
  lv_label_set_text(loading_label, "Reading SD card...");
  lv_obj_set_style_text_font(loading_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(loading_label, primary_color(), 0);
  lv_obj_align(loading_label, LV_ALIGN_CENTER, 0, 0);

  init_timer = lv_timer_create(deferred_init_cb, 50, NULL);
  lv_timer_set_repeat_count(init_timer, 1);
}

void sd_file_browser_show(void) {
  if (browser_screen)
    lv_obj_clear_flag(browser_screen, LV_OBJ_FLAG_HIDDEN);
}

void sd_file_browser_hide(void) {
  if (browser_screen)
    lv_obj_add_flag(browser_screen, LV_OBJ_FLAG_HIDDEN);
}

void sd_file_browser_destroy(void) {
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

  cleanup_listing();
  memset(&cfg, 0, sizeof(cfg));
}
