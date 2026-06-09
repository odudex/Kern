// Load Page — SD-card file browser feeding scan_load_content()

#include "load.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../scan/scan.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* When a directory holds more entries than the menu can display, one slot is
 * given to a "More..." entry that pages through the listing (wrapping back to
 * the first page). */
#define LOAD_MAX_DISPLAYED UI_MENU_MAX_ENTRIES
#define LOAD_PAGE_SIZE (LOAD_MAX_DISPLAYED - 1)

#define LOAD_MAX_FILE_SIZE (256 * 1024)

static lv_obj_t *load_screen = NULL;
static ui_menu_t *load_menu = NULL;
static lv_obj_t *loading_label = NULL;
static lv_timer_t *init_timer = NULL;
static void (*load_return_cb)(void) = NULL;

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
static void refresh(void);

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
  refresh();
}

static void navigate_up(void) {
  char *slash = strrchr(current_path, '/');
  if (slash && slash != current_path)
    *slash = '\0';
  page_start = 0;
  refresh();
}

static void back_cb(void) {
  if (at_root()) {
    if (load_return_cb)
      load_return_cb();
    return;
  }
  navigate_up();
}

/* ---------- File loading ---------- */

// Invoked when the loaded-content flow finishes, errors out, or is backed out
// of — return to the browser at the same directory, re-listed so a just-saved
// signed PSBT shows up.
static void load_finished_cb(void) {
  scan_page_destroy();
  load_page_show();
  refresh();
}

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
  if (sd_card_file_size(full, &size) == ESP_OK && size > LOAD_MAX_FILE_SIZE) {
    dialog_show_error_timeout("File too large", NULL, 0);
    return;
  }

  uint8_t *data = NULL;
  size_t len = 0;
  esp_err_t ret = sd_card_read_file(full, &data, &len);
  if (ret != ESP_OK || !data || len == 0) {
    free(data);
    dialog_show_error_timeout("Failed to read file", NULL, 0);
    return;
  }

  load_page_hide();
  scan_load_content(lv_screen_active(), data, len, current_path, name,
                    load_finished_cb);
  SECURE_FREE_BUFFER(data, len); // the file may hold a mnemonic
}

/* ---------- Selection ---------- */

static void entry_selected_cb(void) {
  int idx = ui_menu_get_selected(load_menu);
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
  if (load_menu) {
    ui_menu_destroy(load_menu);
    load_menu = NULL;
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
  load_menu = ui_menu_create(load_screen, current_path, back_cb);
  if (!load_menu)
    return;

  bool paged = raw_count > LOAD_MAX_DISPLAYED;
  if (page_start >= raw_count)
    page_start = 0;
  shown_count = raw_count - page_start;
  if (paged && shown_count > LOAD_PAGE_SIZE)
    shown_count = LOAD_PAGE_SIZE;

  for (int i = 0; i < shown_count; i++) {
    int r = page_start + i;
    ui_menu_add_entry_with_icon(
        load_menu, raw_is_dir[r] ? LV_SYMBOL_DIRECTORY : LV_SYMBOL_FILE,
        raw_names[r], entry_selected_cb);
  }

  if (raw_count == 0) {
    ui_menu_add_entry(load_menu, "(empty)", entry_selected_cb);
    ui_menu_set_entry_enabled(load_menu, 0, false);
  } else if (paged) {
    char more[32];
    int pages = (raw_count + LOAD_PAGE_SIZE - 1) / LOAD_PAGE_SIZE;
    snprintf(more, sizeof(more), "More... (%d/%d)",
             page_start / LOAD_PAGE_SIZE + 1, pages);
    ui_menu_add_entry(load_menu, more, more_cb);
  }

  ui_menu_show(load_menu);
}

static void refresh(void) {
  if (load_menu) {
    ui_menu_destroy(load_menu);
    load_menu = NULL;
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
    dialog_show_error_timeout("No SD card", load_return_cb, 0);
    return;
  }

  refresh();
}

/* ---------- Public lifecycle ---------- */

void load_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  load_return_cb = return_cb;
  snprintf(current_path, sizeof(current_path), "%s", SD_CARD_MOUNT_POINT);
  page_start = 0;

  load_screen = theme_create_page_container(parent);

  loading_label = lv_label_create(load_screen);
  lv_label_set_text(loading_label, "Reading SD card...");
  lv_obj_set_style_text_font(loading_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(loading_label, primary_color(), 0);
  lv_obj_align(loading_label, LV_ALIGN_CENTER, 0, 0);

  init_timer = lv_timer_create(deferred_init_cb, 50, NULL);
  lv_timer_set_repeat_count(init_timer, 1);
}

void load_page_show(void) {
  if (load_screen)
    lv_obj_clear_flag(load_screen, LV_OBJ_FLAG_HIDDEN);
}

void load_page_hide(void) {
  if (load_screen)
    lv_obj_add_flag(load_screen, LV_OBJ_FLAG_HIDDEN);
}

void load_page_destroy(void) {
  if (init_timer) {
    lv_timer_del(init_timer);
    init_timer = NULL;
  }
  if (load_menu) {
    ui_menu_destroy(load_menu);
    load_menu = NULL;
  }
  if (load_screen) {
    lv_obj_del(load_screen);
    load_screen = NULL;
  }
  loading_label = NULL;

  cleanup_listing();
  load_return_cb = NULL;
}
