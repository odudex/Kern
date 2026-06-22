// Load Page — SD-card file browser feeding scan_load_content()

#include "load.h"
#include "../../ui/dialog.h"
#include "../../utils/secure_mem.h"
#include "../scan/scan.h"
#include "../shared/sd_file_browser.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdlib.h>

static void (*load_return_cb)(void) = NULL;

/* ---------- Loaded-content flow callbacks ---------- */

// Invoked when the loaded-content flow errors out or is backed out of —
// return to the browser at the same directory so another file can be picked.
static void load_finished_cb(void) {
  scan_page_destroy();
  sd_file_browser_show();
  sd_file_browser_refresh();
}

// Invoked when a signing flow runs to completion — nothing left to browse
// for, so return all the way to the caller (home).
static void load_complete_cb(void) {
  scan_page_destroy();
  if (load_return_cb)
    load_return_cb();
}

static void load_on_file_selected(const char *full_path, const char *dir,
                                  const char *name) {
  uint8_t *data = NULL;
  size_t len = 0;
  esp_err_t ret = sd_card_read_file(full_path, &data, &len);
  if (ret != ESP_OK || !data || len == 0) {
    free(data);
    dialog_show_error_timeout("Failed to read file", NULL, 0);
    return;
  }

  sd_file_browser_hide();
  scan_load_content(lv_screen_active(), data, len, dir, name, load_finished_cb,
                    load_complete_cb);
  SECURE_FREE_BUFFER(data, len); // the file may hold a mnemonic
}

/* ---------- Public lifecycle ---------- */

void load_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  load_return_cb = return_cb;

  sd_file_browser_config_t config = {
      .title = NULL,
      .on_file_selected = load_on_file_selected,
      .return_cb = return_cb,
  };
  sd_file_browser_create(parent, &config);
}

void load_page_show(void) { sd_file_browser_show(); }

void load_page_hide(void) { sd_file_browser_hide(); }

void load_page_destroy(void) {
  sd_file_browser_destroy();
  load_return_cb = NULL;
}
