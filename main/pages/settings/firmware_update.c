/*
 * Firmware Update Page — SD card firmware update (security-plan Phase 4).
 *
 * Browse SD for a signed .bin, verify it (signature, project, version)
 * before any flash write, confirm with the user, then stream it to the
 * inactive OTA slot and reboot. Verification and installation run on a
 * worker task; an LVGL timer polls for completion (kef_decrypt pattern,
 * minus the watchdog juggling: these tasks block on I/O constantly, so the
 * idle task is never starved). The worker stack must stay in internal DRAM:
 * flash writes disable the SPI cache, which would fault a PSRAM-backed
 * stack.
 */

#include "firmware_update.h"
#include "../../core/fw_update.h"
#include "../../ui/dialog.h"
#include "../../ui/theme_widgets.h"
#include "../shared/sd_file_browser.h"
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdio.h>
#include <string.h>

#define UPDATE_TASK_STACK_SIZE 12288

static void (*return_callback)(void) = NULL;
static lv_obj_t *verify_dialog = NULL;
static lv_obj_t *install_screen = NULL;
static lv_obj_t *install_bar = NULL;
static lv_obj_t *install_label = NULL;
static lv_timer_t *poll_timer = NULL;

static char selected_path[320];
static fw_update_info_t fw_info;
static const char *task_err = NULL;
static volatile bool task_done = false;
static volatile int task_result = -1;
static volatile int install_percent = 0;
static bool installing = false;

static void start_task(TaskFunction_t fn, const char *name);

// ── Worker tasks (no LVGL access) ──

static void install_progress_cb(int percent, void *user_data) {
  (void)user_data;
  install_percent = percent;
}

static void verify_task(void *arg) {
  (void)arg;
  task_result = fw_update_validate(selected_path, &fw_info, &task_err);
  task_done = true;
  vTaskDelete(NULL);
}

static void install_task(void *arg) {
  (void)arg;
  task_result =
      fw_update_apply(selected_path, install_progress_cb, NULL, &task_err);
  task_done = true;
  vTaskDelete(NULL);
}

// ── Install progress screen ──

static void destroy_install_screen(void) {
  if (install_screen) {
    lv_obj_del(install_screen);
    install_screen = NULL;
  }
  install_bar = NULL;
  install_label = NULL;
}

static void show_install_screen(void) {
  install_screen = theme_create_page_container(lv_screen_active());
  lv_obj_t *title = theme_create_page_title(install_screen, "Firmware Update");

  install_label = lv_label_create(install_screen);
  lv_label_set_text(install_label, "Installing... Do not power off");
  theme_apply_label(install_label, false);
  lv_obj_align(install_label, LV_ALIGN_CENTER, 0, -theme_button_spacing());

  install_bar = theme_create_progress_bar(install_screen, title, 0, 100);
  if (install_bar)
    lv_obj_align(install_bar, LV_ALIGN_CENTER, 0, theme_button_spacing());
}

// ── Completion handling (LVGL context) ──

static void restart_cb(void *user_data) {
  (void)user_data;
  esp_restart();
}

static void install_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;

  sd_file_browser_hide();
  show_install_screen();
  installing = true;
  install_percent = 0;
  start_task(install_task, "fw_install");
}

static void poll_timer_cb(lv_timer_t *timer) {
  (void)timer;

  if (installing && install_bar)
    lv_bar_set_value(install_bar, install_percent, LV_ANIM_OFF);

  if (!task_done)
    return;

  lv_timer_del(poll_timer);
  poll_timer = NULL;

  if (!installing) {
    // Verification finished
    if (verify_dialog) {
      lv_obj_del(verify_dialog);
      verify_dialog = NULL;
    }
    if (task_result != 0) {
      dialog_show_error_timeout(task_err, NULL, 0);
      return;
    }
    static char msg[160];
    snprintf(msg, sizeof(msg),
             "Install version %s?\nCurrent: %s\n\nThe device will restart.",
             fw_info.version, fw_info.current_version);
    dialog_show_confirm(msg, install_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
    return;
  }

  // Installation finished
  installing = false;
  destroy_install_screen();
  if (task_result != 0) {
    sd_file_browser_show();
    dialog_show_error_timeout(task_err, NULL, 0);
    return;
  }
  dialog_show_info("Firmware Update", "Update installed.\nRestarting...",
                   restart_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

static void start_task(TaskFunction_t fn, const char *name) {
  task_done = false;
  task_result = -1;
  task_err = "Update failed";
  if (xTaskCreatePinnedToCore(fn, name, UPDATE_TASK_STACK_SIZE, NULL, 5, NULL,
                              1) != pdPASS) {
    if (verify_dialog) {
      lv_obj_del(verify_dialog);
      verify_dialog = NULL;
    }
    if (installing) {
      installing = false;
      destroy_install_screen();
      sd_file_browser_show();
    }
    dialog_show_error_timeout("Task creation failed", NULL, 0);
    return;
  }
  poll_timer = lv_timer_create(poll_timer_cb, 100, NULL);
}

// ── File browser callbacks ──

static void file_selected_cb(const char *full_path, const char *dir,
                             const char *name) {
  (void)dir;
  size_t len = strlen(name);
  if (len < 4 || strcasecmp(name + len - 4, ".bin") != 0) {
    dialog_show_error_timeout("Select a .bin firmware file", NULL, 0);
    return;
  }
  if (strlen(full_path) >= sizeof(selected_path)) {
    dialog_show_error_timeout("Path too long", NULL, 0);
    return;
  }
  strcpy(selected_path, full_path);

  verify_dialog = dialog_show_progress(
      "Firmware Update", "Verifying signature...", DIALOG_STYLE_OVERLAY);
  installing = false;
  start_task(verify_task, "fw_verify");
}

static void browser_return_cb(void) {
  if (return_callback)
    return_callback();
}

// ── Public lifecycle ──

void firmware_update_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  return_callback = return_cb;
  verify_dialog = NULL;
  install_screen = NULL;
  install_bar = NULL;
  install_label = NULL;
  poll_timer = NULL;
  installing = false;

  sd_file_browser_config_t cfg = {
      .title = "Firmware Update",
      .on_file_selected = file_selected_cb,
      .return_cb = browser_return_cb,
      .max_file_size = 0x600000, /* OTA slot size */
  };
  sd_file_browser_create(parent, &cfg);
}

void firmware_update_page_show(void) { sd_file_browser_show(); }

void firmware_update_page_hide(void) { sd_file_browser_hide(); }

void firmware_update_page_destroy(void) {
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  if (verify_dialog) {
    lv_obj_del(verify_dialog);
    verify_dialog = NULL;
  }
  destroy_install_screen();
  sd_file_browser_destroy();
  return_callback = NULL;
}
