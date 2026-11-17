/*
 * Secure Boot page: shows whether this device only starts release-signed
 * firmware and, once every check in core/secure_boot passes, burns the
 * lockdown behind a warning and the PIN. The status check and the burn run on
 * a worker task; an LVGL timer polls for completion.
 */

#include "secure_boot_page.h"
#include "../../core/secure_boot.h"
#include "../../project.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"
#include "../pin/pin_page.h"
#include <esp_system.h>
#include <stdio.h>

#define TASK_STACK_SIZE 16384

static void (*return_callback)(void) = NULL;
static lv_obj_t *screen = NULL;
static lv_obj_t *body = NULL;
static lv_obj_t *progress = NULL;
static lv_timer_t *poll_timer = NULL;
static bool pin_open;

static secure_boot_status_t status;
static esp_err_t enable_result;
static volatile bool done;
static bool running;
static bool enabling;

static void start_task(bool enable);

static void read_work(void) { secure_boot_read_status(&status); }

static void enable_work(void) { enable_result = secure_boot_enable(); }

static lv_obj_t *text(const char *msg, bool secondary) {
  lv_obj_t *label = theme_create_label(body, msg, secondary);
  lv_obj_set_width(label, LV_PCT(100));
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  return label;
}

static void heading(const char *msg, lv_color_t color) {
  lv_obj_set_style_text_color(text(msg, false), color, 0);
}

static void add_digests(void) {
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++) {
    char hex[SECURE_BOOT_DIGEST_LEN * 2 + SECURE_BOOT_DIGEST_LEN / 4 + 1];
    size_t n = 0;
    for (unsigned b = 0; b < SECURE_BOOT_DIGEST_LEN; b++) {
      if (b && b % 4 == 0)
        hex[n++] = ' ';
      n += snprintf(hex + n, sizeof(hex) - n, "%02x", status.digests[i][b]);
    }
    char title[24];
    snprintf(title, sizeof(title), "Key %u%s", i + 1,
             status.revoked[i] ? " (revoked)" : "");
    text(title, true);
    lv_obj_set_style_text_font(text(hex, false), theme_font_small(), 0);
  }
}

static void add_security_version(void) {
  char msg[80];
  snprintf(msg, sizeof(msg),
           "Security version %u. Firmware with a lower one will not start.",
           status.security_version);
  lv_obj_set_style_margin_top(text(msg, true), theme_default_padding(), 0);
}

static const char *blocked_reason(secure_boot_check_t check) {
  switch (check) {
  case SECURE_BOOT_ERR_BUILD:
    return "This firmware build cannot enable secure boot. Install a release "
           "that supports it.";
  case SECURE_BOOT_ERR_CHIP:
    return "Not available on this chip revision yet: once locked, it could "
           "not be flashed over USB again.";
  case SECURE_BOOT_ERR_PIN:
    return "Set up a PIN first.";
  case SECURE_BOOT_ERR_KEY_SLOTS:
    return "The eFuse key slots secure boot needs are already used on this "
           "device.";
  case SECURE_BOOT_ERR_APP:
    return "The running firmware is not signed by a release key. Install an "
           "official release first.";
  case SECURE_BOOT_ERR_BOOTLOADER:
    return "The bootloader is not signed by every release key. Flash a "
           "release with the USB web flasher first.";
  case SECURE_BOOT_ERR_READ:
    return "Could not read the firmware from flash.";
  default:
    return "";
  }
}

static void confirm_cb(bool confirmed, void *user_data);

static void action_cb(lv_event_t *e) {
  (void)e;
  dialog_show_danger_confirm("Lock this device to release-signed firmware?\n\n"
                             "This burns eFuses and cannot be undone.",
                             confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

static void add_action(const char *label) {
  lv_obj_t *btn = theme_create_button(body, label, true);
  lv_obj_set_style_margin_top(btn, theme_default_padding(), 0);
  lv_obj_add_event_cb(btn, action_cb, LV_EVENT_CLICKED, NULL);
}

static void render(void) {
  lv_obj_clean(body);
  bool ready = status.check == SECURE_BOOT_READY;

  switch (status.state) {
  case SECURE_BOOT_ON:
    heading("Enabled", good_color());
    text("Only firmware signed by one of these keys starts on this device.",
         true);
    add_digests();
    add_security_version();
    return;
  case SECURE_BOOT_INCOMPLETE:
    heading("Enabled, setup unfinished", error_color());
    text("Secure boot is on, but some of the protections that go with it "
         "are not set yet.",
         true);
    add_action("Finish Setup");
    return;
  case SECURE_BOOT_PARTIAL:
    heading("Partially set up", error_color());
    text("The release keys are already burned, but secure boot is not on.",
         true);
    break;
  case SECURE_BOOT_OFF:
    heading("Not enabled", secondary_color());
    text("Locks this device to firmware signed by the " PROJECT_NAME
         " release keys:\n"
         "- Unsigned firmware will not start, from SD card or USB\n"
         "- JTAG debugging is turned off\n"
         "This is permanent.",
         true);
    break;
  }

  if (!ready) {
    lv_obj_set_style_text_color(text(blocked_reason(status.check), false),
                                error_color(), 0);
    return;
  }
  text("Compare these keys with the ones published with the release:", true);
  add_digests();
  add_action(status.state == SECURE_BOOT_PARTIAL ? "Finish Setup"
                                                 : "Enable Secure Boot");
}

static void restart_cb(void *user_data) {
  (void)user_data;
  esp_restart();
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!done)
    return;
  worker_task_wait();
  running = false;
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  if (progress) {
    lv_obj_del(progress);
    progress = NULL;
  }

  if (!enabling) {
    render();
    return;
  }
  enabling = false;
  if (enable_result == ESP_OK) {
    dialog_show_acknowledge("Secure Boot", "Secure boot is enabled.", "Restart",
                            restart_cb, NULL, DIALOG_STYLE_FULLSCREEN);
    return;
  }
  dialog_show_error_timeout("Secure boot could not be enabled.", NULL, 0);
  start_task(false);
}

static void start_task(bool enable) {
  if (running || !body)
    return;
  enabling = enable;
  if (enable) {
    progress = dialog_show_progress("Secure Boot",
                                    "Burning eFuses...\nDo not power off",
                                    DIALOG_STYLE_FULLSCREEN);
  } else {
    lv_obj_clean(body);
    text("Checking firmware signatures...", true);
  }

  done = false;
  if (!worker_task_start_io(enable ? "sb_enable" : "sb_status", TASK_STACK_SIZE,
                            enable ? enable_work : read_work, &done)) {
    if (progress) {
      lv_obj_del(progress);
      progress = NULL;
    }
    enabling = false;
    dialog_show_error_timeout("Could not start the task", NULL, 0);
    return;
  }
  running = true;
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

static void pin_verified_cb(void) {
  pin_page_destroy();
  pin_open = false;
  secure_boot_page_show();
  start_task(true);
}

static void pin_cancel_cb(void) {
  pin_page_destroy();
  pin_open = false;
  secure_boot_page_show();
}

static void confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  secure_boot_page_hide();
  pin_open = true;
  pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, pin_verified_cb,
                  pin_cancel_cb);
}

static void back_cb(lv_event_t *e) {
  (void)e;
  if (!running && return_callback)
    return_callback();
}

void secure_boot_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(secure_boot_page_destroy);
  return_callback = return_cb;

  screen = theme_create_page_container(parent);
  ui_create_back_button(screen, back_cb);
  theme_create_page_title(screen, "Secure Boot");

  int32_t top_h = theme_corner_button_height() + theme_default_padding();
  body = theme_create_page_container(screen);
  lv_obj_set_size(body, LV_PCT(100), theme_screen_height() - top_h);
  lv_obj_align(body, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_pad_all(body, theme_default_padding(), 0);
  lv_obj_set_style_pad_gap(body, theme_small_padding(), 0);
  lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_add_flag(body, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_AUTO);

  start_task(false);
}

void secure_boot_page_show(void) {
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void secure_boot_page_hide(void) {
  if (screen)
    lv_obj_add_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void secure_boot_page_destroy(void) {
  session_cleanup_unregister(secure_boot_page_destroy);
  if (running) {
    worker_task_wait();
    running = false;
  }
  enabling = false;
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  if (progress) {
    lv_obj_del(progress);
    progress = NULL;
  }
  if (pin_open) {
    pin_page_destroy();
    pin_open = false;
  }
  if (screen) {
    lv_obj_del(screen);
    screen = NULL;
  }
  body = NULL;
  return_callback = NULL;
}
