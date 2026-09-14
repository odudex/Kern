// Session lock — inactivity screensaver and lock/power-off routing

#include "session_lock.h"
#include "../core/nvs_secure.h"
#include "../core/pin.h"
#include "../core/settings.h"
#include "../core/wallet.h"
#include "../ui/dialog.h"
#include "../ui/display_cleanup.h"
#include "../utils/session.h"
#include "../utils/session_cleanup.h"
#include "../utils/worker_task.h"
#include "disclaimer.h"
#include "login/login.h"
#include "pin/pin_page.h"
#include "screensaver.h"
#include <bsp/pmic.h>
#include <esp_log.h>

static const char *TAG = "SESSION_LOCK";

static bool device_locked = false;

static void login_now(void) { login_page_create(lv_screen_active()); }

// Gating the login page rather than boot itself keeps the disclaimer
// unskippable: an idle timeout at the dialog locks the device, and the login
// page it eventually returns to is behind the same gate.
static void unlock_finished(void) {
  device_locked = false;
  disclaimer_gate(login_now);
}

// ---------------------------------------------------------------------------
// One-time migration: a PIN stored in plaintext NVS (set before storage
// encryption existed) survives reflashing, since flashing never erases the
// nvs partition. A stored PIN implies encrypted NVS, so after a successful
// unlock the user must re-run PIN setup through the encryption provisioning;
// declining removes the PIN.
// ---------------------------------------------------------------------------

static bool migration_pending(void) {
  return pin_is_configured() && !nvs_secure_is_encrypted();
}

// Declining the migration is meant to leave the device with no PIN. If the
// removal fails the PIN is still set, so say so rather than letting the user
// believe it is gone.
static void remove_pin_or_warn(void) {
  esp_err_t err = pin_remove();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "PIN removal failed: %s", esp_err_to_name(err));
    dialog_show_error_timeout("Could not remove the PIN - it is still set",
                              NULL, 0);
  }
}

static void migration_setup_done(void) {
  pin_page_destroy();
  unlock_finished();
}

static void migration_setup_cancel(void) {
  remove_pin_or_warn();
  pin_page_destroy();
  unlock_finished();
}

static void migration_confirm_result(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    remove_pin_or_warn();
    unlock_finished();
    return;
  }
  pin_page_create(lv_screen_active(), PIN_PAGE_SETUP, migration_setup_done,
                  migration_setup_cancel);
}

static void post_unlock_cb(void) {
  pin_page_destroy();
  if (migration_pending()) {
    dialog_show_confirm(
        "Storage encryption upgrade\n\n"
        "This firmware stores the PIN in encrypted storage. Your PIN was "
        "saved by an older version and must be set up again.\n\n"
        "Declining removes the PIN.",
        migration_confirm_result, NULL, DIALOG_STYLE_FULLSCREEN);
    return;
  }
  unlock_finished();
}

static void lock_dismissed_cb(void) {
  if (pin_is_configured()) {
    pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    unlock_finished();
  }
}

void session_lock_now(void) {
  // A locked device may still have a partially entered PIN to discard.
  device_locked = true;
  // Tear down a plain screensaver before cleaning the screen, otherwise its
  // statics would dangle and the lock-face create below would touch freed
  // objects.
  screensaver_destroy();
  // Workers never call LVGL. Join them before deleting poll timers or buffers.
  worker_task_wait();
  session_cleanup_run();
  wallet_unload();
  lv_obj_clean(lv_screen_active());
  ui_display_scrub();
  screensaver_create(lv_screen_active(), lock_dismissed_cb,
                     pin_is_configured() ? "Locked" : "Unloaded");
  // Finish the clean frame before attempting power-off (USB can keep us on).
  lv_obj_invalidate(lv_screen_active());
  lv_refr_now(NULL);
}

void session_lock_dismiss(void) {
  screensaver_destroy();
  lock_dismissed_cb();
}

static void session_expired_handler(void) {
  session_lock_now();
  if (bsp_pmic_can_power_off())
    bsp_pmic_power_off();
}

static void screensaver_trigger_handler(void) {
  if (screensaver_is_active())
    return;
  screensaver_create(lv_screen_active(), NULL, NULL);
}

void session_lock_reload_settings(void) {
  session_set_screensaver_timeout(settings_get_screensaver_timeout());
  session_set_timeout(settings_get_session_timeout());
}

void session_lock_init(void) {
  session_init(screensaver_trigger_handler, session_expired_handler);
  session_lock_reload_settings();
}

void session_lock_boot_gate(lv_obj_t *screen) {
  if (pin_is_configured()) {
    device_locked = true;
    pin_page_create(screen, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    unlock_finished();
  }
}
