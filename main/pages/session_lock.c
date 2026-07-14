// Session lock — inactivity screensaver and lock/power-off routing

#include "session_lock.h"
#include "../core/pin.h"
#include "../core/settings.h"
#include "../core/wallet.h"
#include "../utils/session.h"
#include "login/login.h"
#include "pin/pin_page.h"
#include "screensaver.h"
#include "video.h"
#include <bsp/pmic.h>

static bool device_locked = false;

static void post_unlock_cb(void) {
  pin_page_destroy();
  device_locked = false;
  login_page_create(lv_screen_active());
}

static void lock_dismissed_cb(void) {
  if (pin_is_configured()) {
    pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    device_locked = false;
    login_page_create(lv_screen_active());
  }
}

static void session_expired_handler(void) {
  if (device_locked) {
    // Nothing left to protect at the lock face / PIN gate; power-off boards
    // save the battery instead of idling there.
    if (bsp_pmic_can_power_off())
      bsp_pmic_power_off();
    return;
  }
  device_locked = true;
  // Tear down a plain screensaver before cleaning the screen, otherwise its
  // statics would dangle and the lock-face create below would touch freed
  // objects.
  screensaver_destroy();
  wallet_unload();
  // Boards with software power-off shut down instead of locking. ESP_OK only
  // means the PMIC accepted the write, so still fall through to the lock
  // face in case power doesn't actually cut (e.g. powered via USB).
  if (bsp_pmic_can_power_off())
    bsp_pmic_power_off();
  // Stop any live camera stream before cleaning: lv_obj_clean bypasses the
  // owning page's teardown, and a late frame would write to freed widgets.
  if (app_video_is_streaming())
    app_video_stop();
  lv_obj_clean(lv_screen_active());
  screensaver_create(lv_screen_active(), lock_dismissed_cb, true);
}

static void screensaver_trigger_handler(void) {
  if (screensaver_is_active())
    return;
  screensaver_create(lv_screen_active(), NULL, false);
}

void session_lock_init(void) {
  session_init(screensaver_trigger_handler, session_expired_handler);
  session_set_screensaver_timeout(settings_get_screensaver_timeout());
  session_set_timeout(settings_get_session_timeout());
}

void session_lock_boot_gate(lv_obj_t *screen) {
  if (pin_is_configured()) {
    device_locked = true;
    pin_page_create(screen, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    login_page_create(screen);
  }
}
