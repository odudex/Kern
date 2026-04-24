#include "core/pin.h"
#include "core/session.h"
#include "core/settings.h"
#include "core/wallet.h"
#include "pages/login/login.h"
#include "pages/pin/pin_page.h"
#include "pages/screensaver.h"
#include "ui/assets/kern_logo_lvgl.h"
#include "ui/theme.h"
#include "utils/bip39_filter.h"
#include <bsp/display.h>
#include <bsp/esp-bsp.h>
#include <bsp/pmic.h>
#include <esp_check.h>
#include <esp_err.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>
#include <nvs_flash.h>
#include <wally_core.h>

static const char *TAG = "KERN_MAIN";

// ---------------------------------------------------------------------------
// Session expiry: lock the device and require PIN re-entry
// ---------------------------------------------------------------------------

static void session_expired_handler(void);

static void post_unlock_cb(void) {
  pin_page_destroy();

  // Start session timeout
  uint16_t timeout = pin_get_session_timeout();
  if (timeout > 0)
    session_start(timeout);

  login_page_create(lv_screen_active());
}

static void screensaver_dismissed_cb(void) {
  pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
}

static void session_expired_handler(void) {
  wallet_unload();
  lv_obj_clean(lv_screen_active());
  screensaver_create(lv_screen_active(), screensaver_dismissed_cb);
}

// ---------------------------------------------------------------------------

void app_main(void) {
  // Initialize NVS for persistent settings
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  settings_init();

  bsp_display_start();
  ESP_LOGI(TAG, "Display initialized successfully");

  // Paint screen black early to overwrite stale framebuffer on warm reset.
  bsp_display_lock(0);
  lv_obj_t *screen = lv_screen_active();
  lv_obj_set_style_bg_color(screen, bg_color(), 0);
  lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);
  lv_obj_invalidate(screen);
  lv_refr_now(NULL);
  bsp_display_unlock();

  // Initialize PMIC (AXP2101 on wave_35; no-op on wave_4b)
  esp_err_t pmic_ret = bsp_pmic_init();
  if (pmic_ret == ESP_OK) {
    ESP_LOGI(TAG, "PMIC initialized");
  } else if (pmic_ret != ESP_ERR_NOT_SUPPORTED) {
    ESP_LOGW(TAG, "PMIC init failed: %s", esp_err_to_name(pmic_ret));
  }

  theme_init();
  bsp_display_lock(0);

  // Set up screen theme background
  theme_apply_screen(screen);
  // Force LVGL to render framebuffer
  lv_refr_now(NULL);
  // Allow rendering to complete
  vTaskDelay(pdMS_TO_TICKS(50));

  // Now turn on backlight
  bsp_display_brightness_set(settings_get_brightness());

  // Show animated logo splash screen
  kern_logo_animated(screen);

  // Unlock display to allow LVGL to render the splash screen
  bsp_display_unlock();

  // Wait for a few seconds to show the splash
  vTaskDelay(pdMS_TO_TICKS(3000));

  // Initialize other libraries while displaying the splash screen
  const int wally_res = wally_init(0);
  if (wally_res != WALLY_OK) {
    abort();
  }

  // Initialize BIP39 wordlist (needed for anti-phishing words)
  bip39_filter_init();

  // Initialize PIN module
  pin_init();

  // Set up session expiry callback
  session_set_expired_callback(session_expired_handler);

  // Lock display again for modifications
  bsp_display_lock(0);

  // Clear the screen
  lv_obj_clean(screen);

  // PIN gate: if PIN is configured, require unlock before login
  if (pin_is_configured()) {
    pin_page_create(screen, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    login_page_create(screen);
  }

  // Unlock display
  bsp_display_unlock();
}
