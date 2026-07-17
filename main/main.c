#include "core/nvs_secure.h"
#include "core/pin.h"
#include "core/settings.h"
#include "pages/session_lock.h"
#include "ui/assets/kern_logo_lvgl.h"
#include "ui/theme_widgets.h"
#include "utils/bip39_filter.h"
#include "video.h"
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

void app_main(void) {
  // Initialize NVS for persistent settings — encrypted if eFuse KEY4 is
  // provisioned, plaintext otherwise (never stock nvs_flash_init(): its
  // keygen path would burn KEY4 without consent)
  ESP_ERROR_CHECK(nvs_secure_init());
  settings_init();

  bsp_display_start();
  ESP_LOGI(TAG, "Display initialized successfully");

  esp_err_t video_ret = app_video_init_once(bsp_i2c_get_handle());
  if (video_ret == ESP_OK) {
    ESP_LOGI(TAG, "Video pipeline initialized");
  } else {
    ESP_LOGW(TAG, "Video pipeline init failed: %s", esp_err_to_name(video_ret));
  }

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

  // Lock display again for modifications
  bsp_display_lock(0);

  // Start inactivity monitoring (screensaver + session lock)
  session_lock_init();

  // Clear the screen
  lv_obj_clean(screen);

  // PIN gate: unlock page if a PIN is configured, else login
  session_lock_boot_gate(screen);

  // Unlock display
  bsp_display_unlock();
}
