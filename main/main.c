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

  // Larger LVGL task stack: libwally descriptor parsing has deep call
  // chains that exceed the default 7168-byte stack during multisig validation
  lvgl_port_cfg_t lvgl_cfg = ESP_LVGL_PORT_INIT_CONFIG();
  lvgl_cfg.task_stack = 16384;

  bsp_display_cfg_t cfg = {.lvgl_port_cfg = lvgl_cfg,
                           .buffer_size = BSP_LCD_DRAW_BUFF_SIZE,
                           .double_buffer = BSP_LCD_DRAW_BUFF_DOUBLE,
                           .flags = {
                               .buff_dma = true,
                               .buff_spiram = true,
                               .sw_rotate = true,
                           }};
  lv_display_t *disp = bsp_display_start_with_config(&cfg);
  ESP_LOGI(TAG, "Display initialized successfully");

  theme_init();
  lvgl_port_lock(0);

  // Apply saved screen rotation
  lv_display_set_rotation(disp, settings_get_rotation());

  // Set up screen theme background
  lv_obj_t *screen = lv_screen_active();
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
  lvgl_port_unlock();

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
  lvgl_port_lock(0);

  // Clear the screen
  lv_obj_clean(screen);

  // PIN gate: if PIN is configured, require unlock before login
  if (pin_is_configured()) {
    pin_page_create(screen, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
  } else {
    login_page_create(screen);
  }

  // Unlock display
  lvgl_port_unlock();
}
