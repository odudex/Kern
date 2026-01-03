#include "pages/login_pages/login.h"
#include "ui_components/logo/kern_logo_lvgl.h"
#include "ui_components/theme.h"
#include <bsp/display.h>
#include <bsp/esp-bsp.h>
#include <esp_check.h>
#include <esp_err.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>
#include <wally_core.h>

static const char *TAG = "KERN_MAIN";

void app_main(void) {
  bsp_display_cfg_t cfg = {.lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
                           .buffer_size = BSP_LCD_DRAW_BUFF_SIZE,
                           .double_buffer = BSP_LCD_DRAW_BUFF_DOUBLE,
                           .flags = {
                               .buff_dma = true,
                               .buff_spiram = false,
                               .sw_rotate = false,
                           }};
  bsp_display_start_with_config(&cfg);
  ESP_LOGI(TAG, "Display initialized successfully");

  theme_init();
  lvgl_port_lock(0);

  // Set up screen theme background
  lv_obj_t *screen = lv_screen_active();
  theme_apply_screen(screen);
  // Force LVGL to render framebuffer
  lv_refr_now(NULL);
  // Allow rendering to complete
  vTaskDelay(pdMS_TO_TICKS(50));

  // Now turn on backlight
  bsp_display_brightness_set(50);

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

  // Lock display again for modifications
  lvgl_port_lock(0);

  // Clear the screen and show login page
  lv_obj_clean(screen);

  // Create and show the login page as a demonstration
  login_page_create(screen);

  // Unlock display
  lvgl_port_unlock();
}
