#include "bsp/bsp_common.h"
#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_35.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7796.h"
#include "esp_lcd_touch_ft5x06.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "wave_35";

esp_err_t bsp_wifi_coproc_disable(void) {
  return bsp_common_wifi_coproc_disable(BSP_C6_WIFI_EN);
}

esp_err_t bsp_i2c_init(void) {
  return bsp_common_i2c_init(BSP_I2C_NUM, BSP_I2C_SDA, BSP_I2C_SCL, false);
}

esp_err_t bsp_i2c_deinit(void) { return bsp_common_i2c_deinit(); }

esp_err_t bsp_display_brightness_init(void) {
  const bsp_ledc_backlight_cfg_t cfg = {
      .gpio_num = BSP_LCD_BACKLIGHT,
      .output_invert = false,
      .min_duty_percent = 0,
  };
  return bsp_common_backlight_ledc_init(&cfg);
}

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  return bsp_common_backlight_ledc_set(brightness_percent);
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  (void)config;
  esp_err_t ret = ESP_OK;
  esp_lcd_panel_io_handle_t io_handle = NULL;
  esp_lcd_panel_handle_t panel_handle = NULL;

  const spi_bus_config_t buscfg = {
      .sclk_io_num = BSP_LCD_SPI_CLK,
      .mosi_io_num = BSP_LCD_SPI_MOSI,
      .miso_io_num = GPIO_NUM_NC,
      .quadwp_io_num = GPIO_NUM_NC,
      .quadhd_io_num = GPIO_NUM_NC,
      .max_transfer_sz = (BSP_LCD_H_RES * BSP_LCD_V_RES),
  };
  ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO));

  ESP_LOGD(TAG, "Install panel IO");
  const esp_lcd_panel_io_spi_config_t io_config = {
      .dc_gpio_num = BSP_LCD_DC,
      .cs_gpio_num = BSP_LCD_SPI_CS,
      .pclk_hz = (80 * 1000 * 1000),
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
      .spi_mode = 3,
      .trans_queue_depth = 10,
  };
  ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST,
                                           &io_config, &io_handle));

  ESP_LOGD(TAG, "Install LCD driver");
  const esp_lcd_panel_dev_config_t panel_config = {
      .reset_gpio_num = BSP_LCD_RST,
      .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
      .bits_per_pixel = 16,
  };
  ESP_ERROR_CHECK(
      esp_lcd_new_panel_st7796(io_handle, &panel_config, &panel_handle));
  ESP_GOTO_ON_ERROR(esp_lcd_panel_reset(panel_handle), err, TAG,
                    "LCD panel reset failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_init(panel_handle), err, TAG,
                    "LCD panel init failed");
  ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
  esp_lcd_panel_disp_on_off(panel_handle, true);
  ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false));

  ret_handles->mipi_dsi_bus = NULL;
  ret_handles->io = io_handle;
  ret_handles->panel = panel_handle;
  ret_handles->control = NULL;

  ESP_LOGI(TAG, "Display initialized");
  return ret;

err:
  if (panel_handle) {
    esp_lcd_panel_del(panel_handle);
  }
  if (io_handle) {
    esp_lcd_panel_io_del(io_handle);
  }
  return ret;
}

esp_err_t bsp_touch_new(const bsp_touch_config_t *config,
                        esp_lcd_touch_handle_t *ret_touch) {
  (void)config;
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());

  const esp_lcd_touch_config_t tp_cfg = {
      .x_max = BSP_LCD_H_RES,
      .y_max = BSP_LCD_V_RES,
      .rst_gpio_num = BSP_LCD_TOUCH_RST,
      .int_gpio_num = BSP_LCD_TOUCH_INT,
      .levels =
          {
              .reset = 0,
              .interrupt = 0,
          },
      .flags =
          {
              .swap_xy = 0,
              .mirror_x = 0,
              .mirror_y = 0,
          },
  };
  esp_lcd_panel_io_handle_t tp_io_handle = NULL;
  esp_lcd_panel_io_i2c_config_t tp_io_config =
      ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG();
  tp_io_config.scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ;
  ESP_RETURN_ON_ERROR(esp_lcd_new_panel_io_i2c(bsp_common_i2c_get_handle(),
                                               &tp_io_config, &tp_io_handle),
                      TAG, "");
  return esp_lcd_touch_new_i2c_ft5x06(tp_io_handle, &tp_cfg, ret_touch);
}

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
lv_display_t *bsp_display_start(void) {
  const bsp_lvgl_display_cfg_t cfg = {
      .h_res = BSP_LCD_H_RES,
      .v_res = BSP_LCD_V_RES,
      .bits_per_pixel = BSP_LCD_BITS_PER_PIXEL,
      .is_mipi_dsi = false,
      .use_psram = true,
  };
  return bsp_common_display_start(&cfg);
}
#endif
