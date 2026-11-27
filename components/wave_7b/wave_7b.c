#include "bsp/bsp_common.h"
#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_7b.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "esp_lcd_ek79007.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "wave_7b";

esp_err_t bsp_wifi_coproc_disable(void) {
  return bsp_common_wifi_coproc_disable(BSP_C6_WIFI_EN);
}

esp_err_t bsp_i2c_init(void) {
  return bsp_common_i2c_init(BSP_I2C_NUM, BSP_I2C_SDA, BSP_I2C_SCL, false);
}

esp_err_t bsp_i2c_deinit(void) { return bsp_common_i2c_deinit(); }

esp_err_t bsp_display_brightness_init(void) {
  /* Backlight on this board is driven through an inverting buffer; set
     output_invert so 100% duty maps to maximum brightness. */
  const bsp_ledc_backlight_cfg_t cfg = {
      .gpio_num = BSP_LCD_BACKLIGHT,
      .output_invert = true,
      .min_duty_percent = 0,
  };
  return bsp_common_backlight_ledc_init(&cfg);
}

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  return bsp_common_backlight_ledc_set(brightness_percent);
}

static esp_err_t create_ek79007_panel(esp_lcd_dsi_bus_handle_t dsi_bus,
                                      esp_lcd_panel_io_handle_t io,
                                      uint8_t bits_per_pixel,
                                      lcd_color_format_t color_fmt,
                                      esp_lcd_panel_handle_t *ret_panel) {
  ESP_LOGI(TAG, "Install EK79007 LCD control panel");
  /* Stock EK79007 1024x600@60Hz timings (52 MHz DPI clock), as used by the
     Waveshare upstream BSP for this panel. */
  esp_lcd_dpi_panel_config_t dpi_config =
      EK79007_1024_600_PANEL_60HZ_CONFIG_CF(color_fmt);
  dpi_config.num_fbs = CONFIG_BSP_LCD_DPI_BUFFER_NUMS;

  ek79007_vendor_config_t vendor_config = {
      .mipi_config =
          {
              .dsi_bus = dsi_bus,
              .dpi_config = &dpi_config,
          },
  };
  esp_lcd_panel_dev_config_t lcd_dev_config = {
      .bits_per_pixel = bits_per_pixel,
      .rgb_ele_order = BSP_LCD_COLOR_SPACE,
      .reset_gpio_num = BSP_LCD_RST,
      .vendor_config = &vendor_config,
  };
  return esp_lcd_new_panel_ek79007(io, &lcd_dev_config, ret_panel);
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  (void)config;
  const bsp_dsi_display_cfg_t dsi_cfg = {
      .phy_ldo_chan = BSP_MIPI_DSI_PHY_PWR_LDO_CHAN,
      .phy_ldo_mv = BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV,
      .lane_num = BSP_LCD_MIPI_DSI_LANE_NUM,
      .lane_bitrate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
      .create_panel = create_ek79007_panel,
      /* Panel is mounted rotated 180 degrees on this board. */
      .mirror_180 = true,
  };
  return bsp_common_dsi_display_init(&dsi_cfg, ret_handles);
}

esp_err_t bsp_touch_new(const bsp_touch_config_t *config,
                        esp_lcd_touch_handle_t *ret_touch) {
  (void)config;
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());
  const bsp_gt911_touch_cfg_t touch_cfg = {
      .x_max = BSP_LCD_H_RES,
      .y_max = BSP_LCD_V_RES,
      .rst_gpio_num = BSP_LCD_TOUCH_RST,
      .int_gpio_num = BSP_LCD_TOUCH_INT,
      /* Match the 180-degree panel mirror. */
      .mirror_x = true,
      .mirror_y = true,
      .probe_backup_addr = true,
  };
  return bsp_common_touch_gt911_new(&touch_cfg, ret_touch);
}

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
lv_display_t *bsp_display_start(void) {
  const bsp_lvgl_display_cfg_t cfg = {
      .h_res = BSP_LCD_H_RES,
      .v_res = BSP_LCD_V_RES,
      .bits_per_pixel = BSP_LCD_BITS_PER_PIXEL,
      .is_mipi_dsi = true,
      .use_psram = false,
  };
  return bsp_common_display_start(&cfg);
}
#endif
