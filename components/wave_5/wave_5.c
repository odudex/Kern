#include "bsp/bsp_common.h"
#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_5.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_lcd_hx8394.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "wave_5";

esp_err_t bsp_wifi_coproc_disable(void) {
  return bsp_common_wifi_coproc_disable(BSP_C6_WIFI_EN);
}

esp_err_t bsp_i2c_init(void) {
  return bsp_common_i2c_init(BSP_I2C_NUM, BSP_I2C_SDA, BSP_I2C_SCL, false);
}

esp_err_t bsp_i2c_deinit(void) { return bsp_common_i2c_deinit(); }

/* Defensive init for a potential TPS-style power-rail chip at I2C 0x45.
   The Waveshare reference BSP ships this same sequence commented out, so
   the chip is unused on current hardware; we attempt it but silently
   succeed if the chip does not ACK, so we do not regress if a future
   hardware revision adds it. */
static esp_err_t bsp_display_power_rails_init(void) {
  ESP_RETURN_ON_ERROR(bsp_i2c_init(), TAG, "I2C init failed");

  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = 0x45,
      .scl_speed_hz = 100000,
  };
  i2c_master_dev_handle_t dev = NULL;
  if (i2c_master_bus_add_device(bsp_common_i2c_get_handle(), &dev_cfg, &dev) !=
      ESP_OK) {
    ESP_LOGW(TAG, "Power-rail chip (0x45) add_device failed; skipping");
    return ESP_OK; // Non-fatal: early boards may omit the chip
  }

  /* Ignore individual write errors — the chip is not ACKed on some samples. */
  const uint8_t seq1[] = {0x95, 0x11};
  (void)i2c_master_transmit(dev, seq1, sizeof(seq1), 50);
  const uint8_t seq2[] = {0x95, 0x17};
  (void)i2c_master_transmit(dev, seq2, sizeof(seq2), 50);
  const uint8_t seq3[] = {0x96, 0x00};
  (void)i2c_master_transmit(dev, seq3, sizeof(seq3), 50);
  vTaskDelay(pdMS_TO_TICKS(100));
  const uint8_t seq4[] = {0x96, 0xFF};
  (void)i2c_master_transmit(dev, seq4, sizeof(seq4), 50);

  i2c_master_bus_rm_device(dev);
  vTaskDelay(pdMS_TO_TICKS(100));
  return ESP_OK;
}

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

static esp_err_t create_hx8394_panel(esp_lcd_dsi_bus_handle_t dsi_bus,
                                     esp_lcd_panel_io_handle_t io,
                                     uint8_t bits_per_pixel,
                                     lcd_color_format_t color_fmt,
                                     esp_lcd_panel_handle_t *ret_panel) {
  ESP_LOGI(TAG, "Install HX8394 LCD control panel");
  esp_lcd_dpi_panel_config_t dpi_config = {
      .dpi_clk_src = MIPI_DSI_DPI_CLK_SRC_DEFAULT,
      .dpi_clock_freq_mhz = 58,
      .virtual_channel = 0,
      .in_color_format = color_fmt,
      .num_fbs = CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
      .video_timing =
          {
              .h_size = 720,
              .v_size = 1280,
              .hsync_back_porch = 20,
              .hsync_pulse_width = 20,
              .hsync_front_porch = 40,
              .vsync_back_porch = 10,
              .vsync_pulse_width = 4,
              .vsync_front_porch = 24,
          },
  };
  hx8394_vendor_config_t vendor_config = {
      .mipi_config =
          {
              .dsi_bus = dsi_bus,
              .dpi_config = &dpi_config,
              .lane_num = BSP_LCD_MIPI_DSI_LANE_NUM,
          },
  };
  esp_lcd_panel_dev_config_t lcd_dev_config = {
      .bits_per_pixel = bits_per_pixel,
      .rgb_ele_order = BSP_LCD_COLOR_SPACE,
      .reset_gpio_num = BSP_LCD_RST,
      .vendor_config = &vendor_config,
      .flags.reset_active_high = 1,
  };
  return esp_lcd_new_panel_hx8394(io, &lcd_dev_config, ret_panel);
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  (void)config;
  const bsp_dsi_display_cfg_t dsi_cfg = {
      .phy_ldo_chan = BSP_MIPI_DSI_PHY_PWR_LDO_CHAN,
      .phy_ldo_mv = BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV,
      .lane_num = BSP_LCD_MIPI_DSI_LANE_NUM,
      .lane_bitrate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
      .pre_bus_init = bsp_display_power_rails_init,
      .create_panel = create_hx8394_panel,
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
