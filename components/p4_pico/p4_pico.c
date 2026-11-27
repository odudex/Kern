#include "bsp/bsp_common.h"
#include "bsp/display.h"
#include "bsp/esp32_p4_pico.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/i2c_master.h"
#include "esp_lcd_hx8394.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "p4_pico";

static i2c_master_dev_handle_t lcd_mcu = NULL;

esp_err_t bsp_wifi_coproc_disable(void) {
  return bsp_common_wifi_coproc_disable(GPIO_NUM_NC);
}

esp_err_t bsp_i2c_init(void) {
  return bsp_common_i2c_init(BSP_I2C_NUM, BSP_I2C_SDA, BSP_I2C_SCL, true);
}

esp_err_t bsp_i2c_deinit(void) {
  if (lcd_mcu) {
    i2c_master_bus_rm_device(lcd_mcu);
    lcd_mcu = NULL;
  }
  return bsp_common_i2c_deinit();
}

esp_err_t bsp_display_brightness_init(void) {
  if (lcd_mcu) {
    return ESP_OK;
  }
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());
  if (bsp_common_i2c_probe(BSP_LCD_MCU_I2C_ADDR) != ESP_OK) {
    ESP_LOGE(TAG, "No display MCU at 0x%02X: is the display attached?",
             BSP_LCD_MCU_I2C_ADDR);
    return ESP_ERR_NOT_FOUND;
  }
  const i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = BSP_LCD_MCU_I2C_ADDR,
      .scl_speed_hz = 100000,
  };
  BSP_ERROR_CHECK_RETURN_ERR(i2c_master_bus_add_device(
      bsp_common_i2c_get_handle(), &dev_cfg, &lcd_mcu));

  /* Panel power-up, as wave_5 sends it to the same display MCU: wave_5
     firmware brings this panel up on a Pico, only its GPIO backlight fails. */
  const uint8_t power[][2] = {{0x95, 0x11}, {0x95, 0x17}};
  for (size_t i = 0; i < sizeof(power) / sizeof(power[0]); i++) {
    BSP_ERROR_CHECK_RETURN_ERR(
        i2c_master_transmit(lcd_mcu, power[i], sizeof(power[i]), 50));
  }
  vTaskDelay(pdMS_TO_TICKS(100));
  return ESP_OK;
}

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  if (brightness_percent > 100) {
    brightness_percent = 100;
  } else if (brightness_percent < 0) {
    brightness_percent = 0;
  }

  ESP_LOGI(TAG, "Setting LCD backlight: %d%%", brightness_percent);
  BSP_ERROR_CHECK_RETURN_ERR(bsp_display_brightness_init());

  /* Register 0x96 of the display MCU: 0x00 off to 0xFF full */
  const uint8_t buf[2] = {0x96, (uint8_t)(255 * brightness_percent / 100)};
  return i2c_master_transmit(lcd_mcu, buf, sizeof(buf), 50);
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
