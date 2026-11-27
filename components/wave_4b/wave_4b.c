#include "bsp/bsp_common.h"
#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_4b.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "esp_lcd_st7703.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "wave_4b";

// 720x720 panel init sequence (differs from upstream 720x1280 default)
static const st7703_lcd_init_cmd_t st7703_720_init_cmds[] = {
    {0xB9, (uint8_t[]){0xF1, 0x12, 0x83}, 3, 0},
    {0xB1, (uint8_t[]){0x00, 0x00, 0x00, 0xDA, 0x80}, 5, 0},
    {0xB2, (uint8_t[]){0x3C, 0x12, 0x30}, 3, 0},
    {0xB3,
     (uint8_t[]){0x10, 0x10, 0x28, 0x28, 0x03, 0xFF, 0x00, 0x00, 0x00, 0x00},
     10, 0},
    {0xB4, (uint8_t[]){0x80}, 1, 0},
    {0xB5, (uint8_t[]){0x0A, 0x0A}, 2, 0},
    {0xB6, (uint8_t[]){0x97, 0x97}, 2, 0},
    {0xB8, (uint8_t[]){0x26, 0x22, 0xF0, 0x13}, 4, 0},
    {0xBA, (uint8_t[]){0x31, 0x81, 0x0F, 0xF9, 0x0E, 0x06, 0x20, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x25, 0x00, 0x90,
                       0x0A, 0x00, 0x00, 0x01, 0x4F, 0x01, 0x00, 0x00, 0x37},
     27, 0},
    {0xBC, (uint8_t[]){0x47}, 1, 0},
    {0xBF, (uint8_t[]){0x02, 0x11, 0x00}, 3, 0},
    {0xC0, (uint8_t[]){0x73, 0x73, 0x50, 0x50, 0x00, 0x00, 0x12, 0x70, 0x00}, 9,
     0},
    {0xC1,
     (uint8_t[]){0x25, 0x00, 0x32, 0x32, 0x77, 0xE4, 0xFF, 0xFF, 0xCC, 0xCC,
                 0x77, 0x77},
     12, 0},
    {0xC6, (uint8_t[]){0x82, 0x00, 0xBF, 0xFF, 0x00, 0xFF}, 6, 0},
    {0xC7, (uint8_t[]){0xB8, 0x00, 0x0A, 0x10, 0x01, 0x09}, 6, 0},
    {0xC8, (uint8_t[]){0x10, 0x40, 0x1E, 0x02}, 4, 0},
    {0xCC, (uint8_t[]){0x0B}, 1, 0},
    {0xE0, (uint8_t[]){0x00, 0x0B, 0x10, 0x2C, 0x3D, 0x3F, 0x42, 0x3A, 0x07,
                       0x0D, 0x0F, 0x13, 0x15, 0x13, 0x14, 0x0F, 0x16, 0x00,
                       0x0B, 0x10, 0x2C, 0x3D, 0x3F, 0x42, 0x3A, 0x07, 0x0D,
                       0x0F, 0x13, 0x15, 0x13, 0x14, 0x0F, 0x16},
     34, 0},
    {0xE3,
     (uint8_t[]){0x07, 0x07, 0x0B, 0x0B, 0x0B, 0x0B, 0x00, 0x00, 0x00, 0x00,
                 0xFF, 0x00, 0xC0, 0x10},
     14, 0},
    {0xE9, (uint8_t[]){0xC8, 0x10, 0x0A, 0x00, 0x00, 0x80, 0x81, 0x12, 0x31,
                       0x23, 0x4F, 0x86, 0xA0, 0x00, 0x47, 0x08, 0x00, 0x00,
                       0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00,
                       0x00, 0x98, 0x02, 0x8B, 0xAF, 0x46, 0x02, 0x88, 0x88,
                       0x88, 0x88, 0x88, 0x98, 0x13, 0x8B, 0xAF, 0x57, 0x13,
                       0x88, 0x88, 0x88, 0x88, 0x88, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
     63, 0},
    {0xEA, (uint8_t[]){0x97, 0x0C, 0x09, 0x09, 0x09, 0x78, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x9F, 0x31, 0x8B, 0xA8, 0x31, 0x75,
                       0x88, 0x88, 0x88, 0x88, 0x88, 0x9F, 0x20, 0x8B, 0xA8,
                       0x20, 0x64, 0x88, 0x88, 0x88, 0x88, 0x88, 0x23, 0x00,
                       0x00, 0x02, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x40, 0x80, 0x81, 0x00, 0x00, 0x00, 0x00},
     61, 0},
    {0xEF, (uint8_t[]){0xFF, 0xFF, 0x01}, 3, 0},
    {0x11, (uint8_t[]){0x00}, 1, 250},
    {0x29, (uint8_t[]){0x00}, 1, 50},
};

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
      .output_invert = true,
      .min_duty_percent = 47,
  };
  return bsp_common_backlight_ledc_init(&cfg);
}

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  return bsp_common_backlight_ledc_set(brightness_percent);
}

static esp_err_t create_st7703_panel(esp_lcd_dsi_bus_handle_t dsi_bus,
                                     esp_lcd_panel_io_handle_t io,
                                     uint8_t bits_per_pixel,
                                     lcd_color_format_t color_fmt,
                                     esp_lcd_panel_handle_t *ret_panel) {
  ESP_LOGI(TAG, "Install ST7703 LCD control panel");
  esp_lcd_dpi_panel_config_t dpi_config = {
      .dpi_clk_src = MIPI_DSI_DPI_CLK_SRC_DEFAULT,
      .dpi_clock_freq_mhz = 38,
      .virtual_channel = 0,
      .in_color_format = color_fmt,
      .num_fbs = CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
      .video_timing =
          {
              .h_size = 720,
              .v_size = 720,
              .hsync_back_porch = 50,
              .hsync_pulse_width = 20,
              .hsync_front_porch = 50,
              .vsync_back_porch = 20,
              .vsync_pulse_width = 4,
              .vsync_front_porch = 20,
          },
  };
  st7703_vendor_config_t vendor_config = {
      .init_cmds = st7703_720_init_cmds,
      .init_cmds_size =
          sizeof(st7703_720_init_cmds) / sizeof(st7703_720_init_cmds[0]),
      .init_in_command_mode = true,
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
  return esp_lcd_new_panel_st7703(io, &lcd_dev_config, ret_panel);
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  (void)config;
  const bsp_dsi_display_cfg_t dsi_cfg = {
      .phy_ldo_chan = BSP_MIPI_DSI_PHY_PWR_LDO_CHAN,
      .phy_ldo_mv = BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV,
      .lane_num = BSP_LCD_MIPI_DSI_LANE_NUM,
      .lane_bitrate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
      .create_panel = create_st7703_panel,
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
      .manual_reset_retry = true,
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
