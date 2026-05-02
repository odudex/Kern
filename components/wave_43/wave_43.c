#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_43.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/ledc.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7701.h"
#include "esp_lcd_touch_gt911.h"
#include "esp_ldo_regulator.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "wave_43";

static bool i2c_initialized = false;
static i2c_master_bus_handle_t i2c_handle = NULL;

/* Vendor-specific ST7701 init sequence (from Waveshare upstream BSP for the
   4.3" panel — required for correct gamma/timing/voltage on this glass). */
static const st7701_lcd_init_cmd_t vendor_specific_init_default[] = {
    {0xFF, (uint8_t[]){0x77, 0x01, 0x00, 0x00, 0x13}, 5, 0},
    {0xEF, (uint8_t[]){0x08}, 1, 0},
    {0xFF, (uint8_t[]){0x77, 0x01, 0x00, 0x00, 0x10}, 5, 0},
    {0xC0, (uint8_t[]){0x63, 0x00}, 2, 0},
    {0xC1, (uint8_t[]){0x0D, 0x02}, 2, 0},
    {0xC2, (uint8_t[]){0x17, 0x08}, 2, 0},
    {0xCC, (uint8_t[]){0x10}, 1, 0},
    {0xB0,
     (uint8_t[]){0x40, 0xC9, 0x94, 0x0E, 0x10, 0x05, 0x0B, 0x09, 0x08, 0x26,
                 0x04, 0x52, 0x10, 0x69, 0x6B, 0x69},
     16, 0},
    {0xB1,
     (uint8_t[]){0x40, 0xD2, 0x98, 0x0C, 0x92, 0x07, 0x09, 0x08, 0x07, 0x25,
                 0x02, 0x0E, 0x0C, 0x6E, 0x78, 0x55},
     16, 0},
    {0xFF, (uint8_t[]){0x77, 0x01, 0x00, 0x00, 0x11}, 5, 0},
    {0xB0, (uint8_t[]){0x5D}, 1, 0},
    {0xB1, (uint8_t[]){0x4E}, 1, 0},
    {0xB2, (uint8_t[]){0x87}, 1, 0},
    {0xB3, (uint8_t[]){0x80}, 1, 0},
    {0xB5, (uint8_t[]){0x4E}, 1, 0},
    {0xB7, (uint8_t[]){0x85}, 1, 0},
    {0xB8, (uint8_t[]){0x21}, 1, 0},
    {0xB9, (uint8_t[]){0x10, 0x1F}, 2, 0},
    {0xBB, (uint8_t[]){0x03}, 1, 0},
    {0xBC, (uint8_t[]){0x00}, 1, 0},
    {0xC1, (uint8_t[]){0x78}, 1, 0},
    {0xC2, (uint8_t[]){0x78}, 1, 0},
    {0xD0, (uint8_t[]){0x88}, 1, 0},
    {0xE0, (uint8_t[]){0x00, 0x3A, 0x02}, 3, 0},
    {0xE1,
     (uint8_t[]){0x04, 0xA0, 0x00, 0xA0, 0x05, 0xA0, 0x00, 0xA0, 0x00, 0x40,
                 0x40},
     11, 0},
    {0xE2,
     (uint8_t[]){0x30, 0x00, 0x40, 0x40, 0x32, 0xA0, 0x00, 0xA0, 0x00, 0xA0,
                 0x00, 0xA0, 0x00},
     13, 0},
    {0xE3, (uint8_t[]){0x00, 0x00, 0x33, 0x33}, 4, 0},
    {0xE4, (uint8_t[]){0x44, 0x44}, 2, 0},
    {0xE5,
     (uint8_t[]){0x09, 0x2E, 0xA0, 0xA0, 0x0B, 0x30, 0xA0, 0xA0, 0x05, 0x2A,
                 0xA0, 0xA0, 0x07, 0x2C, 0xA0, 0xA0},
     16, 0},
    {0xE6, (uint8_t[]){0x00, 0x00, 0x33, 0x33}, 4, 0},
    {0xE7, (uint8_t[]){0x44, 0x44}, 2, 0},
    {0xE8,
     (uint8_t[]){0x08, 0x2D, 0xA0, 0xA0, 0x0A, 0x2F, 0xA0, 0xA0, 0x04, 0x29,
                 0xA0, 0xA0, 0x06, 0x2B, 0xA0, 0xA0},
     16, 0},
    {0xEB, (uint8_t[]){0x00, 0x00, 0x4E, 0x4E, 0x00, 0x00, 0x00}, 7, 0},
    {0xEC, (uint8_t[]){0x08, 0x01}, 2, 0},
    {0xED,
     (uint8_t[]){0xB0, 0x2B, 0x98, 0xA4, 0x56, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF,
                 0xF7, 0x65, 0x4A, 0x89, 0xB2, 0x0B},
     16, 0},
    {0xEF, (uint8_t[]){0x08, 0x08, 0x08, 0x45, 0x3F, 0x54}, 6, 0},
    {0xFF, (uint8_t[]){0x77, 0x01, 0x00, 0x00, 0x00}, 5, 0},
    {0x11, (uint8_t[]){0x00}, 0, 120},
    {0x29, (uint8_t[]){0x00}, 0, 0},
};

esp_err_t bsp_i2c_init(void) {
  if (i2c_initialized) {
    return ESP_OK;
  }

  i2c_master_bus_config_t i2c_bus_conf = {
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .sda_io_num = BSP_I2C_SDA,
      .scl_io_num = BSP_I2C_SCL,
      .i2c_port = BSP_I2C_NUM,
  };
  BSP_ERROR_CHECK_RETURN_ERR(i2c_new_master_bus(&i2c_bus_conf, &i2c_handle));

  i2c_initialized = true;

  return ESP_OK;
}

esp_err_t bsp_i2c_deinit(void) {
  BSP_ERROR_CHECK_RETURN_ERR(i2c_del_master_bus(i2c_handle));
  i2c_initialized = false;
  return ESP_OK;
}

i2c_master_bus_handle_t bsp_i2c_get_handle(void) { return i2c_handle; }

static esp_err_t bsp_i2c_device_probe(uint8_t addr) {
  return i2c_master_probe(i2c_handle, addr, 100);
}

#define LCD_LEDC_CH CONFIG_BSP_DISPLAY_BRIGHTNESS_LEDC_CH

esp_err_t bsp_display_brightness_init(void) {
  /* Backlight on this board is driven through an inverting buffer — set
     output_invert so 100% duty maps to maximum brightness. */
  const ledc_channel_config_t LCD_backlight_channel = {
      .gpio_num = BSP_LCD_BACKLIGHT,
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = LCD_LEDC_CH,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = 1,
      .duty = 0,
      .hpoint = 0,
      .flags = {.output_invert = 1},
  };
  const ledc_timer_config_t LCD_backlight_timer = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .duty_resolution = LEDC_TIMER_10_BIT,
      .timer_num = 1,
      .freq_hz = 5000,
      .clk_cfg = LEDC_AUTO_CLK};

  BSP_ERROR_CHECK_RETURN_ERR(ledc_timer_config(&LCD_backlight_timer));
  BSP_ERROR_CHECK_RETURN_ERR(ledc_channel_config(&LCD_backlight_channel));

  return ESP_OK;
}

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  if (brightness_percent > 100) {
    brightness_percent = 100;
  } else if (brightness_percent < 0) {
    brightness_percent = 0;
  }

  ESP_LOGI(TAG, "Setting LCD backlight: %d%%", brightness_percent);

  uint32_t duty_cycle = (1023 * brightness_percent) / 100;
  BSP_ERROR_CHECK_RETURN_ERR(
      ledc_set_duty(LEDC_LOW_SPEED_MODE, LCD_LEDC_CH, duty_cycle));
  BSP_ERROR_CHECK_RETURN_ERR(
      ledc_update_duty(LEDC_LOW_SPEED_MODE, LCD_LEDC_CH));

  return ESP_OK;
}

esp_err_t bsp_display_backlight_off(void) {
  return bsp_display_brightness_set(0);
}

esp_err_t bsp_display_backlight_on(void) {
  return bsp_display_brightness_set(100);
}

static esp_err_t bsp_enable_dsi_phy_power(void) {
#if BSP_MIPI_DSI_PHY_PWR_LDO_CHAN > 0
  static esp_ldo_channel_handle_t phy_pwr_chan = NULL;
  esp_ldo_channel_config_t ldo_cfg = {
      .chan_id = BSP_MIPI_DSI_PHY_PWR_LDO_CHAN,
      .voltage_mv = BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV,
  };
  ESP_RETURN_ON_ERROR(esp_ldo_acquire_channel(&ldo_cfg, &phy_pwr_chan), TAG,
                      "Acquire LDO channel for DPHY failed");
  ESP_LOGI(TAG, "MIPI DSI PHY Powered on");
#endif

  return ESP_OK;
}

esp_err_t bsp_display_new(const bsp_display_config_t *config,
                          esp_lcd_panel_handle_t *ret_panel,
                          esp_lcd_panel_io_handle_t *ret_io) {
  bsp_lcd_handles_t handles;
  esp_err_t ret = bsp_display_new_with_handles(config, &handles);

  *ret_panel = handles.panel;
  *ret_io = handles.io;

  return ret;
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  esp_err_t ret = ESP_OK;

  ESP_RETURN_ON_ERROR(bsp_display_brightness_init(), TAG,
                      "Brightness init failed");
  ESP_RETURN_ON_ERROR(bsp_enable_dsi_phy_power(), TAG, "DSI PHY power failed");

  esp_lcd_dsi_bus_handle_t mipi_dsi_bus;
  esp_lcd_dsi_bus_config_t bus_config = {
      .bus_id = 0,
      .num_data_lanes = BSP_LCD_MIPI_DSI_LANE_NUM,
      .phy_clk_src = MIPI_DSI_PHY_CLK_SRC_DEFAULT,
      .lane_bit_rate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
  };
  ESP_RETURN_ON_ERROR(esp_lcd_new_dsi_bus(&bus_config, &mipi_dsi_bus), TAG,
                      "New DSI bus init failed");

  ESP_LOGI(TAG, "Install MIPI DSI LCD control panel");
  esp_lcd_panel_io_handle_t io;
  esp_lcd_dbi_io_config_t dbi_config = {
      .virtual_channel = 0,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
  };
  esp_lcd_panel_handle_t disp_panel = NULL;
  ESP_GOTO_ON_ERROR(esp_lcd_new_panel_io_dbi(mipi_dsi_bus, &dbi_config, &io),
                    err, TAG, "New panel IO failed");

  ESP_LOGI(TAG, "Install ST7701 LCD control panel");
  esp_lcd_dpi_panel_config_t dpi_config = {
      .dpi_clk_src = MIPI_DSI_DPI_CLK_SRC_DEFAULT,
      .dpi_clock_freq_mhz = 30,
      .virtual_channel = 0,
#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
      .in_color_format = LCD_COLOR_FMT_RGB888,
#else
      .in_color_format = LCD_COLOR_FMT_RGB565,
#endif
      .num_fbs = CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
      .video_timing =
          {
              .h_size = 480,
              .v_size = 800,
              .hsync_back_porch = 42,
              .hsync_pulse_width = 12,
              .hsync_front_porch = 42,
              .vsync_back_porch = 2,
              .vsync_pulse_width = 8,
              .vsync_front_porch = 60,
          },
  };

  st7701_vendor_config_t vendor_config = {
      .init_cmds = vendor_specific_init_default,
      .init_cmds_size =
          sizeof(vendor_specific_init_default) / sizeof(st7701_lcd_init_cmd_t),
      .flags =
          {
              .use_mipi_interface = 1,
          },
      .mipi_config =
          {
              .dsi_bus = mipi_dsi_bus,
              .dpi_config = &dpi_config,
          },
  };
  esp_lcd_panel_dev_config_t lcd_dev_config = {
#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
      .bits_per_pixel = 24,
#else
      .bits_per_pixel = 16,
#endif
      .rgb_ele_order = BSP_LCD_COLOR_SPACE,
      .reset_gpio_num = BSP_LCD_RST,
      .vendor_config = &vendor_config,
  };
  ESP_GOTO_ON_ERROR(esp_lcd_new_panel_st7701(io, &lcd_dev_config, &disp_panel),
                    err, TAG, "New LCD panel failed");
  ESP_GOTO_ON_ERROR(esp_lcd_dpi_panel_enable_dma2d(disp_panel), err, TAG,
                    "Enable DMA2D failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_reset(disp_panel), err, TAG,
                    "LCD panel reset failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_init(disp_panel), err, TAG,
                    "LCD panel init failed");

  ret_handles->io = io;
  ret_handles->mipi_dsi_bus = mipi_dsi_bus;
  ret_handles->panel = disp_panel;
  ret_handles->control = NULL;

  ESP_LOGI(TAG, "Display initialized");

  return ret;

err:
  if (disp_panel) {
    esp_lcd_panel_del(disp_panel);
  }
  if (io) {
    esp_lcd_panel_io_del(io);
  }
  if (mipi_dsi_bus) {
    esp_lcd_del_dsi_bus(mipi_dsi_bus);
  }
  return ret;
}

esp_err_t bsp_touch_new(const bsp_touch_config_t *config,
                        esp_lcd_touch_handle_t *ret_touch) {
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());

  /* GT911 can respond at either 0x5D (primary) or 0x14 (backup) depending
     on INT/RST timing — probe both and fall back. */
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

  esp_lcd_panel_io_i2c_config_t tp_io_config;
  if (bsp_i2c_device_probe(ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS) == ESP_OK) {
    ESP_LOGI(TAG, "GT911 found at 0x%02X", ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS);
    esp_lcd_panel_io_i2c_config_t cfg = ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG();
    memcpy(&tp_io_config, &cfg, sizeof(cfg));
  } else if (bsp_i2c_device_probe(ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP) ==
             ESP_OK) {
    ESP_LOGI(TAG, "GT911 found at 0x%02X",
             ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP);
    esp_lcd_panel_io_i2c_config_t cfg = ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG();
    cfg.dev_addr = ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP;
    memcpy(&tp_io_config, &cfg, sizeof(cfg));
  } else {
    ESP_LOGE(TAG, "GT911 not found at either I2C address");
    return ESP_ERR_NOT_FOUND;
  }
  tp_io_config.scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ;

  esp_lcd_panel_io_handle_t tp_io_handle = NULL;
  ESP_RETURN_ON_ERROR(
      esp_lcd_new_panel_io_i2c(i2c_handle, &tp_io_config, &tp_io_handle), TAG,
      "");

  return esp_lcd_touch_new_i2c_gt911(tp_io_handle, &tp_cfg, ret_touch);
}

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
static lv_display_t *bsp_display_lcd_init(void) {
  bsp_lcd_handles_t lcd_panels;
  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_new_with_handles(NULL, &lcd_panels));

  ESP_LOGD(TAG, "Add LCD screen");
  esp_lv_adapter_display_config_t disp_cfg = {
      .panel = lcd_panels.panel,
      .panel_io = lcd_panels.io,
      .profile =
          {
              .interface = ESP_LV_ADAPTER_PANEL_IF_MIPI_DSI,
              .rotation = ESP_LV_ADAPTER_ROTATE_0,
              .hor_res = BSP_LCD_H_RES,
              .ver_res = BSP_LCD_V_RES,
              .buffer_height = 50,
              .use_psram = false,
              .enable_ppa_accel = false,
              .require_double_buffer = false,
          },
      .tear_avoid_mode = ESP_LV_ADAPTER_TEAR_AVOID_MODE_NONE,
      .te_sync = ESP_LV_ADAPTER_TE_SYNC_DISABLED(),
  };

  return esp_lv_adapter_register_display(&disp_cfg);
}

static lv_indev_t *bsp_display_indev_init(lv_display_t *disp) {
  esp_lcd_touch_handle_t tp;
  BSP_ERROR_CHECK_RETURN_NULL(bsp_touch_new(NULL, &tp));
  assert(tp);

  const esp_lv_adapter_touch_config_t touch_cfg =
      ESP_LV_ADAPTER_TOUCH_DEFAULT_CONFIG(disp, tp);

  return esp_lv_adapter_register_touch(&touch_cfg);
}

lv_display_t *bsp_display_start(void) {
  esp_lv_adapter_config_t adapter_cfg = ESP_LV_ADAPTER_DEFAULT_CONFIG();
  // Larger task stack: libwally descriptor parsing has deep call chains
  adapter_cfg.task_stack_size = 16384;
  adapter_cfg.stack_in_psram = false;
  BSP_ERROR_CHECK_RETURN_NULL(esp_lv_adapter_init(&adapter_cfg));

  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_brightness_init());

  lv_display_t *disp;
  BSP_NULL_CHECK(disp = bsp_display_lcd_init(), NULL);
  BSP_NULL_CHECK(bsp_display_indev_init(disp), NULL);

  ESP_ERROR_CHECK(esp_lv_adapter_start());

  return disp;
}

bool bsp_display_lock(uint32_t timeout_ms) {
  // esp_lv_adapter_lock treats 0 as "try once, fail immediately",
  // but callers use 0 to mean "block forever" (matching esp_lvgl_port
  // convention). Translate 0 → -1 (portMAX_DELAY).
  int32_t ms = (timeout_ms == 0) ? -1 : (int32_t)timeout_ms;
  return esp_lv_adapter_lock(ms) == ESP_OK;
}

void bsp_display_unlock(void) { esp_lv_adapter_unlock(); }

#endif
