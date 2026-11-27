#include "bsp/bsp_common.h"
#include "bsp/display_security.h"
#include "bsp_err_check.h"
#include "driver/ledc.h"
#include "esp_check.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "bsp_common";

static bool i2c_initialized = false;
static i2c_master_bus_handle_t i2c_handle = NULL;

static int ledc_min_duty_percent = 0;

esp_err_t bsp_common_wifi_coproc_disable(gpio_num_t en_gpio) {
  if (en_gpio == GPIO_NUM_NC) {
    ESP_LOGI(TAG, "No wireless co-processor on this board");
    return ESP_OK;
  }
  /* Output latch defaults to 0, so enabling the driver already pulls CHIP_EN
   * low against the external pull-up. */
  const gpio_config_t en_cfg = {
      .pin_bit_mask = 1ULL << en_gpio,
      .mode = GPIO_MODE_OUTPUT,
  };
  BSP_ERROR_CHECK_RETURN_ERR(gpio_config(&en_cfg));
  BSP_ERROR_CHECK_RETURN_ERR(gpio_set_level(en_gpio, 0));
  /* Latch the pad so CHIP_EN stays low through soft/WDT resets; only a
   * power-on reset releases it. */
  BSP_ERROR_CHECK_RETURN_ERR(gpio_hold_en(en_gpio));
  ESP_LOGI(TAG, "ESP32-C6 held in reset");
  return ESP_OK;
}

esp_err_t bsp_common_i2c_init(i2c_port_num_t port, gpio_num_t sda,
                              gpio_num_t scl, bool internal_pullup) {
  if (i2c_initialized) {
    return ESP_OK;
  }

  i2c_master_bus_config_t i2c_bus_conf = {
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .sda_io_num = sda,
      .scl_io_num = scl,
      .i2c_port = port,
      .flags.enable_internal_pullup = internal_pullup,
  };
  BSP_ERROR_CHECK_RETURN_ERR(i2c_new_master_bus(&i2c_bus_conf, &i2c_handle));

  i2c_initialized = true;
  return ESP_OK;
}

esp_err_t bsp_common_i2c_deinit(void) {
  if (i2c_initialized && i2c_handle) {
    BSP_ERROR_CHECK_RETURN_ERR(i2c_del_master_bus(i2c_handle));
    i2c_handle = NULL;
    i2c_initialized = false;
  }
  return ESP_OK;
}

i2c_master_bus_handle_t bsp_common_i2c_get_handle(void) { return i2c_handle; }

i2c_master_bus_handle_t bsp_i2c_get_handle(void) { return i2c_handle; }

esp_err_t bsp_common_i2c_probe(uint8_t addr) {
  return i2c_master_probe(i2c_handle, addr, 100);
}

#define LCD_LEDC_CH CONFIG_BSP_DISPLAY_BRIGHTNESS_LEDC_CH

esp_err_t bsp_common_backlight_ledc_init(const bsp_ledc_backlight_cfg_t *cfg) {
  ledc_min_duty_percent = cfg->min_duty_percent;

  const ledc_channel_config_t LCD_backlight_channel = {
      .gpio_num = cfg->gpio_num,
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = LCD_LEDC_CH,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = 1,
      .duty = 0,
      .hpoint = 0,
      .flags = {.output_invert = cfg->output_invert ? 1 : 0},
  };
  const ledc_timer_config_t LCD_backlight_timer = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .duty_resolution = LEDC_TIMER_10_BIT,
      .timer_num = 1,
      .freq_hz = 5000,
      .clk_cfg = LEDC_AUTO_CLK,
  };

  BSP_ERROR_CHECK_RETURN_ERR(ledc_timer_config(&LCD_backlight_timer));
  BSP_ERROR_CHECK_RETURN_ERR(ledc_channel_config(&LCD_backlight_channel));
  return ESP_OK;
}

esp_err_t bsp_common_backlight_ledc_set(int brightness_percent) {
  if (brightness_percent > 100) {
    brightness_percent = 100;
  } else if (brightness_percent < 0) {
    brightness_percent = 0;
  }

  int actual_percent =
      ledc_min_duty_percent +
      (brightness_percent * (100 - ledc_min_duty_percent)) / 100;

  ESP_LOGI(TAG, "Setting LCD backlight: %d%%", brightness_percent);

  uint32_t duty_cycle = (1023 * actual_percent) / 100;
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

esp_err_t bsp_common_ldo_enable(int chan_id, int voltage_mv,
                                esp_ldo_channel_handle_t *handle_slot) {
  if (chan_id <= 0) {
    return ESP_OK;
  }
  if (*handle_slot) {
    return ESP_OK;
  }
  esp_ldo_channel_config_t ldo_cfg = {
      .chan_id = chan_id,
      .voltage_mv = voltage_mv,
  };
  ESP_RETURN_ON_ERROR(esp_ldo_acquire_channel(&ldo_cfg, handle_slot), TAG,
                      "Acquire LDO channel %d failed", chan_id);
  ESP_LOGI(TAG, "LDO channel %d (%d mV) enabled", chan_id, voltage_mv);
  return ESP_OK;
}

esp_err_t bsp_display_new(const bsp_display_config_t *config,
                          esp_lcd_panel_handle_t *ret_panel,
                          esp_lcd_panel_io_handle_t *ret_io) {
  bsp_lcd_handles_t handles = {0};
  esp_err_t ret = bsp_display_new_with_handles(config, &handles);

  *ret_panel = handles.panel;
  *ret_io = handles.io;
  return ret;
}

esp_err_t bsp_common_dsi_display_init(const bsp_dsi_display_cfg_t *cfg,
                                      bsp_lcd_handles_t *ret_handles) {
  static esp_ldo_channel_handle_t phy_pwr_chan = NULL;
  esp_err_t ret = ESP_OK;

  ESP_RETURN_ON_ERROR(bsp_display_brightness_init(), TAG,
                      "Brightness init failed");
  ESP_RETURN_ON_ERROR(
      bsp_common_ldo_enable(cfg->phy_ldo_chan, cfg->phy_ldo_mv, &phy_pwr_chan),
      TAG, "DSI PHY power failed");
  if (cfg->pre_bus_init) {
    ESP_RETURN_ON_ERROR(cfg->pre_bus_init(), TAG, "Panel pre-bus init failed");
  }

  esp_lcd_dsi_bus_handle_t mipi_dsi_bus = NULL;
  esp_lcd_dsi_bus_config_t bus_config = {
      .bus_id = 0,
      .num_data_lanes = cfg->lane_num,
      .lane_bit_rate_mbps = cfg->lane_bitrate_mbps,
  };
  ESP_RETURN_ON_ERROR(esp_lcd_new_dsi_bus(&bus_config, &mipi_dsi_bus), TAG,
                      "New DSI bus init failed");

  ESP_LOGI(TAG, "Install MIPI DSI LCD control panel");
  esp_lcd_panel_io_handle_t io = NULL;
  esp_lcd_dbi_io_config_t dbi_config = {
      .virtual_channel = 0,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
  };
  esp_lcd_panel_handle_t disp_panel = NULL;
  ESP_GOTO_ON_ERROR(esp_lcd_new_panel_io_dbi(mipi_dsi_bus, &dbi_config, &io),
                    err, TAG, "New panel IO failed");

#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
  const uint8_t bpp = 24;
  const lcd_color_format_t color_fmt = LCD_COLOR_FMT_RGB888;
#else
  const uint8_t bpp = 16;
  const lcd_color_format_t color_fmt = LCD_COLOR_FMT_RGB565;
#endif

  ESP_GOTO_ON_ERROR(
      cfg->create_panel(mipi_dsi_bus, io, bpp, color_fmt, &disp_panel), err,
      TAG, "New LCD panel failed");
  ESP_GOTO_ON_ERROR(esp_lcd_dpi_panel_enable_dma2d(disp_panel), err, TAG,
                    "Enable DMA2D failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_reset(disp_panel), err, TAG,
                    "LCD panel reset failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_init(disp_panel), err, TAG,
                    "LCD panel init failed");
  if (cfg->mirror_180) {
    ESP_GOTO_ON_ERROR(esp_lcd_panel_mirror(disp_panel, true, true), err, TAG,
                      "LCD panel mirror failed");
  }

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

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
lv_display_t *bsp_common_display_start(const bsp_lvgl_display_cfg_t *cfg) {
  esp_lv_adapter_config_t adapter_cfg = ESP_LV_ADAPTER_DEFAULT_CONFIG();
  /* Larger task stack: libwally descriptor parsing has deep call chains. */
  adapter_cfg.task_stack_size = 16384;
  adapter_cfg.stack_in_psram = false;
  BSP_ERROR_CHECK_RETURN_NULL(esp_lv_adapter_init(&adapter_cfg));

  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_brightness_init());

  bsp_lcd_handles_t lcd_panels = {0};
  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_new_with_handles(NULL, &lcd_panels));

  if (cfg->is_mipi_dsi) {
    bsp_display_register_sensitive_buffers(
        lcd_panels.panel, CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
        (size_t)cfg->h_res * cfg->v_res * cfg->bits_per_pixel / 8);
  }

  ESP_LOGD(TAG, "Add LCD screen");
  esp_lv_adapter_display_config_t disp_cfg = {
      .panel = lcd_panels.panel,
      .panel_io = lcd_panels.io,
      .profile =
          {
              .interface = cfg->is_mipi_dsi ? ESP_LV_ADAPTER_PANEL_IF_MIPI_DSI
                                            : ESP_LV_ADAPTER_PANEL_IF_OTHER,
              .rotation = ESP_LV_ADAPTER_ROTATE_0,
              .hor_res = cfg->h_res,
              .ver_res = cfg->v_res,
              .buffer_height = 50,
              .use_psram = cfg->use_psram,
              .enable_ppa_accel = false,
              .require_double_buffer = false,
          },
      .tear_avoid_mode = ESP_LV_ADAPTER_TEAR_AVOID_MODE_NONE,
      .te_sync = ESP_LV_ADAPTER_TE_SYNC_DISABLED(),
  };

  lv_display_t *disp;
  BSP_NULL_CHECK(disp = esp_lv_adapter_register_display(&disp_cfg), NULL);

  esp_lcd_touch_handle_t tp = NULL;
  BSP_ERROR_CHECK_RETURN_NULL(bsp_touch_new(NULL, &tp));
  assert(tp);
  const esp_lv_adapter_touch_config_t touch_cfg =
      ESP_LV_ADAPTER_TOUCH_DEFAULT_CONFIG(disp, tp);
  BSP_NULL_CHECK(esp_lv_adapter_register_touch(&touch_cfg), NULL);

  ESP_ERROR_CHECK(esp_lv_adapter_start());
  return disp;
}

bool bsp_display_lock(uint32_t timeout_ms) {
  /* esp_lv_adapter_lock treats 0 as "try once, fail immediately", but callers
   * use 0 to mean "block forever" (matching esp_lvgl_port convention). */
  int32_t ms = (timeout_ms == 0) ? -1 : (int32_t)timeout_ms;
  return esp_lv_adapter_lock(ms) == ESP_OK;
}

void bsp_display_unlock(void) { esp_lv_adapter_unlock(); }
#endif
