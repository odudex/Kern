#include "bsp/display.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_35.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7796.h"
#include "esp_lcd_touch_ft5x06.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "wave_35";

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
static lv_indev_t *disp_indev = NULL;
#endif

static bool i2c_initialized = false;
static esp_lcd_touch_handle_t tp = NULL;
static esp_lcd_panel_handle_t panel_handle = NULL;
static esp_lcd_panel_io_handle_t io_handle = NULL;
static i2c_master_bus_handle_t i2c_handle = NULL;

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
  if (i2c_initialized && i2c_handle) {
    BSP_ERROR_CHECK_RETURN_ERR(i2c_del_master_bus(i2c_handle));
    i2c_initialized = false;
  }
  return ESP_OK;
}

i2c_master_bus_handle_t bsp_i2c_get_handle(void) { return i2c_handle; }

#define LCD_LEDC_CH CONFIG_BSP_DISPLAY_BRIGHTNESS_LEDC_CH

esp_err_t bsp_display_brightness_init(void) {
  const ledc_channel_config_t LCD_backlight_channel = {
      .gpio_num = BSP_LCD_BACKLIGHT,
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = LCD_LEDC_CH,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = 1,
      .duty = 0,
      .hpoint = 0,
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
  ESP_RETURN_ON_ERROR(
      esp_lcd_new_panel_io_i2c(i2c_handle, &tp_io_config, &tp_io_handle), TAG,
      "");
  return esp_lcd_touch_new_i2c_ft5x06(tp_io_handle, &tp_cfg, ret_touch);
}

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
static lv_display_t *bsp_display_lcd_init(const bsp_display_cfg_t *cfg) {
  assert(cfg != NULL);
  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_new(NULL, &panel_handle, &io_handle));

  ESP_LOGD(TAG, "Add LCD screen");
  esp_lv_adapter_display_config_t disp_cfg = {
      .panel = panel_handle,
      .panel_io = io_handle,
      .profile =
          {
              .interface = ESP_LV_ADAPTER_PANEL_IF_OTHER,
              .rotation = ESP_LV_ADAPTER_ROTATE_0,
              .hor_res = BSP_LCD_H_RES,
              .ver_res = BSP_LCD_V_RES,
              .buffer_height = 50,
              .use_psram = true,
              .enable_ppa_accel = false,
              .require_double_buffer = false,
          },
      .tear_avoid_mode = ESP_LV_ADAPTER_TEAR_AVOID_MODE_NONE,
  };

  lv_display_t *disp = esp_lv_adapter_register_display(&disp_cfg);
  if (!disp) {
    return NULL;
  }

  return disp;
}

static lv_indev_t *bsp_display_indev_init(lv_display_t *disp) {
  BSP_ERROR_CHECK_RETURN_NULL(bsp_touch_new(NULL, &tp));
  assert(tp);

  const esp_lv_adapter_touch_config_t touch_cfg =
      ESP_LV_ADAPTER_TOUCH_DEFAULT_CONFIG(disp, tp);

  return esp_lv_adapter_register_touch(&touch_cfg);
}

lv_display_t *bsp_display_start(void) {
  bsp_display_cfg_t cfg = {
      .lv_adapter_cfg = ESP_LV_ADAPTER_DEFAULT_CONFIG(),
  };
  return bsp_display_start_with_config(&cfg);
}

lv_display_t *bsp_display_start_with_config(bsp_display_cfg_t *cfg) {
  lv_display_t *disp;

  assert(cfg != NULL);
  cfg->lv_adapter_cfg.task_stack_size = 16384;
  cfg->lv_adapter_cfg.stack_in_psram = false;
  BSP_ERROR_CHECK_RETURN_NULL(esp_lv_adapter_init(&cfg->lv_adapter_cfg));

  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_brightness_init());

  BSP_NULL_CHECK(disp = bsp_display_lcd_init(cfg), NULL);

  BSP_NULL_CHECK(disp_indev = bsp_display_indev_init(disp), NULL);

  ESP_ERROR_CHECK(esp_lv_adapter_start());

  return disp;
}

lv_indev_t *bsp_display_get_input_dev(void) { return disp_indev; }

bool bsp_display_lock(uint32_t timeout_ms) {
  // esp_lv_adapter_lock treats 0 as "try once, fail immediately",
  // but callers use 0 to mean "block forever" (matching esp_lvgl_port
  // convention). Translate 0 → -1 (portMAX_DELAY).
  int32_t ms = (timeout_ms == 0) ? -1 : (int32_t)timeout_ms;
  return esp_lv_adapter_lock(ms) == ESP_OK;
}

void bsp_display_unlock(void) { esp_lv_adapter_unlock(); }

#endif
