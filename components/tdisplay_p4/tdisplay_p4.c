#include "bsp/tdisplay_p4.h"
#include "bsp/display.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_ldo_regulator.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gt9895_touch.h"
#include "sdkconfig.h"
#include "xl9535.h"
#include <string.h>

static const char *TAG = "tdisplay_p4";

static bool i2c_initialized = false;
static i2c_master_bus_handle_t i2c_handle = NULL;
static bool xl9535_ready = false;

/* RM69A10 brightness uses DCS 0x51 instead of a backlight GPIO. */
static esp_lcd_panel_io_handle_t s_panel_io = NULL;

/* From the LilyGO RM69A10 driver for this AMOLED glass. */
typedef struct {
  uint8_t cmd;
  uint8_t data[4];
  uint8_t len;
  uint16_t delay_ms;
} rm69a10_cmd_t;

static const rm69a10_cmd_t rm69a10_init[] = {
    {0xFE, {0xFD}, 1, 0}, /* page select */
    {0x80, {0xFC}, 1, 0},
    {0xFE, {0x00}, 1, 0},                   /* back to user page */
    {0x2A, {0x00, 0x00, 0x02, 0x37}, 4, 0}, /* column: 0..567 */
    {0x2B, {0x00, 0x00, 0x04, 0xCF}, 4, 0}, /* row: 0..1231 */
    {0x31, {0x00, 0x03, 0x02, 0x34}, 4, 0},
    {0x30, {0x00, 0x00, 0x04, 0xCF}, 4, 0},
    {0x12, {0x00}, 1, 0},
    {0x35, {0x00}, 1, 0}, /* tearing effect on */
    {0x51, {0x00}, 1, 0}, /* brightness 0 (lit later via settings) */
    {0x11, {0}, 0, 120},  /* sleep out */
    {0x29, {0}, 0, 0},    /* display on */
};

#define RM69A10_CMD_BRIGHTNESS 0x51

#define SGM38121_I2C_ADDR 0x28
#define SGM38121_DEVICE_ID 0x80
#define SGM38121_REG_DEVICE_ID 0x00
#define SGM38121_REG_DVDD1 0x03
#define SGM38121_REG_AVDD1 0x05
#define SGM38121_REG_AVDD2 0x06
#define SGM38121_REG_ENABLE 0x0E
#define SGM38121_DVDD1_ENABLE (1U << 0)
#define SGM38121_AVDD1_ENABLE (1U << 2)
#define SGM38121_AVDD2_ENABLE (1U << 3)
#define SGM38121_DVDD_MV(mv) (((mv) - 504) / 8)
#define SGM38121_AVDD_MV(mv) (((mv) - 1384) / 8)

static i2c_master_dev_handle_t s_camera_ldo = NULL;

static esp_err_t sgm38121_read(uint8_t reg, uint8_t *value) {
  return i2c_master_transmit_receive(s_camera_ldo, &reg, 1, value, 1, 100);
}

static esp_err_t sgm38121_write(uint8_t reg, uint8_t value) {
  uint8_t data[] = {reg, value};
  return i2c_master_transmit(s_camera_ldo, data, sizeof(data), 100);
}

esp_err_t bsp_camera_power_init(i2c_master_bus_handle_t i2c_bus) {
  ESP_RETURN_ON_FALSE(i2c_bus, ESP_ERR_INVALID_ARG, TAG, "invalid camera bus");

  if (!s_camera_ldo) {
    const i2c_device_config_t config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = SGM38121_I2C_ADDR,
        .scl_speed_hz = 100000,
    };
    ESP_RETURN_ON_ERROR(
        i2c_master_bus_add_device(i2c_bus, &config, &s_camera_ldo), TAG,
        "add SGM38121 failed");
  }

  uint8_t id = 0;
  ESP_RETURN_ON_ERROR(sgm38121_read(SGM38121_REG_DEVICE_ID, &id), TAG,
                      "read SGM38121 id failed");
  ESP_RETURN_ON_FALSE(id == SGM38121_DEVICE_ID, ESP_ERR_INVALID_RESPONSE, TAG,
                      "unexpected SGM38121 id 0x%02X", id);

  ESP_RETURN_ON_ERROR(
      sgm38121_write(SGM38121_REG_DVDD1, SGM38121_DVDD_MV(1500)), TAG,
      "set camera DVDD failed");
  ESP_RETURN_ON_ERROR(
      sgm38121_write(SGM38121_REG_AVDD1, SGM38121_AVDD_MV(1800)), TAG,
      "set camera AVDD1 failed");
  ESP_RETURN_ON_ERROR(
      sgm38121_write(SGM38121_REG_AVDD2, SGM38121_AVDD_MV(3000)), TAG,
      "set camera AVDD2 failed");

  uint8_t enabled = 0;
  ESP_RETURN_ON_ERROR(sgm38121_read(SGM38121_REG_ENABLE, &enabled), TAG,
                      "read SGM38121 enable failed");
  enabled |=
      SGM38121_DVDD1_ENABLE | SGM38121_AVDD1_ENABLE | SGM38121_AVDD2_ENABLE;
  ESP_RETURN_ON_ERROR(sgm38121_write(SGM38121_REG_ENABLE, enabled), TAG,
                      "enable camera rails failed");
  vTaskDelay(pdMS_TO_TICKS(10));
  ESP_LOGI(TAG, "OV2710 power rails enabled");
  return ESP_OK;
}

esp_err_t bsp_wifi_coproc_disable(void) {
  /* CHIP_EN and the peripheral rail are routed through the XL9535. */
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());

  if (!xl9535_ready) {
    BSP_ERROR_CHECK_RETURN_ERR(xl9535_init(i2c_handle, BSP_XL9535_I2C_ADDR));
    xl9535_ready = true;
  }

  BSP_ERROR_CHECK_RETURN_ERR(xl9535_set_level(BSP_XL9535_C6_EN, 0));
  BSP_ERROR_CHECK_RETURN_ERR(xl9535_set_direction(BSP_XL9535_C6_EN, true));

  /* Display, touch and camera 3V3 enable is active low. */
  BSP_ERROR_CHECK_RETURN_ERR(xl9535_set_level(BSP_XL9535_PWR_EN_3V3, 0));
  BSP_ERROR_CHECK_RETURN_ERR(xl9535_set_direction(BSP_XL9535_PWR_EN_3V3, true));

  ESP_LOGI(TAG, "ESP32-C6 held in reset; 3V3 rail enabled");
  return ESP_OK;
}

esp_err_t bsp_i2c_init(void) {
  if (i2c_initialized) {
    return ESP_OK;
  }

  i2c_master_bus_config_t i2c_bus_conf = {
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .sda_io_num = BSP_I2C_SDA,
      .scl_io_num = BSP_I2C_SCL,
      .i2c_port = BSP_I2C_NUM,
      .flags.enable_internal_pullup = true,
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

esp_err_t bsp_display_brightness_init(void) { return ESP_OK; }

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  if (brightness_percent > 100) {
    brightness_percent = 100;
  } else if (brightness_percent < 0) {
    brightness_percent = 0;
  }

  if (!s_panel_io) {
    return ESP_ERR_INVALID_STATE;
  }

  uint8_t level = (uint8_t)((255 * brightness_percent) / 100);
  ESP_LOGI(TAG, "Setting AMOLED brightness: %d%% (0x%02X)", brightness_percent,
           level);
  return esp_lcd_panel_io_tx_param(s_panel_io, RM69A10_CMD_BRIGHTNESS, &level,
                                   1);
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

static esp_err_t rm69a10_hw_reset(void) {
  ESP_RETURN_ON_ERROR(xl9535_set_direction(BSP_XL9535_SCREEN_RST, true), TAG,
                      "rst dir");
  ESP_RETURN_ON_ERROR(xl9535_set_level(BSP_XL9535_SCREEN_RST, 1), TAG,
                      "rst hi");
  vTaskDelay(pdMS_TO_TICKS(10));
  ESP_RETURN_ON_ERROR(xl9535_set_level(BSP_XL9535_SCREEN_RST, 0), TAG,
                      "rst lo");
  vTaskDelay(pdMS_TO_TICKS(10));
  ESP_RETURN_ON_ERROR(xl9535_set_level(BSP_XL9535_SCREEN_RST, 1), TAG,
                      "rst hi");
  vTaskDelay(pdMS_TO_TICKS(120));
  return ESP_OK;
}

esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles) {
  (void)config;
  esp_err_t ret = ESP_OK;

  ESP_RETURN_ON_ERROR(bsp_enable_dsi_phy_power(), TAG, "DSI PHY power failed");

  esp_lcd_dsi_bus_handle_t mipi_dsi_bus = NULL;
  esp_lcd_dsi_bus_config_t bus_config = {
      .bus_id = 0,
      .num_data_lanes = BSP_LCD_MIPI_DSI_LANE_NUM,
      .phy_clk_src = MIPI_DSI_PHY_CLK_SRC_DEFAULT,
      .lane_bit_rate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
  };
  ESP_RETURN_ON_ERROR(esp_lcd_new_dsi_bus(&bus_config, &mipi_dsi_bus), TAG,
                      "New DSI bus init failed");

  esp_lcd_panel_io_handle_t io = NULL;
  esp_lcd_dbi_io_config_t dbi_config = {
      .virtual_channel = 0,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
  };
  esp_lcd_panel_handle_t disp_panel = NULL;
  ESP_GOTO_ON_ERROR(esp_lcd_new_panel_io_dbi(mipi_dsi_bus, &dbi_config, &io),
                    err, TAG, "New panel IO failed");

  ESP_GOTO_ON_ERROR(rm69a10_hw_reset(), err, TAG, "panel reset failed");
  for (size_t i = 0; i < sizeof(rm69a10_init) / sizeof(rm69a10_init[0]); i++) {
    const rm69a10_cmd_t *c = &rm69a10_init[i];
    ESP_GOTO_ON_ERROR(
        esp_lcd_panel_io_tx_param(io, c->cmd, c->len ? c->data : NULL, c->len),
        err, TAG, "init cmd 0x%02X failed", c->cmd);
    if (c->delay_ms) {
      vTaskDelay(pdMS_TO_TICKS(c->delay_ms));
    }
  }

  ESP_LOGI(TAG, "Install RM69A10 DPI panel");
  esp_lcd_dpi_panel_config_t dpi_config = {
      .dpi_clk_src = MIPI_DSI_DPI_CLK_SRC_DEFAULT,
      .dpi_clock_freq_mhz = BSP_LCD_DPI_CLK_MHZ,
      .virtual_channel = 0,
#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
      .in_color_format = LCD_COLOR_FMT_RGB888,
#else
      .in_color_format = LCD_COLOR_FMT_RGB565,
#endif
      .num_fbs = CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
      .video_timing =
          {
              .h_size = BSP_LCD_H_RES,
              .v_size = BSP_LCD_V_RES,
              .hsync_back_porch = BSP_LCD_DPI_HBP,
              .hsync_pulse_width = BSP_LCD_DPI_HSYNC,
              .hsync_front_porch = BSP_LCD_DPI_HFP,
              .vsync_back_porch = BSP_LCD_DPI_VBP,
              .vsync_pulse_width = BSP_LCD_DPI_VSYNC,
              .vsync_front_porch = BSP_LCD_DPI_VFP,
          },
  };
  ESP_GOTO_ON_ERROR(
      esp_lcd_new_panel_dpi(mipi_dsi_bus, &dpi_config, &disp_panel), err, TAG,
      "New DPI panel failed");
  ESP_GOTO_ON_ERROR(esp_lcd_dpi_panel_enable_dma2d(disp_panel), err, TAG,
                    "Enable DMA2D failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_init(disp_panel), err, TAG,
                    "DPI panel init failed");

  ret_handles->io = io;
  ret_handles->mipi_dsi_bus = mipi_dsi_bus;
  ret_handles->panel = disp_panel;
  ret_handles->control = NULL;
  s_panel_io = io;

  ESP_LOGI(TAG, "Display initialized (RM69A10 %dx%d)", BSP_LCD_H_RES,
           BSP_LCD_V_RES);
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

esp_err_t bsp_display_new(const bsp_display_config_t *config,
                          esp_lcd_panel_handle_t *ret_panel,
                          esp_lcd_panel_io_handle_t *ret_io) {
  bsp_lcd_handles_t handles;
  esp_err_t ret = bsp_display_new_with_handles(config, &handles);
  *ret_panel = handles.panel;
  *ret_io = handles.io;
  return ret;
}

esp_err_t bsp_touch_new(const bsp_touch_config_t *config,
                        esp_lcd_touch_handle_t *ret_touch) {
  (void)config;
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());

  /* GT9895 reset is routed through the XL9535. */
  ESP_RETURN_ON_ERROR(xl9535_set_direction(BSP_XL9535_TOUCH_RST, true), TAG,
                      "touch rst dir");
  ESP_RETURN_ON_ERROR(xl9535_set_level(BSP_XL9535_TOUCH_RST, 0), TAG,
                      "trst lo");
  vTaskDelay(pdMS_TO_TICKS(10));
  ESP_RETURN_ON_ERROR(xl9535_set_level(BSP_XL9535_TOUCH_RST, 1), TAG,
                      "trst hi");
  vTaskDelay(pdMS_TO_TICKS(100));

  const esp_lcd_touch_config_t tp_cfg = {
      .x_max = BSP_LCD_H_RES,
      .y_max = BSP_LCD_V_RES,
      .rst_gpio_num = GPIO_NUM_NC,
      .int_gpio_num = GPIO_NUM_NC,
      .flags =
          {
              .swap_xy = 0,
              .mirror_x = 0,
              .mirror_y = 0,
          },
  };
  return gt9895_touch_new(i2c_handle, &tp_cfg, ret_touch);
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

  lv_display_t *disp;
  BSP_NULL_CHECK(disp = bsp_display_lcd_init(), NULL);
  BSP_NULL_CHECK(bsp_display_indev_init(disp), NULL);

  ESP_ERROR_CHECK(esp_lv_adapter_start());

  return disp;
}

bool bsp_display_lock(uint32_t timeout_ms) {
  int32_t ms = (timeout_ms == 0) ? -1 : (int32_t)timeout_ms;
  return esp_lv_adapter_lock(ms) == ESP_OK;
}

void bsp_display_unlock(void) { esp_lv_adapter_unlock(); }

#endif
