#include "bsp/display.h"
#include "bsp/display_security.h"
#include "bsp/esp32_p4_pico.h"
#include "bsp/touch.h"
#include "bsp_err_check.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_touch_ft5x06.h"
#include "esp_lcd_touch_gt911.h"
#include "esp_ldo_regulator.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/mipi_dsi_hal.h"
#include "hal/mipi_dsi_ll.h"
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "p4_pico";

static bool i2c_initialized = false;
static i2c_master_bus_handle_t i2c_handle = NULL;
static i2c_master_dev_handle_t bridge_dev = NULL;

esp_err_t bsp_wifi_coproc_disable(void) {
  ESP_LOGI(TAG, "No wireless co-processor on this board");
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
  if (bridge_dev) {
    i2c_master_bus_rm_device(bridge_dev);
    bridge_dev = NULL;
  }
  BSP_ERROR_CHECK_RETURN_ERR(i2c_del_master_bus(i2c_handle));
  i2c_initialized = false;
  return ESP_OK;
}

i2c_master_bus_handle_t bsp_i2c_get_handle(void) { return i2c_handle; }

static esp_err_t bsp_i2c_device_probe(uint8_t addr) {
  return i2c_master_probe(i2c_handle, addr, 100);
}

/* ---- Display MCU at 0x45 (power, backlight) ------------------------------ */

static esp_err_t bridge_write(uint8_t reg, uint8_t val) {
  uint8_t buf[2] = {reg, val};
  return i2c_master_transmit(bridge_dev, buf, sizeof(buf), 100);
}

static esp_err_t bridge_read(uint8_t reg, uint8_t *val) {
  return i2c_master_transmit_receive(bridge_dev, &reg, 1, val, 1, 100);
}

esp_err_t bsp_display_brightness_init(void) {
  if (bridge_dev) {
    return ESP_OK;
  }
  BSP_ERROR_CHECK_RETURN_ERR(bsp_i2c_init());
  if (bsp_i2c_device_probe(BSP_LCD_BRIDGE_I2C_ADDR) != ESP_OK) {
    ESP_LOGE(TAG,
             "No display MCU at 0x%02X: is the DSI display attached through a "
             "display-type 22-to-15 cable?",
             BSP_LCD_BRIDGE_I2C_ADDR);
    return ESP_ERR_NOT_FOUND;
  }
  const i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = BSP_LCD_BRIDGE_I2C_ADDR,
      .scl_speed_hz = 100000,
  };
  BSP_ERROR_CHECK_RETURN_ERR(
      i2c_master_bus_add_device(i2c_handle, &dev_cfg, &bridge_dev));
  return ESP_OK;
}

#if CONFIG_KERN_PICO_DSI_BRIDGE_RPI_TS

/* Atmel MCU registers on the Raspberry Pi touch display */
#define RPI_REG_ID 0x80
#define RPI_REG_PORTA 0x81
#define RPI_REG_PORTB 0x82
#define RPI_REG_POWERON 0x85
#define RPI_REG_PWM 0x86

/* TC358762 registers, written over DSI generic long packets */
#define TC_PPI_STARTPPI 0x0104
#define TC_PPI_LPTXTIMECNT 0x0114
#define TC_PPI_D0S_ATMR 0x0144
#define TC_PPI_D1S_ATMR 0x0148
#define TC_PPI_D0S_CLRSIPOCOUNT 0x0164
#define TC_PPI_D1S_CLRSIPOCOUNT 0x0168
#define TC_DSI_STARTDSI 0x0204
#define TC_DSI_LANEENABLE 0x0210
#define TC_LCDCTRL 0x0420
#define TC_SPICMR 0x0450
#define TC_SYSCTRL 0x0464

static esp_err_t bridge_power_on(void) {
  uint8_t id = 0;
  if (bridge_read(RPI_REG_ID, &id) == ESP_OK) {
    /* 0xDE (v1) or 0xC3 (v2) on the genuine display */
    ESP_LOGI(TAG, "Display MCU ID 0x%02X", id);
  }
  /* The MCU misbehaves on I2C for a few ms after REG_POWERON writes, and the
     bridge wants at least 100 ms off before power-up. */
  bridge_write(RPI_REG_PWM, 0);
  bridge_write(RPI_REG_POWERON, 0);
  vTaskDelay(pdMS_TO_TICKS(100));
  ESP_RETURN_ON_ERROR(bridge_write(RPI_REG_POWERON, 1), TAG, "power on");
  vTaskDelay(pdMS_TO_TICKS(25));
  for (int i = 0; i < 100; i++) {
    uint8_t portb = 0;
    if (bridge_read(RPI_REG_PORTB, &portb) == ESP_OK && (portb & 1)) {
      return ESP_OK;
    }
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  ESP_LOGW(TAG, "Bridge power-good not reported, continuing");
  return ESP_OK;
}

static void tc358762_write(uint16_t reg, uint32_t val) {
  /* Only one DSI host exists on the P4, so the register bases are static and
     the HAL context needs no private bus state. */
  mipi_dsi_hal_context_t hal = {
      .host = MIPI_DSI_LL_GET_HOST(0),
      .bridge = MIPI_DSI_LL_GET_BRG(0),
  };
  const uint8_t msg[6] = {reg & 0xFF,         reg >> 8,
                          val & 0xFF,         (val >> 8) & 0xFF,
                          (val >> 16) & 0xFF, (val >> 24) & 0xFF};
  mipi_dsi_hal_host_gen_write_long_packet(
      &hal, 0, MIPI_DSI_DT_GENERIC_LONG_WRITE, msg, sizeof(msg));
}

/* Same sequence as the Linux tc358762 bridge driver; the host must still be in
   command mode (no video stream) while these go out. */
static void bridge_configure(void) {
  tc358762_write(TC_DSI_LANEENABLE, BIT(0) | BIT(1));
  tc358762_write(TC_PPI_D0S_CLRSIPOCOUNT, 0x05);
  tc358762_write(TC_PPI_D1S_CLRSIPOCOUNT, 0x05);
  tc358762_write(TC_PPI_D0S_ATMR, 0x00);
  tc358762_write(TC_PPI_D1S_ATMR, 0x00);
  tc358762_write(TC_PPI_LPTXTIMECNT, 0x03);
  tc358762_write(TC_SPICMR, 0x00);
  /* VSDELAY(1) | RGB888 | UNK6 | VTGEN */
  tc358762_write(TC_LCDCTRL, 0x00100150);
  tc358762_write(TC_SYSCTRL, 0x040F);
  vTaskDelay(pdMS_TO_TICKS(100));
  tc358762_write(TC_PPI_STARTPPI, 0x01);
  tc358762_write(TC_DSI_STARTDSI, 0x01);
  vTaskDelay(pdMS_TO_TICKS(100));
}

static esp_err_t bridge_enable(void) {
  /* Same orientation the Pi firmware uses for this panel */
  return bridge_write(RPI_REG_PORTA, BIT(2));
}

static esp_err_t bridge_set_backlight(uint8_t level) {
  return bridge_write(RPI_REG_PWM, level);
}

/* Modeline from the Pi firmware: the bridge regenerates DPI timing itself, so
   the DSI-side blanking is tiny. */
#define PICO_DPI_CLK_MHZ 26
#define PICO_HBP 46
#define PICO_HPW 2
#define PICO_HFP 1
#define PICO_VBP 21
#define PICO_VPW 2
#define PICO_VFP 7

#else /* CONFIG_KERN_PICO_DSI_BRIDGE_WAVESHARE */

static esp_err_t bridge_power_on(void) {
  ESP_RETURN_ON_ERROR(bridge_write(0xC0, 0x01), TAG, "bridge 0xC0");
  ESP_RETURN_ON_ERROR(bridge_write(0xC2, 0x01), TAG, "bridge 0xC2");
  ESP_RETURN_ON_ERROR(bridge_write(0xAC, 0x01), TAG, "bridge 0xAC");
  return ESP_OK;
}

static void bridge_configure(void) {}

static esp_err_t bridge_enable(void) { return bridge_write(0xAD, 0x01); }

static esp_err_t bridge_set_backlight(uint8_t level) {
  ESP_RETURN_ON_ERROR(bridge_write(0xAB, 0xFF - level), TAG, "backlight");
  return bridge_write(0xAA, 0x01);
}

#define PICO_DPI_CLK_MHZ 28
#define PICO_HBP 40
#define PICO_HPW 20
#define PICO_HFP 40
#define PICO_VBP 10
#define PICO_VPW 10
#define PICO_VFP 10

#endif

esp_err_t bsp_display_brightness_set(int brightness_percent) {
  if (brightness_percent > 100) {
    brightness_percent = 100;
  } else if (brightness_percent < 0) {
    brightness_percent = 0;
  }

  ESP_LOGI(TAG, "Setting LCD backlight: %d%%", brightness_percent);
  BSP_ERROR_CHECK_RETURN_ERR(bsp_display_brightness_init());
  return bridge_set_backlight((uint8_t)((255 * brightness_percent) / 100));
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
  if (phy_pwr_chan) {
    return ESP_OK;
  }
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
  bsp_lcd_handles_t handles = {0};
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

  esp_lcd_dsi_bus_handle_t mipi_dsi_bus = NULL;
  esp_lcd_dsi_bus_config_t bus_config = {
      .bus_id = 0,
      .num_data_lanes = BSP_LCD_MIPI_DSI_LANE_NUM,
      .phy_clk_src = MIPI_DSI_PHY_CLK_SRC_DEFAULT,
      .lane_bit_rate_mbps = BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS,
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

  ESP_GOTO_ON_ERROR(bridge_power_on(), err, TAG, "Display MCU power-on failed");
  bridge_configure();

  ESP_LOGI(TAG, "Install DPI panel behind the DSI bridge");
  esp_lcd_dpi_panel_config_t dpi_config = {
      .dpi_clk_src = MIPI_DSI_DPI_CLK_SRC_DEFAULT,
      .dpi_clock_freq_mhz = PICO_DPI_CLK_MHZ,
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
              .hsync_back_porch = PICO_HBP,
              .hsync_pulse_width = PICO_HPW,
              .hsync_front_porch = PICO_HFP,
              .vsync_back_porch = PICO_VBP,
              .vsync_pulse_width = PICO_VPW,
              .vsync_front_porch = PICO_VFP,
          },
  };
  ESP_GOTO_ON_ERROR(
      esp_lcd_new_panel_dpi(mipi_dsi_bus, &dpi_config, &disp_panel), err, TAG,
      "New DPI panel failed");
  ESP_GOTO_ON_ERROR(esp_lcd_dpi_panel_enable_dma2d(disp_panel), err, TAG,
                    "Enable DMA2D failed");
  ESP_GOTO_ON_ERROR(esp_lcd_panel_init(disp_panel), err, TAG,
                    "DPI panel init failed");
  ESP_GOTO_ON_ERROR(bridge_enable(), err, TAG, "Display enable failed");

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

  /* Which touch controller sits on the ribbon depends on the display, not the
     board: GT911 answers at 0x5D or 0x14, the FT5406 on the Raspberry Pi
     display and the FT5x06 on some Waveshare panels at 0x38. */
  esp_lcd_panel_io_i2c_config_t tp_io_config;
  bool gt911 = true;
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
  } else if (bsp_i2c_device_probe(ESP_LCD_TOUCH_IO_I2C_FT5x06_ADDRESS) ==
             ESP_OK) {
    ESP_LOGI(TAG, "FT5x06 found at 0x%02X",
             ESP_LCD_TOUCH_IO_I2C_FT5x06_ADDRESS);
    esp_lcd_panel_io_i2c_config_t cfg = ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG();
    memcpy(&tp_io_config, &cfg, sizeof(cfg));
    gt911 = false;
  } else {
    ESP_LOGE(TAG, "No touch controller found at 0x5D, 0x14 or 0x38");
    return ESP_ERR_NOT_FOUND;
  }
  tp_io_config.scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ;

  esp_lcd_panel_io_handle_t tp_io_handle = NULL;
  ESP_RETURN_ON_ERROR(
      esp_lcd_new_panel_io_i2c(i2c_handle, &tp_io_config, &tp_io_handle), TAG,
      "");

  if (gt911) {
    return esp_lcd_touch_new_i2c_gt911(tp_io_handle, &tp_cfg, ret_touch);
  }
  return esp_lcd_touch_new_i2c_ft5x06(tp_io_handle, &tp_cfg, ret_touch);
}

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
static lv_display_t *bsp_display_lcd_init(void) {
  bsp_lcd_handles_t lcd_panels;
  BSP_ERROR_CHECK_RETURN_NULL(bsp_display_new_with_handles(NULL, &lcd_panels));
  bsp_display_register_sensitive_buffers(
      lcd_panels.panel, CONFIG_BSP_LCD_DPI_BUFFER_NUMS,
      (size_t)BSP_LCD_H_RES * BSP_LCD_V_RES * BSP_LCD_BITS_PER_PIXEL / 8);

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
  // convention). Translate 0 to -1 (portMAX_DELAY).
  int32_t ms = (timeout_ms == 0) ? -1 : (int32_t)timeout_ms;
  return esp_lv_adapter_lock(ms) == ESP_OK;
}

void bsp_display_unlock(void) { esp_lv_adapter_unlock(); }

#endif
