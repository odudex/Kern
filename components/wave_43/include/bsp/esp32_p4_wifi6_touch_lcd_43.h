#pragma once

#include "bsp/config.h"
#include "bsp/display.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "sdkconfig.h"

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
#include "esp_lv_adapter.h"
#include "lvgl.h"
#endif

/**************************************************************************************************
 *  BSP Capabilities
 **************************************************************************************************/

#define BSP_CAPS_DISPLAY 1
#define BSP_CAPS_TOUCH 1
#define BSP_CAPS_BUTTONS 0
#define BSP_CAPS_AUDIO 0
#define BSP_CAPS_AUDIO_SPEAKER 0
#define BSP_CAPS_AUDIO_MIC 0
#define BSP_CAPS_SDCARD 0
#define BSP_CAPS_IMU 0

/**************************************************************************************************
 *  Pinout
 **************************************************************************************************/
/* I2C */
#define BSP_I2C_SCL (GPIO_NUM_8)
#define BSP_I2C_SDA (GPIO_NUM_7)

#define BSP_LCD_BACKLIGHT (GPIO_NUM_26)
#define BSP_LCD_RST (GPIO_NUM_27)
#define BSP_LCD_TOUCH_RST (GPIO_NUM_NC)
#define BSP_LCD_TOUCH_INT (GPIO_NUM_NC)

/* Wi-Fi 6 / BT co-processor (ESP32-C6).
   The C6 provides wireless via ESP-Hosted over SDIO; its active-high CHIP_EN
   line is driven by P4 GPIO54 (through R34, 0R — see board schematic). Kern is
   an air-gapped signer and never brings up the ESP-Hosted host, so we hold the
   C6 in reset (EN low) to keep its radio powered down. */
#define BSP_C6_WIFI_EN (GPIO_NUM_54)

/* Camera I2C (shares main I2C bus on this board) */
#define BSP_CAM_I2C_SCL BSP_I2C_SCL
#define BSP_CAM_I2C_SDA BSP_I2C_SDA
#define BSP_CAM_HAS_MOTOR 0

/**************************************************************************************************
 *
 * I2C interface
 *
 **************************************************************************************************/
#define BSP_I2C_NUM CONFIG_BSP_I2C_NUM

esp_err_t bsp_i2c_init(void);
esp_err_t bsp_i2c_deinit(void);
i2c_master_bus_handle_t bsp_i2c_get_handle(void);

/**************************************************************************************************
 *
 * Wireless co-processor
 *
 **************************************************************************************************/

/**
 * @brief Hold the Wi-Fi/BT co-processor (ESP32-C6) in reset.
 *
 * Configures BSP_C6_WIFI_EN as an output and drives it low, keeping the C6
 * powered down so its radio cannot be brought up. Intended to be called once,
 * as early as possible during boot. Note: this is a runtime measure enforced by
 * the P4 firmware; it does not modify the C6's own flash.
 *
 * @return ESP_OK on success, or a gpio driver error code.
 */
esp_err_t bsp_wifi_coproc_disable(void);

/**************************************************************************************************
 *
 * LCD interface
 *
 **************************************************************************************************/

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)

lv_display_t *bsp_display_start(void);

/**
 * @brief Take LVGL mutex
 *
 * @param[in] timeout_ms Timeout in [ms]. 0 will block indefinitely.
 * @return true  Mutex was taken
 * @return false Mutex was NOT taken
 */
bool bsp_display_lock(uint32_t timeout_ms);

/**
 * @brief Give LVGL mutex
 */
void bsp_display_unlock(void);

#endif
