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

/* Display and touch reset are routed through the XL9535. */
#define BSP_LCD_RST (GPIO_NUM_NC)
#define BSP_LCD_TOUCH_RST (GPIO_NUM_NC)
#define BSP_LCD_TOUCH_INT (GPIO_NUM_NC)

/* AMOLED brightness uses DCS 0x51. */
#define BSP_LCD_BACKLIGHT (GPIO_NUM_NC)

/* Camera SCCB uses the dedicated Port2 bus. */
#define BSP_CAM_I2C_SCL BSP_I2C_SCL
#define BSP_CAM_I2C_SDA BSP_I2C_SDA
#define BSP_CAM_I2C_SCL_ALT (GPIO_NUM_21)
#define BSP_CAM_I2C_SDA_ALT (GPIO_NUM_20)
#define BSP_CAM_HAS_MOTOR 0

/**************************************************************************************************
 *  XL9535 GPIO expander
 **************************************************************************************************/
#define BSP_XL9535_I2C_ADDR (0x20)
#define BSP_XL9535_PWR_EN_3V3 (0)  /* IO0  : peripheral 3V3 rail enable */
#define BSP_XL9535_SCREEN_RST (2)  /* IO2  : display panel reset */
#define BSP_XL9535_TOUCH_RST (3)   /* IO3  : GT9895 reset */
#define BSP_XL9535_TOUCH_INT (4)   /* IO4  : GT9895 interrupt */
#define BSP_XL9535_USB_PWR_EN (10) /* IO10 : USB PHY power enable */
#define BSP_XL9535_C6_EN (14)      /* IO14 : ESP32-C6 CHIP_EN (air-gap) */
#define BSP_XL9535_SD_PWR_EN (15)  /* IO15 : SD card power enable */

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
 * Camera power
 *
 **************************************************************************************************/

esp_err_t bsp_camera_power_init(i2c_master_bus_handle_t i2c_bus);

/**************************************************************************************************
 *
 * Wireless co-processor
 *
 **************************************************************************************************/

/**
 * @brief Hold the ESP32-C6 in reset (CHIP_EN low) so its radio stays off. Call
 * once, early at boot. On this board CHIP_EN is behind the XL9535 expander, so
 * this brings up the I2C bus and the expander first.
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
