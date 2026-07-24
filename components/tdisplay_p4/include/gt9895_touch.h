#pragma once

#include "driver/i2c_master.h"
#include "esp_lcd_touch.h"

/* The GT9895 uses 32-bit big-endian register addressing. */

/**
 * @brief Create a GT9895 touch handle.
 *
 * @param bus    I2C master bus.
 * @param config Touch configuration.
 * @param out    Resulting touch handle.
 */
esp_err_t gt9895_touch_new(i2c_master_bus_handle_t bus,
                           const esp_lcd_touch_config_t *config,
                           esp_lcd_touch_handle_t *out);
