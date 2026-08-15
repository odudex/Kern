#pragma once

#include "driver/i2c_master.h"
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

/* XL9535 driver using the LilyGO IO0..7 and IO10..17 pin numbering. */

/**
 * @brief Attach to an XL9535 and cache its current register state.
 */
esp_err_t xl9535_init(i2c_master_bus_handle_t bus, uint8_t addr);

/** @brief Configure a pin as output (true) or input (false). */
esp_err_t xl9535_set_direction(uint8_t pin, bool output);

/** @brief Drive an output pin high (level != 0) or low. */
esp_err_t xl9535_set_level(uint8_t pin, uint8_t level);
