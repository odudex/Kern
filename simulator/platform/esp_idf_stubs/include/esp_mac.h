#ifndef ESP_MAC_H
#define ESP_MAC_H

#include "esp_err.h"
#include <stdint.h>

// Host stub: no eFuse, so the simulator hands back a fixed base MAC.
esp_err_t esp_efuse_mac_get_default(uint8_t *mac);

#endif // ESP_MAC_H
