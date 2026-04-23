// Persistent settings backed by NVS (Non-Volatile Storage)

#ifndef SETTINGS_H
#define SETTINGS_H

#include "wallet.h"
#include <esp_err.h>

#define AE_TARGET_MIN 2
#define AE_TARGET_MAX 235
#define AE_TARGET_DEFAULT 80
#define FOCUS_POSITION_MAX 1023
#define FOCUS_POSITION_DEFAULT 500

esp_err_t settings_init(void);
wallet_network_t settings_get_default_network(void);
esp_err_t settings_set_default_network(wallet_network_t network);
uint8_t settings_get_brightness(void);
esp_err_t settings_set_brightness(uint8_t brightness);
uint8_t settings_get_ae_target(void);
esp_err_t settings_set_ae_target(uint8_t level);
uint16_t settings_get_focus_position(void);
esp_err_t settings_set_focus_position(uint16_t position);
bool settings_get_permissive_signing(void);
esp_err_t settings_set_permissive_signing(bool permissive);
esp_err_t settings_reset_all(void);

#endif // SETTINGS_H
