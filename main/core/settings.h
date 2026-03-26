// Persistent settings backed by NVS (Non-Volatile Storage)

#ifndef SETTINGS_H
#define SETTINGS_H

#include "wallet.h"
#include <esp_err.h>

esp_err_t settings_init(void);
wallet_network_t settings_get_default_network(void);
esp_err_t settings_set_default_network(wallet_network_t network);
wallet_policy_t settings_get_default_policy(void);
esp_err_t settings_set_default_policy(wallet_policy_t policy);
uint8_t settings_get_brightness(void);
esp_err_t settings_set_brightness(uint8_t brightness);
uint8_t settings_get_rotation(void);
esp_err_t settings_set_rotation(uint8_t rotation);
esp_err_t settings_reset_all(void);

#endif // SETTINGS_H
