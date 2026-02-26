// Persistent settings backed by NVS (Non-Volatile Storage)

#include "settings.h"
#include <esp_log.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG = "SETTINGS";
static const char *NVS_NAMESPACE = "settings";
static const char *KEY_DEFAULT_NET = "def_net";
static const char *KEY_DEFAULT_POL = "def_pol";
static const char *KEY_BRIGHTNESS = "bright";

static nvs_handle_t settings_nvs;
static bool initialized = false;

esp_err_t settings_init(void) {
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &settings_nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS namespace: %s", esp_err_to_name(err));
    return err;
  }
  initialized = true;
  return ESP_OK;
}

wallet_network_t settings_get_default_network(void) {
  if (!initialized)
    return WALLET_NETWORK_MAINNET;
  uint8_t val = 0;
  if (nvs_get_u8(settings_nvs, KEY_DEFAULT_NET, &val) != ESP_OK)
    return WALLET_NETWORK_MAINNET;
  return (val <= WALLET_NETWORK_TESTNET) ? (wallet_network_t)val
                                         : WALLET_NETWORK_MAINNET;
}

esp_err_t settings_set_default_network(wallet_network_t network) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  esp_err_t err = nvs_set_u8(settings_nvs, KEY_DEFAULT_NET, (uint8_t)network);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

wallet_policy_t settings_get_default_policy(void) {
  if (!initialized)
    return WALLET_POLICY_SINGLESIG;
  uint8_t val = 0;
  if (nvs_get_u8(settings_nvs, KEY_DEFAULT_POL, &val) != ESP_OK)
    return WALLET_POLICY_SINGLESIG;
  return (val <= WALLET_POLICY_MULTISIG) ? (wallet_policy_t)val
                                         : WALLET_POLICY_SINGLESIG;
}

esp_err_t settings_set_default_policy(wallet_policy_t policy) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  esp_err_t err = nvs_set_u8(settings_nvs, KEY_DEFAULT_POL, (uint8_t)policy);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

uint8_t settings_get_brightness(void) {
  if (!initialized)
    return 50;
  uint8_t val = 50;
  if (nvs_get_u8(settings_nvs, KEY_BRIGHTNESS, &val) != ESP_OK)
    return 50;
  return (val <= 100) ? val : 50;
}

esp_err_t settings_set_brightness(uint8_t brightness) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  if (brightness > 100)
    brightness = 100;
  esp_err_t err = nvs_set_u8(settings_nvs, KEY_BRIGHTNESS, brightness);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

esp_err_t settings_reset_all(void) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  esp_err_t err = nvs_erase_all(settings_nvs);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}
