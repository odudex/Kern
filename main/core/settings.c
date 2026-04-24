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
static const char *KEY_AE_TARGET = "ae_tgt";
static const char *KEY_FOCUS_POS = "focus";
static const char *KEY_PERMISSIVE_SIGNING = "perm_sign";

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

uint8_t settings_get_ae_target(void) {
  if (!initialized)
    return AE_TARGET_DEFAULT;
  uint8_t val = AE_TARGET_DEFAULT;
  if (nvs_get_u8(settings_nvs, KEY_AE_TARGET, &val) != ESP_OK)
    return AE_TARGET_DEFAULT;
  return (val >= AE_TARGET_MIN && val <= AE_TARGET_MAX) ? val
                                                        : AE_TARGET_DEFAULT;
}

esp_err_t settings_set_ae_target(uint8_t level) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  if (level < AE_TARGET_MIN)
    level = AE_TARGET_MIN;
  if (level > AE_TARGET_MAX)
    level = AE_TARGET_MAX;
  esp_err_t err = nvs_set_u8(settings_nvs, KEY_AE_TARGET, level);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

uint16_t settings_get_focus_position(void) {
  if (!initialized)
    return FOCUS_POSITION_DEFAULT;
  uint16_t val = FOCUS_POSITION_DEFAULT;
  if (nvs_get_u16(settings_nvs, KEY_FOCUS_POS, &val) != ESP_OK)
    return FOCUS_POSITION_DEFAULT;
  return (val <= FOCUS_POSITION_MAX) ? val : FOCUS_POSITION_DEFAULT;
}

esp_err_t settings_set_focus_position(uint16_t position) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  if (position > FOCUS_POSITION_MAX)
    position = FOCUS_POSITION_MAX;
  esp_err_t err = nvs_set_u16(settings_nvs, KEY_FOCUS_POS, position);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

bool settings_get_permissive_signing(void) {
  if (!initialized)
    return false;
  uint8_t val = 0;
  if (nvs_get_u8(settings_nvs, KEY_PERMISSIVE_SIGNING, &val) != ESP_OK)
    return false;
  return val ? true : false;
}

esp_err_t settings_set_permissive_signing(bool permissive) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  uint8_t val = permissive ? 1 : 0;
  esp_err_t err = nvs_set_u8(settings_nvs, KEY_PERMISSIVE_SIGNING, val);
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
