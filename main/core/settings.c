// Persistent settings backed by NVS (Non-Volatile Storage)

#include "settings.h"
#include <esp_log.h>
#include <nvs.h>
#include <nvs_flash.h>

static const char *TAG = "SETTINGS";
static const char *NVS_NAMESPACE = "settings";
/* Key name predates the removal of the "default wallet" settings page;
 * kept as "def_net" so existing devices retain their network choice. */
static const char *KEY_NETWORK = "def_net";
static const char *KEY_BRIGHTNESS = "bright";
static const char *KEY_AE_TARGET = "ae_tgt";
static const char *KEY_FOCUS_POS = "focus";
static const char *KEY_QR_DENSITY = "qr_dens";
static const char *KEY_QR_SHADE = "qr_shade";
static const char *KEY_QR_FPS = "qr_fps";
static const char *KEY_PERMISSIVE_SIGNING = "perm_sign";
static const char *KEY_PARTIAL_SIGNING = "part_sign";
static const char *KEY_EXPECTED_OWNED_SIGNING = "exp_own_sign";
static const char *KEY_SCREENSAVER = "scrn_svr";
static const char *KEY_SESSION_TIMEOUT = "sess_tout";

static nvs_handle_t settings_nvs;
static bool initialized = false;

static uint8_t settings_get_u8_or_default(const char *key,
                                          uint8_t default_value) {
  if (!initialized)
    return default_value;

  uint8_t value = default_value;
  if (nvs_get_u8(settings_nvs, key, &value) != ESP_OK)
    return default_value;
  return value;
}

static uint16_t settings_get_u16_or_default(const char *key,
                                            uint16_t default_value) {
  if (!initialized)
    return default_value;

  uint16_t value = default_value;
  if (nvs_get_u16(settings_nvs, key, &value) != ESP_OK)
    return default_value;
  return value;
}

static bool settings_get_bool_or_default(const char *key, bool default_value) {
  return settings_get_u8_or_default(key, default_value ? 1 : 0) != 0;
}

static esp_err_t settings_set_u8_and_commit(const char *key, uint8_t value) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;

  esp_err_t err = nvs_set_u8(settings_nvs, key, value);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

static esp_err_t settings_set_u16_and_commit(const char *key, uint16_t value) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;

  esp_err_t err = nvs_set_u16(settings_nvs, key, value);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}

static esp_err_t settings_set_bool_and_commit(const char *key, bool value) {
  return settings_set_u8_and_commit(key, value ? 1 : 0);
}

esp_err_t settings_init(void) {
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &settings_nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS namespace: %s", esp_err_to_name(err));
    return err;
  }
  initialized = true;

  /* Drop legacy "def_pol" (default wallet policy) key — superseded by the
   * per-state permissive/partial/expected-owned toggles. Inert if absent. */
  esp_err_t mig = nvs_erase_key(settings_nvs, "def_pol");
  if (mig == ESP_OK) {
    ESP_LOGI(TAG, "migrated: erased legacy 'def_pol' key");
    nvs_commit(settings_nvs);
  } else if (mig != ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGW(TAG, "migration: erase 'def_pol' returned %s",
             esp_err_to_name(mig));
  }

  return ESP_OK;
}

wallet_network_t settings_get_network(void) {
  uint8_t val = settings_get_u8_or_default(KEY_NETWORK, WALLET_NETWORK_MAINNET);
  return (val <= WALLET_NETWORK_TESTNET) ? (wallet_network_t)val
                                         : WALLET_NETWORK_MAINNET;
}

esp_err_t settings_set_network(wallet_network_t network) {
  return settings_set_u8_and_commit(KEY_NETWORK, (uint8_t)network);
}

uint8_t settings_get_brightness(void) {
  uint8_t val = settings_get_u8_or_default(KEY_BRIGHTNESS, 50);
  return (val >= BRIGHTNESS_MIN && val <= 100) ? val : 50;
}

esp_err_t settings_set_brightness(uint8_t brightness) {
  if (brightness < BRIGHTNESS_MIN)
    brightness = BRIGHTNESS_MIN;
  if (brightness > 100)
    brightness = 100;
  return settings_set_u8_and_commit(KEY_BRIGHTNESS, brightness);
}

uint8_t settings_get_ae_target(void) {
  uint8_t val = settings_get_u8_or_default(KEY_AE_TARGET, AE_TARGET_DEFAULT);
  return (val >= AE_TARGET_MIN && val <= AE_TARGET_MAX) ? val
                                                        : AE_TARGET_DEFAULT;
}

esp_err_t settings_set_ae_target(uint8_t level) {
  if (level < AE_TARGET_MIN)
    level = AE_TARGET_MIN;
  if (level > AE_TARGET_MAX)
    level = AE_TARGET_MAX;
  return settings_set_u8_and_commit(KEY_AE_TARGET, level);
}

uint16_t settings_get_focus_position(void) {
  uint16_t val =
      settings_get_u16_or_default(KEY_FOCUS_POS, FOCUS_POSITION_DEFAULT);
  return (val <= FOCUS_POSITION_MAX) ? val : FOCUS_POSITION_DEFAULT;
}

esp_err_t settings_set_focus_position(uint16_t position) {
  if (position > FOCUS_POSITION_MAX)
    position = FOCUS_POSITION_MAX;
  return settings_set_u16_and_commit(KEY_FOCUS_POS, position);
}

uint16_t settings_get_qr_density(void) {
  uint16_t val =
      settings_get_u16_or_default(KEY_QR_DENSITY, QR_DENSITY_DEFAULT);
  return (val >= QR_DENSITY_MIN && val <= QR_DENSITY_MAX) ? val
                                                          : QR_DENSITY_DEFAULT;
}

esp_err_t settings_set_qr_density(uint16_t chars_per_frame) {
  if (chars_per_frame < QR_DENSITY_MIN)
    chars_per_frame = QR_DENSITY_MIN;
  if (chars_per_frame > QR_DENSITY_MAX)
    chars_per_frame = QR_DENSITY_MAX;
  return settings_set_u16_and_commit(KEY_QR_DENSITY, chars_per_frame);
}

uint8_t settings_get_qr_shade(void) {
  uint8_t val = settings_get_u8_or_default(KEY_QR_SHADE, QR_SHADE_DEFAULT);
  return (val >= QR_SHADE_MIN && val <= QR_SHADE_MAX) ? val : QR_SHADE_DEFAULT;
}

esp_err_t settings_set_qr_shade(uint8_t shade) {
  if (shade < QR_SHADE_MIN)
    shade = QR_SHADE_MIN;
  if (shade > QR_SHADE_MAX)
    shade = QR_SHADE_MAX;
  return settings_set_u8_and_commit(KEY_QR_SHADE, shade);
}

uint8_t settings_get_qr_fps(void) {
  uint8_t val = settings_get_u8_or_default(KEY_QR_FPS, QR_FPS_DEFAULT);
  return (val >= QR_FPS_MIN && val <= QR_FPS_MAX) ? val : QR_FPS_DEFAULT;
}

esp_err_t settings_set_qr_fps(uint8_t fps) {
  if (fps < QR_FPS_MIN)
    fps = QR_FPS_MIN;
  if (fps > QR_FPS_MAX)
    fps = QR_FPS_MAX;
  return settings_set_u8_and_commit(KEY_QR_FPS, fps);
}

bool settings_get_permissive_signing(void) {
  return settings_get_bool_or_default(KEY_PERMISSIVE_SIGNING, false);
}

esp_err_t settings_set_permissive_signing(bool permissive) {
  return settings_set_bool_and_commit(KEY_PERMISSIVE_SIGNING, permissive);
}

bool settings_get_partial_signing(void) {
  return settings_get_bool_or_default(KEY_PARTIAL_SIGNING, false);
}

esp_err_t settings_set_partial_signing(bool partial) {
  return settings_set_bool_and_commit(KEY_PARTIAL_SIGNING, partial);
}

bool settings_get_expected_owned_signing(void) {
  return settings_get_bool_or_default(KEY_EXPECTED_OWNED_SIGNING, false);
}

esp_err_t settings_set_expected_owned_signing(bool enabled) {
  return settings_set_bool_and_commit(KEY_EXPECTED_OWNED_SIGNING, enabled);
}

uint16_t settings_get_screensaver_timeout(void) {
  return settings_get_u16_or_default(KEY_SCREENSAVER,
                                     SCREENSAVER_TIMEOUT_DEFAULT_SEC);
}

esp_err_t settings_set_screensaver_timeout(uint16_t sec) {
  return settings_set_u16_and_commit(KEY_SCREENSAVER, sec);
}

uint16_t settings_get_session_timeout(void) {
  return settings_get_u16_or_default(KEY_SESSION_TIMEOUT,
                                     SESSION_TIMEOUT_DEFAULT_SEC);
}

esp_err_t settings_set_session_timeout(uint16_t sec) {
  return settings_set_u16_and_commit(KEY_SESSION_TIMEOUT, sec);
}

esp_err_t settings_reset_all(void) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  esp_err_t err = nvs_erase_all(settings_nvs);
  if (err != ESP_OK)
    return err;
  return nvs_commit(settings_nvs);
}
