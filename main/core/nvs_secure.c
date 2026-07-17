// NVS encryption (HMAC scheme, eFuse KEY4)

#include "nvs_secure.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include "pin.h"
#include "settings.h"

#include <esp_efuse.h>
#include <esp_log.h>
#include <nvs_flash.h>

static const char *TAG = "NVS_SECURE";

static bool encrypted = false;

nvs_secure_key_status_t nvs_secure_key_check(void) {
  esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(EFUSE_BLK_KEY4);
  if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP)
    return NVS_SECURE_KEY_PROVISIONED;
  if (esp_efuse_key_block_unused(EFUSE_BLK_KEY4))
    return NVS_SECURE_KEY_NOT_PROVISIONED;
  return NVS_SECURE_KEY_ERROR; // Block used for something else
}

bool nvs_secure_is_encrypted(void) { return encrypted; }

// Derive keys from KEY4 via the HMAC peripheral (no eFuse burn) and init the
// default partition encrypted. Erase + retry only on errors that identify an
// unmigrated/incompatible partition (e.g. plaintext left behind by an
// interrupted provisioning); transient errors (no-mem, flash driver) must
// propagate without destroying valid encrypted data.
static esp_err_t secure_init_default(void) {
  nvs_sec_cfg_t cfg;
  esp_err_t err = nvs_flash_read_security_cfg_v2(
      nvs_flash_get_default_security_scheme(), &cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to derive NVS keys: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_flash_secure_init(&cfg);
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_LOGW(TAG, "Encrypted NVS init failed (%s), erasing partition",
             esp_err_to_name(err));
    nvs_flash_erase();
    err = nvs_flash_secure_init(&cfg);
  }
  secure_memzero(&cfg, sizeof(cfg));

  if (err == ESP_OK)
    encrypted = true;
  else
    ESP_LOGE(TAG, "Encrypted NVS init failed: %s", esp_err_to_name(err));
  return err;
}

esp_err_t nvs_secure_init(void) {
  if (nvs_secure_key_check() == NVS_SECURE_KEY_PROVISIONED)
    return secure_init_default();

  esp_err_t err = nvs_flash_init_partition(NVS_DEFAULT_PART_NAME);
  if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
      err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    err = nvs_flash_init_partition(NVS_DEFAULT_PART_NAME);
  }
  return err;
}

esp_err_t nvs_secure_provision(void) {
  nvs_secure_key_status_t status = nvs_secure_key_check();
  if (status == NVS_SECURE_KEY_ERROR) {
    ESP_LOGE(TAG, "eFuse KEY4 already used for another purpose");
    return ESP_ERR_INVALID_STATE;
  }

  if (status == NVS_SECURE_KEY_NOT_PROVISIONED) {
    uint8_t key[32];
    crypto_random_bytes(key, sizeof(key));

    esp_err_t err = esp_efuse_write_key(
        EFUSE_BLK_KEY4, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
    secure_memzero(key, sizeof(key));
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write eFuse key: %s", esp_err_to_name(err));
      return err;
    }

    // Read-protect so the key can only be used by the HMAC peripheral
    err = esp_efuse_set_key_dis_read(EFUSE_BLK_KEY4);
    if (err != ESP_OK)
      ESP_LOGW(TAG, "Failed to read-protect eFuse key: %s",
               esp_err_to_name(err));

    err = esp_efuse_set_key_dis_write(EFUSE_BLK_KEY4);
    if (err != ESP_OK)
      ESP_LOGW(TAG, "Failed to write-protect eFuse key: %s",
               esp_err_to_name(err));
  }

  if (encrypted)
    return ESP_OK;

  // Migrate in session: all NVS handle owners must be closed before deinit.
  // If power is cut anywhere past this point, nvs_secure_init() finishes the
  // migration on next boot (KEY4 present → erase plaintext → encrypted init).
  pin_deinit();
  settings_deinit();
  nvs_flash_deinit();
  nvs_flash_erase();

  esp_err_t err = secure_init_default();
  if (err != ESP_OK)
    return err;

  settings_init();
  pin_init();
  return ESP_OK;
}
