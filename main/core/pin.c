// PIN authentication with split-PIN anti-phishing

#include "pin.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include "settings.h"
#include "storage.h"

#include <esp_efuse.h>
#include <esp_hmac.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <string.h>
#include <wally_bip39.h>

static const char *TAG = "PIN";

// NVS namespace and keys
static const char *PIN_NVS_NAMESPACE = "pin";
static const char *KEY_PIN_HASH = "pin_hash";
static const char *KEY_SPLIT_POS = "split_pos";
static const char *KEY_FAIL_CNT = "fail_cnt";
static const char *KEY_MAX_FAIL = "max_fail";
static const char *KEY_HAS_EFUSE = "has_efuse";

// Salt derivation tags
static const char *HMAC_SALT_TAG = "C-Krux-PIN-salt-v1";
static const char *FALLBACK_SALT_TAG = "C-Krux-fallback-salt-v1";

static nvs_handle_t pin_nvs;
static bool initialized = false;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Compute device salt via HMAC peripheral or deterministic fallback
static esp_err_t compute_device_salt(uint8_t salt_out[PIN_HASH_SIZE]) {
  uint8_t tag_hash[PIN_HASH_SIZE];
  int rc = crypto_sha256((const uint8_t *)HMAC_SALT_TAG, strlen(HMAC_SALT_TAG),
                         tag_hash);
  if (rc != CRYPTO_OK) {
    secure_memzero(tag_hash, sizeof(tag_hash));
    return ESP_FAIL;
  }

  esp_err_t err =
      esp_hmac_calculate(HMAC_KEY5, tag_hash, sizeof(tag_hash), salt_out);
  secure_memzero(tag_hash, sizeof(tag_hash));

  if (err == ESP_OK)
    return ESP_OK;

  // Fallback: deterministic salt (no eFuse)
  ESP_LOGW(TAG, "HMAC peripheral unavailable, using fallback salt");
  rc = crypto_sha256((const uint8_t *)FALLBACK_SALT_TAG,
                     strlen(FALLBACK_SALT_TAG), salt_out);
  return (rc == CRYPTO_OK) ? ESP_OK : ESP_FAIL;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

esp_err_t pin_init(void) {
  if (initialized)
    return ESP_OK;
  esp_err_t err = nvs_open(PIN_NVS_NAMESPACE, NVS_READWRITE, &pin_nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS namespace: %s", esp_err_to_name(err));
    return err;
  }
  initialized = true;
  return ESP_OK;
}

// ---------------------------------------------------------------------------
// eFuse
// ---------------------------------------------------------------------------

pin_efuse_status_t pin_efuse_check(void) {
  esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(EFUSE_BLK_KEY5);
  if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_UP)
    return PIN_EFUSE_PROVISIONED;
  if (esp_efuse_key_block_unused(EFUSE_BLK_KEY5))
    return PIN_EFUSE_NOT_PROVISIONED;
  return PIN_EFUSE_ERROR; // Block used for something else
}

esp_err_t pin_efuse_provision(void) {
  // Idempotent
  if (pin_efuse_check() == PIN_EFUSE_PROVISIONED)
    return ESP_OK;

  if (!esp_efuse_key_block_unused(EFUSE_BLK_KEY5)) {
    ESP_LOGE(TAG, "eFuse KEY5 already used for another purpose");
    return ESP_ERR_INVALID_STATE;
  }

  // Generate random 256-bit key
  uint8_t key[32];
  crypto_random_bytes(key, sizeof(key));

  esp_err_t err = esp_efuse_write_key(
      EFUSE_BLK_KEY5, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
  secure_memzero(key, sizeof(key));
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to write eFuse key: %s", esp_err_to_name(err));
    return err;
  }

  // Read-protect so key can only be used by HMAC peripheral
  err = esp_efuse_set_key_dis_read(EFUSE_BLK_KEY5);
  if (err != ESP_OK)
    ESP_LOGW(TAG, "Failed to read-protect eFuse key: %s", esp_err_to_name(err));

  // Write-protect so key cannot be modified via flash access
  err = esp_efuse_set_key_dis_write(EFUSE_BLK_KEY5);
  if (err != ESP_OK)
    ESP_LOGW(TAG, "Failed to write-protect eFuse key: %s",
             esp_err_to_name(err));

  // Track in NVS
  if (initialized) {
    nvs_set_u8(pin_nvs, KEY_HAS_EFUSE, 1);
    nvs_commit(pin_nvs);
  }

  return ESP_OK;
}

// ---------------------------------------------------------------------------
// Anti-phishing words
// ---------------------------------------------------------------------------

esp_err_t pin_compute_anti_phishing(const char *prefix, size_t len,
                                    const char **word1_out,
                                    const char **word2_out,
                                    uint8_t identicon_out[3]) {
  if (!prefix || len == 0 || !word1_out || !word2_out)
    return ESP_ERR_INVALID_ARG;

  // SHA256(prefix)
  uint8_t prefix_hash[PIN_HASH_SIZE];
  int rc = crypto_sha256((const uint8_t *)prefix, len, prefix_hash);
  if (rc != CRYPTO_OK) {
    secure_memzero(prefix_hash, sizeof(prefix_hash));
    return ESP_FAIL;
  }

  // HMAC(KEY5, prefix_hash)
  uint8_t hmac_out[32];
  esp_err_t err =
      esp_hmac_calculate(HMAC_KEY5, prefix_hash, sizeof(prefix_hash), hmac_out);
  secure_memzero(prefix_hash, sizeof(prefix_hash));
  if (err != ESP_OK) {
    secure_memzero(hmac_out, sizeof(hmac_out));
    return err;
  }

  // Extract two 11-bit indices from first 3 bytes (22 bits used)
  uint32_t val = ((uint32_t)hmac_out[0] << 16) | ((uint32_t)hmac_out[1] << 8) |
                 hmac_out[2];

  // Extract identicon data from bytes 3-5
  if (identicon_out) {
    identicon_out[0] = hmac_out[3];
    identicon_out[1] = hmac_out[4];
    identicon_out[2] = hmac_out[5];
  }

  secure_memzero(hmac_out, sizeof(hmac_out));

  uint16_t index1 = (val >> 11) & 0x7FF;
  uint16_t index2 = val & 0x7FF;
  val = 0;

  // Look up BIP39 words
  struct words *wordlist = NULL;
  if (bip39_get_wordlist(NULL, &wordlist) != WALLY_OK || !wordlist) {
    index1 = 0;
    index2 = 0;
    return ESP_FAIL;
  }

  *word1_out = bip39_get_word_by_index(wordlist, index1);
  *word2_out = bip39_get_word_by_index(wordlist, index2);
  index1 = 0;
  index2 = 0;

  if (!*word1_out || !*word2_out)
    return ESP_FAIL;

  return ESP_OK;
}

// ---------------------------------------------------------------------------
// PIN lifecycle
// ---------------------------------------------------------------------------

bool pin_is_configured(void) {
  if (!initialized)
    return false;
  uint8_t hash[PIN_HASH_SIZE];
  size_t len = PIN_HASH_SIZE;
  esp_err_t err = nvs_get_blob(pin_nvs, KEY_PIN_HASH, hash, &len);
  secure_memzero(hash, sizeof(hash));
  return (err == ESP_OK && len == PIN_HASH_SIZE);
}

esp_err_t pin_setup(const char *pin, size_t len, uint8_t split_pos) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  if (!pin || len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH)
    return ESP_ERR_INVALID_ARG;
  if (split_pos < 1 || split_pos >= len)
    return ESP_ERR_INVALID_ARG;

  uint8_t salt[PIN_HASH_SIZE];
  esp_err_t err = compute_device_salt(salt);
  if (err != ESP_OK)
    return err;

  uint8_t hash[PIN_HASH_SIZE];
  int rc = crypto_pbkdf2_sha256((const uint8_t *)pin, len, salt, sizeof(salt),
                                PIN_PBKDF2_ITERATIONS, hash, PIN_HASH_SIZE);
  secure_memzero(salt, sizeof(salt));
  if (rc != CRYPTO_OK) {
    secure_memzero(hash, sizeof(hash));
    return ESP_FAIL;
  }

  err = nvs_set_blob(pin_nvs, KEY_PIN_HASH, hash, PIN_HASH_SIZE);
  secure_memzero(hash, sizeof(hash));
  if (err != ESP_OK)
    return err;

  err = nvs_set_u8(pin_nvs, KEY_SPLIT_POS, split_pos);
  if (err != ESP_OK)
    return err;

  // Reset failure count
  nvs_set_u8(pin_nvs, KEY_FAIL_CNT, 0);

  // Set default for max_fail if not already configured
  uint8_t tmp8;
  if (nvs_get_u8(pin_nvs, KEY_MAX_FAIL, &tmp8) != ESP_OK)
    nvs_set_u8(pin_nvs, KEY_MAX_FAIL, PIN_DEFAULT_MAX_FAILURES);

  // Record eFuse availability
  uint8_t has_efuse = (pin_efuse_check() == PIN_EFUSE_PROVISIONED) ? 1 : 0;
  nvs_set_u8(pin_nvs, KEY_HAS_EFUSE, has_efuse);

  return nvs_commit(pin_nvs);
}

pin_verify_result_t pin_verify(const char *pin, size_t len) {
  if (!initialized || !pin || len == 0 || len > PIN_MAX_LENGTH)
    return PIN_VERIFY_WRONG;

  uint8_t fail_cnt = 0;
  nvs_get_u8(pin_nvs, KEY_FAIL_CNT, &fail_cnt);

  uint8_t max_fail = PIN_DEFAULT_MAX_FAILURES;
  nvs_get_u8(pin_nvs, KEY_MAX_FAIL, &max_fail);

  // Pre-increment failure count and commit before the slow PBKDF2 so that
  // a power-cut during verification cannot gift the attacker a free attempt.
  uint8_t pending_cnt = (fail_cnt < 255) ? fail_cnt + 1 : fail_cnt;
  nvs_set_u8(pin_nvs, KEY_FAIL_CNT, pending_cnt);
  nvs_commit(pin_nvs);

  // Always run PBKDF2 to prevent timing oracle at wipe threshold
  uint8_t salt[PIN_HASH_SIZE];
  if (compute_device_salt(salt) != ESP_OK) {
    secure_memzero(salt, sizeof(salt));
    if (pending_cnt >= max_fail) {
      pin_wipe_all();
      return PIN_VERIFY_WIPED; // unreachable
    }
    return PIN_VERIFY_WRONG;
  }

  uint8_t attempt_hash[PIN_HASH_SIZE];
  int rc =
      crypto_pbkdf2_sha256((const uint8_t *)pin, len, salt, sizeof(salt),
                           PIN_PBKDF2_ITERATIONS, attempt_hash, PIN_HASH_SIZE);
  secure_memzero(salt, sizeof(salt));
  if (rc != CRYPTO_OK) {
    secure_memzero(attempt_hash, sizeof(attempt_hash));
    if (pending_cnt >= max_fail) {
      pin_wipe_all();
      return PIN_VERIFY_WIPED; // unreachable
    }
    return PIN_VERIFY_WRONG;
  }

  // Check wipe threshold after PBKDF2 (uniform timing)
  if (pending_cnt >= max_fail) {
    secure_memzero(attempt_hash, sizeof(attempt_hash));
    ESP_LOGW(TAG, "Max failures reached (%u/%u), wiping device", pending_cnt,
             max_fail);
    pin_wipe_all();
    return PIN_VERIFY_WIPED; // unreachable
  }

  // Load stored hash
  uint8_t stored_hash[PIN_HASH_SIZE];
  size_t hash_len = PIN_HASH_SIZE;
  esp_err_t err = nvs_get_blob(pin_nvs, KEY_PIN_HASH, stored_hash, &hash_len);
  if (err != ESP_OK || hash_len != PIN_HASH_SIZE) {
    secure_memzero(attempt_hash, sizeof(attempt_hash));
    secure_memzero(stored_hash, sizeof(stored_hash));
    return PIN_VERIFY_WRONG;
  }

  // Constant-time comparison
  int match = secure_memcmp(attempt_hash, stored_hash, PIN_HASH_SIZE);
  secure_memzero(attempt_hash, sizeof(attempt_hash));
  secure_memzero(stored_hash, sizeof(stored_hash));

  if (match == 0) {
    // Correct PIN — roll back the pre-incremented failure count
    nvs_set_u8(pin_nvs, KEY_FAIL_CNT, 0);
    nvs_commit(pin_nvs);
    return PIN_VERIFY_OK;
  }

  // Wrong PIN — failure count was already persisted above
  return PIN_VERIFY_DELAY;
}

esp_err_t pin_change(const char *new_pin, size_t len, uint8_t split_pos) {
  // Caller must verify old PIN first via pin_verify()
  return pin_setup(new_pin, len, split_pos);
}

esp_err_t pin_remove(void) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  esp_err_t err = nvs_erase_all(pin_nvs);
  if (err != ESP_OK)
    return err;
  return nvs_commit(pin_nvs);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

uint8_t pin_get_split_position(void) {
  if (!initialized)
    return 1;
  uint8_t pos = 1;
  nvs_get_u8(pin_nvs, KEY_SPLIT_POS, &pos);
  return pos;
}

uint32_t pin_get_delay_ms(void) {
  if (!initialized)
    return 0;
  uint8_t fail_cnt = 0;
  nvs_get_u8(pin_nvs, KEY_FAIL_CNT, &fail_cnt);
  if (fail_cnt == 0)
    return 0;
  // 2^fail_cnt seconds, capped at 32768s
  uint32_t exp = (fail_cnt > 15) ? 15 : fail_cnt;
  return (1u << exp) * 1000;
}

uint8_t pin_get_fail_count(void) {
  if (!initialized)
    return 0;
  uint8_t val = 0;
  nvs_get_u8(pin_nvs, KEY_FAIL_CNT, &val);
  return val;
}

uint8_t pin_get_max_failures(void) {
  if (!initialized)
    return PIN_DEFAULT_MAX_FAILURES;
  uint8_t val = PIN_DEFAULT_MAX_FAILURES;
  nvs_get_u8(pin_nvs, KEY_MAX_FAIL, &val);
  return val;
}

bool pin_has_anti_phishing(void) {
  if (!initialized)
    return false;
  uint8_t val = 0;
  nvs_get_u8(pin_nvs, KEY_HAS_EFUSE, &val);
  return val != 0;
}

esp_err_t pin_set_max_failures(uint8_t max) {
  if (!initialized)
    return ESP_ERR_INVALID_STATE;
  if (max < 5 || max > 50)
    return ESP_ERR_INVALID_ARG;
  esp_err_t err = nvs_set_u8(pin_nvs, KEY_MAX_FAIL, max);
  if (err != ESP_OK)
    return err;
  return nvs_commit(pin_nvs);
}

// ---------------------------------------------------------------------------
// Wipe
// ---------------------------------------------------------------------------

esp_err_t pin_wipe_all(void) {
  ESP_LOGW(TAG, "Wiping all data");

  // Erase PIN NVS namespace
  if (initialized) {
    nvs_erase_all(pin_nvs);
    nvs_commit(pin_nvs);
  }

  // Reset settings
  settings_reset_all();

  // Wipe flash storage
  storage_init(); // Ensure SPIFFS is mounted
  storage_wipe_flash();

  esp_restart();
  return ESP_OK; // unreachable
}
