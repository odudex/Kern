// PIN authentication with split-PIN anti-phishing
//
// Uses a separate NVS namespace ("pin") from settings. Device salt is derived
// from the ESP32-P4 HMAC peripheral (eFuse KEY5) so it can't be extracted from
// a flash dump. If the HMAC peripheral is unavailable, falls back to a
// deterministic salt (anti-phishing words are skipped).

#ifndef PIN_H
#define PIN_H

#include <esp_err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PIN_HASH_SIZE 32
#define PIN_MIN_LENGTH 6
#define PIN_MAX_LENGTH 16
#define PIN_DEFAULT_MAX_FAILURES 10
#define PIN_PBKDF2_ITERATIONS 100000

typedef enum {
  PIN_EFUSE_NOT_PROVISIONED,
  PIN_EFUSE_PROVISIONED,
  PIN_EFUSE_ERROR,
} pin_efuse_status_t;

typedef enum {
  PIN_VERIFY_OK,
  PIN_VERIFY_WRONG,
  PIN_VERIFY_DELAY,
  PIN_VERIFY_WIPED,
} pin_verify_result_t;

/* Initialization — opens the "pin" NVS namespace. Safe to call multiple times.
 */
esp_err_t pin_init(void);

/* eFuse KEY5 status check */
pin_efuse_status_t pin_efuse_check(void);

/* Idempotent: generate random key, burn to eFuse KEY5, read-protect.
 * Returns ESP_OK if already provisioned or on success. */
esp_err_t pin_efuse_provision(void);

/* Derive two BIP39 anti-phishing words + identicon data from a PIN prefix
 * via HMAC(KEY5). word1_out / word2_out point into the BIP39 wordlist (do not
 * free). identicon_out (if non-NULL) receives 3 bytes: [0..1] = cell pattern
 * bits, [2] = hue byte. Returns ESP_FAIL if HMAC peripheral unavailable.
 */
esp_err_t pin_compute_anti_phishing(const char *prefix, size_t len,
                                    const char **word1_out,
                                    const char **word2_out,
                                    uint8_t identicon_out[3]);

/* PIN lifecycle */
bool pin_is_configured(void);
esp_err_t pin_setup(const char *pin, size_t len, uint8_t split_pos);
pin_verify_result_t pin_verify(const char *pin, size_t len);
esp_err_t pin_change(const char *new_pin, size_t len, uint8_t split_pos);

/* Remove PIN without wiping user data (for "Disable PIN" in settings) */
esp_err_t pin_remove(void);

/* Config getters/setters */
uint8_t pin_get_split_position(void);
uint32_t pin_get_delay_ms(void);
uint8_t pin_get_fail_count(void);
uint8_t pin_get_max_failures(void);
bool pin_has_anti_phishing(void);
esp_err_t pin_set_max_failures(uint8_t max);

/* Nuclear wipe: erase "pin" NVS + settings + SPIFFS.
 * Called when max failures reached. Device reboots to fresh state. */
esp_err_t pin_wipe_all(void);

#endif // PIN_H
