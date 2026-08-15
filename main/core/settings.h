// Persistent settings backed by NVS (Non-Volatile Storage)

#ifndef SETTINGS_H
#define SETTINGS_H

#include "../utils/attributes.h"
#include "wallet.h"
#include <esp_err.h>

#define BRIGHTNESS_MIN 10
#define AE_TARGET_MIN 2
#define AE_TARGET_MAX 235
#define AE_TARGET_DEFAULT 80
#define FOCUS_POSITION_MAX 1023
#define FOCUS_POSITION_DEFAULT 500
#define QR_DENSITY_MIN 100
#define QR_DENSITY_MAX 600
#define QR_DENSITY_DEFAULT 400
#define QR_SHADE_MIN 30
#define QR_SHADE_MAX 100
#define QR_SHADE_DEFAULT 100
#define QR_FPS_MIN 1
#define QR_FPS_MAX 5
#define QR_FPS_DEFAULT 4
#define SCREENSAVER_TIMEOUT_DEFAULT_SEC 120
#define SESSION_TIMEOUT_DEFAULT_SEC 300
#define SETTINGS_VERSION_MAX 32

KERN_WARN_UNUSED_RESULT esp_err_t settings_init(void);

/* Close the settings NVS handle (required before nvs_flash_deinit) */
void settings_deinit(void);

/* The settings_set_* family deliberately carries no KERN_WARN_UNUSED_RESULT:
 * these persist a preference the caller has already applied in this session,
 * and no caller can do anything useful about a failed write. settings.c logs
 * every failure with the key that could not be stored. Functions whose result
 * a caller must act on - init and reset_all - do carry it. */
wallet_network_t settings_get_network(void);
esp_err_t settings_set_network(wallet_network_t network);
KERN_WARN_UNUSED_RESULT uint8_t settings_get_brightness(void);
esp_err_t settings_set_brightness(uint8_t brightness);
KERN_WARN_UNUSED_RESULT uint8_t settings_get_ae_target(void);
esp_err_t settings_set_ae_target(uint8_t level);
KERN_WARN_UNUSED_RESULT uint16_t settings_get_focus_position(void);
esp_err_t settings_set_focus_position(uint16_t position);
KERN_WARN_UNUSED_RESULT uint16_t settings_get_qr_density(void);
esp_err_t settings_set_qr_density(uint16_t chars_per_frame);
KERN_WARN_UNUSED_RESULT uint8_t settings_get_qr_shade(void);
esp_err_t settings_set_qr_shade(uint8_t shade);
KERN_WARN_UNUSED_RESULT uint8_t settings_get_qr_fps(void);
esp_err_t settings_set_qr_fps(uint8_t fps);
KERN_WARN_UNUSED_RESULT bool settings_get_permissive_signing(void);
esp_err_t settings_set_permissive_signing(bool permissive);
KERN_WARN_UNUSED_RESULT bool settings_get_partial_signing(void);
esp_err_t settings_set_partial_signing(bool partial);
KERN_WARN_UNUSED_RESULT bool settings_get_expected_owned_signing(void);
esp_err_t settings_set_expected_owned_signing(bool enabled);
KERN_WARN_UNUSED_RESULT uint16_t settings_get_screensaver_timeout(void);
esp_err_t settings_set_screensaver_timeout(uint16_t sec);
KERN_WARN_UNUSED_RESULT uint16_t settings_get_session_timeout(void);
esp_err_t settings_set_session_timeout(uint16_t sec);
KERN_WARN_UNUSED_RESULT bool
settings_disclaimer_acknowledged(const char *version);
esp_err_t settings_acknowledge_disclaimer(const char *version);
KERN_WARN_UNUSED_RESULT esp_err_t settings_reset_all(void);

#endif // SETTINGS_H
