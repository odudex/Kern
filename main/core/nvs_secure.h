// NVS encryption (HMAC scheme, eFuse KEY4)
//
// The stock nvs_flash_init() must never be called: with CONFIG_NVS_ENCRYPTION
// its keygen path burns the eFuse HMAC key without user consent. This module
// is the only NVS initialization entry point — it branches on KEY4 presence,
// not PIN presence (a device may have encrypted NVS with the PIN later
// disabled).

#ifndef NVS_SECURE_H
#define NVS_SECURE_H

#include <esp_err.h>
#include <stdbool.h>

typedef enum {
  NVS_SECURE_KEY_NOT_PROVISIONED,
  NVS_SECURE_KEY_PROVISIONED,
  NVS_SECURE_KEY_ERROR,
} nvs_secure_key_status_t;

/* eFuse KEY4 status check */
nvs_secure_key_status_t nvs_secure_key_check(void);

/* Boot-time NVS init. KEY4 provisioned → encrypted init (a plaintext or
 * corrupt partition is erased and re-initialized encrypted); KEY4 absent →
 * plain init that never touches the eFuse keygen path. */
esp_err_t nvs_secure_init(void);

/* Consent-gated provisioning, called from PIN setup after the user confirms.
 * Burns KEY4 (idempotent), read/write-protects it, then migrates NVS in
 * session: closes pin/settings handles, erases the partition, re-initializes
 * it encrypted, and reopens the handles. Erases all NVS content. */
esp_err_t nvs_secure_provision(void);

/* True once the running session initialized NVS encrypted */
bool nvs_secure_is_encrypted(void);

#endif // NVS_SECURE_H
