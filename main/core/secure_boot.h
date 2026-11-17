/*
 * On-device Secure Boot v2 activation (security-plan Phase 6).
 *
 * Burns the three embedded release-key digests into eFuse KEY0-KEY2, the
 * hardening set the stock bootloader burns alongside secure boot, then
 * SECURE_BOOT_EN and the RD_DIS write-protect. Refuses unless the running
 * firmware and the flashed bootloader would both pass the ROM's check under
 * those digests afterwards, and the read-protected PIN keys (KEY4, KEY5) are
 * already sealed. See docs/secure-boot.md section 5a.
 *
 * UI-free. Both entry points block (the status check hashes the running
 * firmware): run them on a worker task.
 */

#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include "../utils/attributes.h"
#include <esp_err.h>
#include <stdbool.h>
#include <stdint.h>

#define SECURE_BOOT_KEY_COUNT 3
#define SECURE_BOOT_DIGEST_LEN 32

typedef enum {
  SECURE_BOOT_OFF,
  SECURE_BOOT_PARTIAL,    /* digests burned, SECURE_BOOT_EN not yet */
  SECURE_BOOT_INCOMPLETE, /* SECURE_BOOT_EN burned, hardening missing */
  SECURE_BOOT_ON,
} secure_boot_state_t;

/* Why OFF or PARTIAL cannot proceed, in the order they are reported */
typedef enum {
  SECURE_BOOT_READY,
  SECURE_BOOT_ERR_BUILD,      /* firmware not built for secure boot */
  SECURE_BOOT_ERR_CHIP,       /* chip revision has no USB reflash once locked */
  SECURE_BOOT_ERR_PIN,        /* no PIN, or KEY4/KEY5 not sealed */
  SECURE_BOOT_ERR_KEY_SLOTS,  /* KEY0-KEY2 hold other data, or revoked */
  SECURE_BOOT_ERR_APP,        /* running firmware not signed by a key */
  SECURE_BOOT_ERR_BOOTLOADER, /* bootloader not signed by every key */
  SECURE_BOOT_ERR_READ,       /* flash read failed */
} secure_boot_check_t;

typedef struct {
  secure_boot_state_t state;
  secure_boot_check_t check;
  /* Burned digests once SECURE_BOOT_EN is set, the embedded ones before */
  uint8_t digests[SECURE_BOOT_KEY_COUNT][SECURE_BOOT_DIGEST_LEN];
  bool revoked[SECURE_BOOT_KEY_COUNT];
  /* eFuse anti-rollback counter: firmware below it does not start */
  uint8_t security_version;
} secure_boot_status_t;

void secure_boot_read_status(secure_boot_status_t *out);

/* Re-runs every check, then burns what is missing. Irreversible; restart
 * afterwards. */
KERN_WARN_UNUSED_RESULT esp_err_t secure_boot_enable(void);

#endif // SECURE_BOOT_H
