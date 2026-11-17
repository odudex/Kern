/* Simulator stand-in for core/secure_boot.c: no eFuses or signed images on
 * the desktop. Starts off and ready once a PIN is set; a finished lockdown
 * persists in <data-dir>/secure_boot.sim, which `just sim-reset` removes.
 *
 * KERN_SIM_SECURE_BOOT previews the other screens:
 *   ready                                           ready without a PIN
 *   build | chip | pin | slots | app | bootloader | read
 *                                                   blocked, with that reason
 *   partial | incomplete                            interrupted lockdown
 *   fail                                            the burn reports failure
 */

#include "../../../main/core/secure_boot.h"
#include "../../../main/core/pin.h"
#include "kern_sb_digests.h"
#include "sim_nvs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *mode(void) {
  const char *m = getenv("KERN_SIM_SECURE_BOOT");
  return m ? m : "";
}

static void state_path(char *buf, size_t n) {
  snprintf(buf, n, "%s/secure_boot.sim", sim_nvs_get_data_dir());
}

static bool locked(void) {
  char path[512];
  state_path(path, sizeof(path));
  return access(path, F_OK) == 0;
}

void secure_boot_read_status(secure_boot_status_t *out) {
  static const struct {
    const char *name;
    secure_boot_check_t check;
  } blocked[] = {
      {"build", SECURE_BOOT_ERR_BUILD},
      {"chip", SECURE_BOOT_ERR_CHIP},
      {"pin", SECURE_BOOT_ERR_PIN},
      {"slots", SECURE_BOOT_ERR_KEY_SLOTS},
      {"app", SECURE_BOOT_ERR_APP},
      {"bootloader", SECURE_BOOT_ERR_BOOTLOADER},
      {"read", SECURE_BOOT_ERR_READ},
  };

  memset(out, 0, sizeof(*out));
  memcpy(out->digests, KERN_SB_DIGESTS, sizeof(out->digests));
  usleep(300 * 1000); /* the device hashes the running firmware */

  if (locked()) {
    out->state = SECURE_BOOT_ON;
    return;
  }
  if (strcmp(mode(), "incomplete") == 0) {
    out->state = SECURE_BOOT_INCOMPLETE;
    return;
  }
  out->state =
      strcmp(mode(), "partial") == 0 ? SECURE_BOOT_PARTIAL : SECURE_BOOT_OFF;
  out->check = pin_is_configured() || strcmp(mode(), "ready") == 0
                   ? SECURE_BOOT_READY
                   : SECURE_BOOT_ERR_PIN;
  for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++)
    if (strcmp(mode(), blocked[i].name) == 0)
      out->check = blocked[i].check;
}

esp_err_t secure_boot_enable(void) {
  usleep(1000 * 1000);
  if (strcmp(mode(), "fail") == 0)
    return ESP_FAIL;
  char path[512];
  state_path(path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f)
    return ESP_FAIL;
  fputs("on\n", f);
  fclose(f);
  return ESP_OK;
}
