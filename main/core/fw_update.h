/*
 * Firmware update from SD card (security-plan Phase 4).
 *
 * Pre-flight validation reads the candidate image straight from the SD file
 * and rejects bad images before the OTA slot is touched: image header and
 * chip id, app descriptor (project name, version, secure_version downgrade
 * check), and full Secure Boot v2 RSA-3072 signature verification against
 * the keys trusted by the running app.
 *
 * UI-free: progress is reported through a callback; both entry points block
 * and must run on a worker task, not the LVGL task.
 */

#ifndef FW_UPDATE_H
#define FW_UPDATE_H

#include <stddef.h>
#include <stdint.h>

#define FW_UPDATE_VERSION_LEN 32

typedef struct {
  char version[FW_UPDATE_VERSION_LEN];         /* candidate app version */
  char current_version[FW_UPDATE_VERSION_LEN]; /* running app version */
  uint32_t secure_version;
  size_t image_size; /* whole file, signature sector included */
} fw_update_info_t;

/* percent is 0-100; called from the worker task context. */
typedef void (*fw_update_progress_cb_t)(int percent, void *user_data);

/* Validate the image at path without writing anything. On success fills
 * *info and returns 0; on failure returns -1 and *err_out points to a
 * static human-readable reason. */
int fw_update_validate(const char *path, fw_update_info_t *info,
                       const char **err_out);

/* Stream the image at path into the inactive OTA slot, verify it and set
 * it as the boot partition. Returns 0 on success (caller reboots); on
 * failure returns -1 with *err_out set and the current firmware untouched. */
int fw_update_apply(const char *path, fw_update_progress_cb_t progress_cb,
                    void *user_data, const char **err_out);

/* Boot-time self-test confirmation: if the running image is pending
 * verification after an update, mark it valid so the bootloader does not
 * roll back to the previous slot. Call once the app is fully up. */
void fw_update_boot_confirm(void);

#endif // FW_UPDATE_H
