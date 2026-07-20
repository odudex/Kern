/* Simulator stub for core/fw_update.h — no OTA or signature machinery on
 * the desktop. Validation accepts any readable file and reports a fake
 * candidate version; apply just animates progress. */

#include "../../../main/core/fw_update.h"
#include <esp_app_desc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int fw_update_validate(const char *path, fw_update_info_t *info,
                       const char **err_out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    *err_out = "Cannot open file";
    return -1;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fclose(f);

  if (info) {
    memset(info, 0, sizeof(*info));
    strncpy(info->version, "9.9.9-sim", sizeof(info->version) - 1);
    strncpy(info->current_version, esp_app_get_description()->version,
            sizeof(info->current_version) - 1);
    info->image_size = (size_t)fsize;
  }
  usleep(500 * 1000); /* pretend verification takes a moment */
  return 0;
}

int fw_update_apply(const char *path, fw_update_progress_cb_t progress_cb,
                    void *user_data, const char **err_out) {
  (void)path;
  (void)err_out;
  for (int pct = 0; pct <= 100; pct += 5) {
    if (progress_cb)
      progress_cb(pct, user_data);
    usleep(100 * 1000);
  }
  return 0;
}

void fw_update_boot_confirm(void) {}
