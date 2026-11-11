#include "esp_log.h"
#include "esp_secure_boot.h"

esp_err_t __real_esp_secure_boot_v2_permanently_enable(
    const esp_image_metadata_t *image_data);

/* Called on every boot before the app loads. The app has already been
 * verified against its own keys (or the burned digests once they exist); only
 * the first-boot burn is skipped. */
esp_err_t __wrap_esp_secure_boot_v2_permanently_enable(
    const esp_image_metadata_t *image_data) {
  if (!esp_secure_boot_enabled()) {
    ESP_LOGI("secure_boot", "Off until enabled in Settings");
    return ESP_OK;
  }
  return __real_esp_secure_boot_v2_permanently_enable(image_data);
}
