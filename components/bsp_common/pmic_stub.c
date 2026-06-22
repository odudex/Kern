#include "bsp/pmic.h"

/* No-op PMIC implementation for boards without a dedicated PMIC chip.
   Boards that have a real PMIC (e.g. wave_35 / AXP2101) provide their
   own implementation of these symbols and this file is excluded from
   the build for those boards (see CMakeLists.txt). */

esp_err_t bsp_pmic_init(void) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t bsp_pmic_power_off(void) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  (void)pct;
  return ESP_ERR_NOT_SUPPORTED;
}
esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  (void)mv;
  return ESP_ERR_NOT_SUPPORTED;
}
esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  (void)status;
  return ESP_ERR_NOT_SUPPORTED;
}
bool bsp_pmic_is_vbus_present(void) { return false; }
bool bsp_pmic_is_available(void) { return false; }
bool bsp_pmic_can_power_off(void) { return false; }
