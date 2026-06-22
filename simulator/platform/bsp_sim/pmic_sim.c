#include "bsp/pmic.h"

#ifdef BSP_HAS_PMIC

#include <stdio.h>
#include <stdlib.h>

/*
 * Simulated PMIC for boards with battery (wave_35).
 * Pretends a battery is present at 75%, discharging.
 */

static bool pmic_initialized = false;

esp_err_t bsp_pmic_init(void) {
  pmic_initialized = true;
  return ESP_OK;
}

esp_err_t bsp_pmic_power_off(void) {
  fprintf(stderr, "[SIM] bsp_pmic_power_off() called — exiting\n");
  exit(0);
}

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  if (!pmic_initialized)
    return ESP_ERR_INVALID_STATE;
  *pct = 75;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  if (!pmic_initialized)
    return ESP_ERR_INVALID_STATE;
  *mv = 3800;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  if (!pmic_initialized)
    return ESP_ERR_INVALID_STATE;
  *status = BSP_PMIC_CHG_DISCHARGING;
  return ESP_OK;
}

bool bsp_pmic_is_vbus_present(void) { return false; }

bool bsp_pmic_is_available(void) { return pmic_initialized; }

bool bsp_pmic_can_power_off(void) { return pmic_initialized; }

#else /* !BSP_HAS_PMIC */

/* No PMIC on this board — all calls return ESP_ERR_NOT_SUPPORTED / false. */

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

#endif /* BSP_HAS_PMIC */
