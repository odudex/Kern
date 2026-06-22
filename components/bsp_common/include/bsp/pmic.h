#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
  BSP_PMIC_CHG_ABSENT,
  BSP_PMIC_CHG_DISCHARGING,
  BSP_PMIC_CHG_CHARGING,
  BSP_PMIC_CHG_FULL,
} bsp_pmic_chg_t;

esp_err_t bsp_pmic_init(void);
esp_err_t bsp_pmic_power_off(void);
esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct);
esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv);
esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status);
bool bsp_pmic_is_vbus_present(void);
bool bsp_pmic_is_available(void);

/* True only if bsp_pmic_power_off() can actually cut power in software.
   A board may have an available PMIC for battery telemetry yet have no
   software power-off (e.g. crowpanel's TP4059 + STC8H, which relies on a
   physical switch). Distinct from bsp_pmic_is_available(). */
bool bsp_pmic_can_power_off(void);
