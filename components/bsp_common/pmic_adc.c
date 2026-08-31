/* Battery sense for boards with no PMIC. Voltage is not a state of charge, so
   only bsp_pmic_get_battery_mv() is implemented, for a low battery warning. */

#include "bsp/pmic.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_check.h"

/* BAT --[R12 200k]-- BAT_ADC --[R15 100k]-- GND on GPIO20, ADC1 channel 4,
   on wave_43 and wave_5 alike. Verified on wave_43 hardware only. */
#define BAT_ADC_CHANNEL ADC_CHANNEL_4
#define BAT_DIVIDER_MUL 3
#define BAT_ADC_UNIT ADC_UNIT_1
/* 4.2 V pack lands at 1.4 V on the pin */
#define BAT_ADC_ATTEN ADC_ATTEN_DB_12
/* the divider node is a noisy source */
#define BAT_ADC_SAMPLES 16

static const char *TAG = "bsp_bat_adc";
static adc_oneshot_unit_handle_t adc;
static adc_cali_handle_t cali;

esp_err_t bsp_pmic_init(void) {
  esp_err_t ret;
  adc_oneshot_unit_init_cfg_t unit = {.unit_id = BAT_ADC_UNIT};
  adc_oneshot_chan_cfg_t chan = {.atten = BAT_ADC_ATTEN,
                                 .bitwidth = ADC_BITWIDTH_DEFAULT};
  adc_cali_curve_fitting_config_t cal = {.unit_id = BAT_ADC_UNIT,
                                         .chan = BAT_ADC_CHANNEL,
                                         .atten = BAT_ADC_ATTEN,
                                         .bitwidth = ADC_BITWIDTH_DEFAULT};
  ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&unit, &adc), TAG, "unit");
  ESP_GOTO_ON_ERROR(adc_oneshot_config_channel(adc, BAT_ADC_CHANNEL, &chan),
                    err, TAG, "channel");
  ESP_GOTO_ON_ERROR(adc_cali_create_scheme_curve_fitting(&cal, &cali), err, TAG,
                    "calibration");
  return ESP_OK;
err:
  adc_oneshot_del_unit(adc);
  adc = NULL;
  return ret;
}

esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  int node_mv, sum = 0;
  if (!cali || !mv)
    return ESP_ERR_NOT_SUPPORTED;
  for (int i = 0; i < BAT_ADC_SAMPLES; i++) {
    ESP_RETURN_ON_ERROR(
        adc_oneshot_get_calibrated_result(adc, cali, BAT_ADC_CHANNEL, &node_mv),
        TAG, "read");
    sum += node_mv;
  }
  *mv = sum / BAT_ADC_SAMPLES * BAT_DIVIDER_MUL;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  (void)pct;
  return ESP_ERR_NOT_SUPPORTED;
}
esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  (void)status;
  return ESP_ERR_NOT_SUPPORTED;
}
/* The 5 V rail is latched by a physical button and no GPIO senses VBUS. */
esp_err_t bsp_pmic_power_off(void) { return ESP_ERR_NOT_SUPPORTED; }
bool bsp_pmic_can_power_off(void) { return false; }
bool bsp_pmic_is_vbus_present(void) { return false; }
bool bsp_pmic_is_available(void) { return cali != NULL; }
