/* Battery monitoring for the Waveshare ESP32-P4-WiFi6-Touch-LCD-4.3.
 *
 * Hardware overview
 * -----------------
 * Unlike wave_35 (AXP2101) and crowpanel (STC8H companion MCU), this board has
 * no PMIC and no fuel gauge.  An ETA6098 linear charger sits between USB and
 * the MX1.25 pack, and the only telemetry reaching the SoC is the raw pack
 * voltage through the resistor divider documented next to BSP_BAT_ADC_GPIO in
 * the board header.  So this driver is the one place in the tree that talks to
 * the ESP-IDF ADC directly, and everything the PMIC API exposes has to be
 * derived from that single number.
 *
 * Two consequences worth knowing before reading the code:
 *
 *   - State of charge is estimated from a LiPo discharge curve.  Without a
 *     coulomb counter that is the best available, and it is only accurate at
 *     rest: the pack sags under display and radio load, so readings are
 *     smoothed and never allowed to climb while discharging.
 *
 *   - Charge state is a heuristic.  The ETA6098 STAT pin goes to test point
 *     TP1 only, and no GPIO senses VBUS either, so there is no charge signal
 *     to read.  Two observations stand in for it, and either one is enough:
 *     the pack sits at the charger's 4.2 V CV target once charging finishes,
 *     and while charging is still in progress the voltage climbs steadily.
 *     Measured on this board, a charging pack rose ~13 mV/min and settled at
 *     exactly 4200 mV on termination.
 */

#include "bsp/pmic.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_43.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "wave43_bat";

/* BAT_ADC is GPIO20, which is ADC1 channel 4 on the ESP32-P4.  A full 4.2 V
   pack reaches the pin as 1.4 V, comfortably inside the 12 dB range. */
#define BAT_ADC_UNIT ADC_UNIT_1
#define BAT_ADC_CHANNEL ADC_CHANNEL_4
#define BAT_ADC_ATTEN ADC_ATTEN_DB_12

/* The divider presents R12||R15 = 66.7 kOhm to the ADC, which is high enough
   that a single conversion is noisy even with C173 holding the node up.
   Averaging a burst costs nothing at our refresh rate. */
#define BAT_ADC_SAMPLES 16

/* Used only when the calibration eFuse is not burnt: nominal full-scale of the
   12 dB attenuation against the 12-bit raw range. */
#define BAT_ADC_FALLBACK_FS_MV 3100
#define BAT_ADC_FALLBACK_FS_RAW 4095

/* A pack outside this window means something other than a battery is on the
   connector (or nothing at all), so the indicator stays hidden. */
#define BAT_SANITY_MIN_MV 2500
#define BAT_SANITY_MAX_MV 4600

/* Threshold arm of the charge heuristic: the pack is parked at the charger's
   CV target.  Hysteresis keeps the icon from flickering around the edge.  A
   full pack that was just unplugged reads as charging until it drops below the
   lower bound; there is no way to tell the two apart here. */
#define BAT_CHARGING_ENTER_MV 4180
#define BAT_CHARGING_EXIT_MV 4120

/* Trend arm: the threshold alone only fires once charging has finished, which
   would leave the icon claiming "discharging" for the hours a flat pack spends
   climbing.  A charging pack was measured rising ~13 mV/min on this board,
   against an EMA noise floor well under 1 mV/min over the same window, so the
   rate below separates the two with room to spare.  Comparing a rate rather
   than a raw delta keeps this honest when callers ask at an uneven cadence. */
#define BAT_TREND_WINDOW_US (180 * 1000 * 1000)
#define BAT_TREND_RISE_MV_PER_MIN 3

/* Cache window shared by all getters: ui_battery_create() asks for percentage
   and charge state back to back, and both should see the same sample. */
#define BAT_CACHE_VALID_US (1000 * 1000)

/* Exponential moving average weight, as a divisor: new = old + (raw - old)/N */
#define BAT_SMOOTH_DIVISOR 4

static adc_oneshot_unit_handle_t adc_handle = NULL;
static adc_cali_handle_t adc_cali_handle = NULL;
static bool pmic_available = false;

static int smoothed_mv = -1;
static int64_t smoothed_at_us = 0;
static bool charging = false;
static uint8_t last_pct = 0xFF;

/* Charge heuristic state: the threshold arm latches through its hysteresis
   band, the trend arm re-derives itself from scratch every window. */
static bool threshold_charging = false;
static bool trend_rising = false;
static int trend_mv = 0;
static int64_t trend_at_us = 0;

/* Discharge curve for a single-cell LiPo at rest, descending by voltage. */
static const struct {
  uint16_t mv;
  uint8_t pct;
} lipo_curve[] = {
    {4200, 100}, {4100, 90}, {4000, 80}, {3900, 68}, {3800, 55},
    {3700, 40},  {3600, 25}, {3500, 12}, {3400, 5},  {3300, 0},
};

/* Average a burst of conversions and scale the divider node back up to the
   pack voltage. */
static esp_err_t bat_sample_mv(int *out_mv) {
  int raw_sum = 0;
  for (int i = 0; i < BAT_ADC_SAMPLES; i++) {
    int raw = 0;
    ESP_RETURN_ON_ERROR(adc_oneshot_read(adc_handle, BAT_ADC_CHANNEL, &raw),
                        TAG, "read BAT_ADC");
    raw_sum += raw;
  }
  int raw_avg = raw_sum / BAT_ADC_SAMPLES;

  int node_mv;
  if (adc_cali_handle) {
    ESP_RETURN_ON_ERROR(
        adc_cali_raw_to_voltage(adc_cali_handle, raw_avg, &node_mv), TAG,
        "convert raw %d", raw_avg);
  } else {
    node_mv = raw_avg * BAT_ADC_FALLBACK_FS_MV / BAT_ADC_FALLBACK_FS_RAW;
  }

  *out_mv = node_mv * BSP_BAT_DIVIDER_MUL;
  return ESP_OK;
}

/* Refresh the cached pack voltage and charge state, at most once per cache
   window.  Feeds the EMA rather than the raw sample so a momentary sag under
   load does not move the icon. */
static esp_err_t bat_refresh(void) {
  int64_t now = esp_timer_get_time();
  if (smoothed_mv >= 0 && now - smoothed_at_us < BAT_CACHE_VALID_US) {
    return ESP_OK;
  }

  int mv;
  ESP_RETURN_ON_ERROR(bat_sample_mv(&mv), TAG, "sample battery");

  if (smoothed_mv < 0) {
    smoothed_mv = mv;
  } else {
    smoothed_mv += (mv - smoothed_mv) / BAT_SMOOTH_DIVISOR;
  }
  smoothed_at_us = now;

  if (threshold_charging) {
    threshold_charging = smoothed_mv >= BAT_CHARGING_EXIT_MV;
  } else {
    threshold_charging = smoothed_mv >= BAT_CHARGING_ENTER_MV;
  }

  /* Re-derived, never latched: the moment the climb stops -- charge complete,
     or the cable pulled -- the trend arm drops on the next window and the
     threshold arm is left to decide. */
  int64_t trend_elapsed_us = now - trend_at_us;
  if (trend_elapsed_us >= BAT_TREND_WINDOW_US) {
    int64_t rate_mv_per_min =
        (int64_t)(smoothed_mv - trend_mv) * 60 * 1000000 / trend_elapsed_us;
    trend_rising = rate_mv_per_min >= BAT_TREND_RISE_MV_PER_MIN;
    trend_mv = smoothed_mv;
    trend_at_us = now;
  }

  charging = threshold_charging || trend_rising;

  return ESP_OK;
}

static uint8_t bat_mv_to_percent(int mv) {
  const size_t n = sizeof(lipo_curve) / sizeof(lipo_curve[0]);
  if (mv >= lipo_curve[0].mv) {
    return lipo_curve[0].pct;
  }
  for (size_t i = 1; i < n; i++) {
    if (mv >= lipo_curve[i].mv) {
      /* Linear interpolation between the bracketing points. */
      int span_mv = lipo_curve[i - 1].mv - lipo_curve[i].mv;
      int span_pct = lipo_curve[i - 1].pct - lipo_curve[i].pct;
      return (uint8_t)(lipo_curve[i].pct +
                       (mv - lipo_curve[i].mv) * span_pct / span_mv);
    }
  }
  return lipo_curve[n - 1].pct;
}

esp_err_t bsp_pmic_init(void) {
  if (pmic_available) {
    return ESP_OK;
  }

  adc_oneshot_unit_init_cfg_t unit_cfg = {
      .unit_id = BAT_ADC_UNIT,
      .ulp_mode = ADC_ULP_MODE_DISABLE,
  };
  ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&unit_cfg, &adc_handle), TAG,
                      "create ADC1 unit");

  adc_oneshot_chan_cfg_t chan_cfg = {
      .atten = BAT_ADC_ATTEN,
      .bitwidth = ADC_BITWIDTH_DEFAULT,
  };
  ESP_RETURN_ON_ERROR(
      adc_oneshot_config_channel(adc_handle, BAT_ADC_CHANNEL, &chan_cfg), TAG,
      "configure BAT_ADC channel");

  /* Curve fitting is the only scheme the ESP32-P4 supports.  It needs eFuse
     calibration data, so fall back to the nominal full-scale ratio when the
     bits are not burnt rather than giving up on battery reporting. */
  adc_cali_curve_fitting_config_t cali_cfg = {
      .unit_id = BAT_ADC_UNIT,
      .chan = BAT_ADC_CHANNEL,
      .atten = BAT_ADC_ATTEN,
      .bitwidth = ADC_BITWIDTH_DEFAULT,
  };
  esp_err_t cali_ret =
      adc_cali_create_scheme_curve_fitting(&cali_cfg, &adc_cali_handle);
  if (cali_ret != ESP_OK) {
    ESP_LOGW(TAG, "ADC calibration unavailable (%s), using nominal scale",
             esp_err_to_name(cali_ret));
    adc_cali_handle = NULL;
  }

  int mv = 0;
  esp_err_t ret = bat_sample_mv(&mv);
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "battery sense read failed: %s", esp_err_to_name(ret));
    return ret;
  }
  if (mv < BAT_SANITY_MIN_MV || mv > BAT_SANITY_MAX_MV) {
    ESP_LOGW(TAG, "no battery detected on GPIO%d (%d mV)", BSP_BAT_ADC_GPIO,
             mv);
    return ESP_ERR_NOT_FOUND;
  }

  ESP_LOGI(TAG, "battery sense on GPIO%d: %d mV", BSP_BAT_ADC_GPIO, mv);

  smoothed_mv = mv;
  smoothed_at_us = esp_timer_get_time();
  /* The trend arm needs a window of uptime before it can say anything, so a
     board that boots mid-charge reports discharging until then. Booting is
     exactly when that happens: plugging the cable resets this board. */
  trend_mv = mv;
  trend_at_us = smoothed_at_us;
  trend_rising = false;
  threshold_charging = mv >= BAT_CHARGING_ENTER_MV;
  charging = threshold_charging;

  pmic_available = true;
  return ESP_OK;
}

esp_err_t bsp_pmic_power_off(void) {
  /* The ECJ23001 latch that gates the 5 V rail is wired to the physical Key3
     button only; no GPIO reaches its KEY or OUT pin. */
  return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  if (!pmic_available || !pct) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  ESP_RETURN_ON_ERROR(bat_refresh(), TAG, "refresh battery");

  uint8_t value = bat_mv_to_percent(smoothed_mv);
  /* Only charging may push the reading back up; otherwise a pack recovering
     after a load spike would make the icon walk backwards. */
  if (!charging && last_pct != 0xFF && value > last_pct) {
    value = last_pct;
  }
  last_pct = value;

  *pct = value;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  if (!pmic_available || !mv) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  ESP_RETURN_ON_ERROR(bat_refresh(), TAG, "refresh battery");
  *mv = (uint16_t)smoothed_mv;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  if (!pmic_available || !status) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  ESP_RETURN_ON_ERROR(bat_refresh(), TAG, "refresh battery");
  /* No way to distinguish CHARGING from FULL without a STAT line: both show
     up here as a pack held at the CV target. */
  *status = charging ? BSP_PMIC_CHG_CHARGING : BSP_PMIC_CHG_DISCHARGING;
  return ESP_OK;
}

bool bsp_pmic_is_vbus_present(void) {
  if (!pmic_available) {
    return false;
  }
  if (bat_refresh() != ESP_OK) {
    return false;
  }
  /* The charging heuristic is the only USB evidence this board offers. */
  return charging;
}

bool bsp_pmic_is_available(void) { return pmic_available; }

/* Power is cut by the Key3 button through the ECJ23001 latch, not in software.
 */
bool bsp_pmic_can_power_off(void) { return false; }
