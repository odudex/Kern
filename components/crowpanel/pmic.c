/* Battery monitoring for the CrowPanel Advanced ESP32-P4 boards (7" / 10.1").
 *
 * Hardware overview
 * -----------------
 * A TP4059 linear LiPo charger handles charging.  A companion STC8H1K08
 * 8-bit MCU sits between the battery and the ESP32-P4: it reads the battery
 * voltage via its own ADC (through a 100 kΩ / 39 kΩ resistor divider),
 * monitors the TP4059 CHG/STD status lines, drives the red/green indicator
 * LEDs, and exposes all this data to the ESP32-P4 over I²C as a register
 * map.
 *
 * I²C interface (7-bit address 0x2F, shared I²C bus GPIO45/GPIO46)
 * ----------------------------------------------------------------
 * Registers (little-endian where multi-byte):
 *   0x00–0x03  adc_voltage  (uint32_t, mV) – raw divider node voltage
 *   0x04–0x07  bat_voltage  (uint32_t, mV) – actual battery voltage
 *   0x08       bat_level    (uint8_t, 0–100) – state-of-charge percentage
 *   0x09       bat_state    (uint8_t) – see EM_BAT_CHARGE_STATE below
 *   0x0A       led_state    (uint8_t) – LED indicator state (informational)
 *
 * bat_state values (from factory firmware):
 *   0  IDLE          – on battery, not charging
 *   1  CHARGING      – actively charging
 *   2  FULLY_CHARGED – charge complete
 *   3  NO_CHARGE     – no charger connected
 *   4  ERROR         – error condition
 */

#include "bsp/pmic.h"
#include "bsp/crowpanel.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"

static const char *TAG = "crowpanel_pmic";

/* STC8H1K08 I²C slave address (7-bit) */
#define STC8H_ADDR 0x2F

/* Register base addresses */
#define REG_ADC_VOLTAGE 0x00 /* u32 LE, raw divider voltage in mV    */
#define REG_BAT_VOLTAGE 0x04 /* u32 LE, actual battery voltage in mV */
#define REG_BAT_LEVEL 0x08   /* u8,  state-of-charge 0–100 %         */
#define REG_BAT_STATE 0x09   /* u8,  EM_BAT_CHARGE_STATE             */
#define REG_LED_STATE 0x0A   /* u8,  EM_LED_STATE                    */

/* EM_BAT_CHARGE_STATE values */
#define BAT_CHARGE_IDLE 0
#define BAT_CHARGE_CHARGING 1
#define BAT_CHARGE_FULLY_CHARGED 2
#define BAT_CHARGE_NO_CHARGE 3
#define BAT_CHARGE_ERROR 4

/* EM_LED_STATE values – directly reflect the physical indicator LED */
#define LED_IDLE 0
#define LED_CHARGING 1      /* red LED on – actively charging        */
#define LED_FULLY_CHARGED 2 /* green LED on – charge complete        */
#define LED_NO_CHARGE 3     /* no charger connected                  */
#define LED_LOW_POWER 4     /* 0.5 Hz red blink – low battery        */

#define I2C_TIMEOUT_MS 100

static i2c_master_dev_handle_t pmic_dev = NULL;
static bool pmic_available = false;

static esp_err_t pmic_read_u8(uint8_t reg, uint8_t *val) {
  return i2c_master_transmit_receive(pmic_dev, &reg, 1, val, 1, I2C_TIMEOUT_MS);
}

/* Read a little-endian uint32_t using a single 4-byte I²C transfer */
static esp_err_t pmic_read_u32_le(uint8_t reg, uint32_t *val) {
  uint8_t buf[4];
  esp_err_t err =
      i2c_master_transmit_receive(pmic_dev, &reg, 1, buf, 4, I2C_TIMEOUT_MS);
  if (err != ESP_OK) {
    return err;
  }
  *val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
         ((uint32_t)buf[3] << 24);
  return ESP_OK;
}

esp_err_t bsp_pmic_init(void) {
  if (pmic_available) {
    return ESP_OK;
  }

  i2c_master_bus_handle_t bus = bsp_i2c_get_handle();
  if (!bus) {
    return ESP_ERR_INVALID_STATE;
  }

  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = STC8H_ADDR,
      .scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ,
  };
  ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &pmic_dev), TAG,
                      "add STC8H device");

  /* Probe: try reading the bat_level register and sanity-check its value */
  uint8_t probe_val = 0;
  esp_err_t ret = pmic_read_u8(REG_BAT_LEVEL, &probe_val);
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "STC8H1KXX not found (err=%d)", ret);
    i2c_master_bus_rm_device(pmic_dev);
    pmic_dev = NULL;
    return ESP_ERR_NOT_FOUND;
  }
  if (probe_val > 100) {
    ESP_LOGW(TAG, "STC8H1KXX returned unexpected bat_level=%u during probe",
             probe_val);
    i2c_master_bus_rm_device(pmic_dev);
    pmic_dev = NULL;
    return ESP_ERR_NOT_FOUND;
  }

  ESP_LOGI(TAG, "STC8H1KXX battery controller detected");
  pmic_available = true;
  return ESP_OK;
}

esp_err_t bsp_pmic_power_off(void) {
  /* The TP4059 + STC8H1KXX combination does not expose a software
     power-off command. */
  return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  if (!pmic_available || !pct) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  uint8_t val = 0;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_BAT_LEVEL, &val), TAG, "read bat_level");
  if (val > 100) {
    val = 100;
  }
  *pct = val;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  if (!pmic_available || !mv) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  uint32_t bat_mv = 0;
  ESP_RETURN_ON_ERROR(pmic_read_u32_le(REG_BAT_VOLTAGE, &bat_mv), TAG,
                      "read bat_voltage");
  /* Clamp to uint16_t range (battery voltage is always < 5000 mV) */
  *mv = (bat_mv > 0xFFFF) ? 0xFFFF : (uint16_t)bat_mv;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  if (!pmic_available || !status) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  uint8_t bat_state = 0;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_BAT_STATE, &bat_state), TAG,
                      "read bat_state");
  uint8_t led_state = 0;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_LED_STATE, &led_state), TAG,
                      "read led_state");

  /*
   * Some CrowPanel STC8H firmware revisions do not set bat_state=1
   * during active charging; they only update the led_state register.
   * Check both so that either one can signal the charging condition.
   */
  if (bat_state == BAT_CHARGE_CHARGING || led_state == LED_CHARGING) {
    *status = BSP_PMIC_CHG_CHARGING;
  } else if (bat_state == BAT_CHARGE_FULLY_CHARGED ||
             led_state == LED_FULLY_CHARGED) {
    *status = BSP_PMIC_CHG_FULL;
  } else if (bat_state == BAT_CHARGE_NO_CHARGE ||
             bat_state == BAT_CHARGE_ERROR || led_state == LED_NO_CHARGE) {
    *status = BSP_PMIC_CHG_ABSENT;
  } else {
    *status = BSP_PMIC_CHG_DISCHARGING;
  }
  return ESP_OK;
}

bool bsp_pmic_is_vbus_present(void) {
  if (!pmic_available) {
    return false;
  }
  uint8_t bat_state = 0;
  uint8_t led_state = 0;
  if (pmic_read_u8(REG_BAT_STATE, &bat_state) != ESP_OK) {
    return false;
  }
  if (pmic_read_u8(REG_LED_STATE, &led_state) != ESP_OK) {
    return false;
  }
  return (bat_state == BAT_CHARGE_CHARGING ||
          bat_state == BAT_CHARGE_FULLY_CHARGED || led_state == LED_CHARGING ||
          led_state == LED_FULLY_CHARGED);
}

bool bsp_pmic_is_available(void) { return pmic_available; }
