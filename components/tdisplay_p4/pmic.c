/* TI BQ27220 fuel gauge support for the T-Display-P4. */

#include "bsp/pmic.h"
#include "bsp/tdisplay_p4.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"

static const char *TAG = "bq27220";

#define BQ27220_ADDR 0x55
#define BQ27220_CMD_VOLTAGE 0x08
#define BQ27220_CMD_BATTERY_STATUS 0x0A
#define BQ27220_CMD_CURRENT 0x0C
#define BQ27220_CMD_SOC 0x2C

#define BQ27220_STATUS_DSG (1u << 0) /* discharging */
#define BQ27220_STATUS_FC (1u << 5)  /* full charged */

#define BQ27220_I2C_TIMEOUT_MS 100

static i2c_master_dev_handle_t s_dev = NULL;
static bool s_available = false;

static esp_err_t bq_read_word(uint8_t cmd, uint16_t *out) {
  uint8_t rx[2] = {0};
  esp_err_t ret = i2c_master_transmit_receive(s_dev, &cmd, 1, rx, 2,
                                              BQ27220_I2C_TIMEOUT_MS);
  if (ret != ESP_OK) {
    return ret;
  }
  *out = (uint16_t)(rx[0] | (rx[1] << 8));
  return ESP_OK;
}

esp_err_t bsp_pmic_init(void) {
  i2c_master_bus_handle_t bus = bsp_i2c_get_handle();
  if (!bus) {
    return ESP_ERR_INVALID_STATE;
  }

  if (i2c_master_probe(bus, BQ27220_ADDR, 100) != ESP_OK) {
    ESP_LOGW(TAG, "BQ27220 not detected at 0x%02X", BQ27220_ADDR);
    return ESP_ERR_NOT_SUPPORTED;
  }

  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = BQ27220_ADDR,
      .scl_speed_hz = 100000,
  };
  ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev), TAG,
                      "add device failed");

  s_available = true;
  ESP_LOGI(TAG, "BQ27220 fuel gauge ready");
  return ESP_OK;
}

esp_err_t bsp_pmic_power_off(void) { return ESP_ERR_NOT_SUPPORTED; }

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  if (!s_available || !pct) {
    return ESP_ERR_INVALID_STATE;
  }
  uint16_t soc = 0;
  ESP_RETURN_ON_ERROR(bq_read_word(BQ27220_CMD_SOC, &soc), TAG, "read soc");
  if (soc > 100) {
    soc = 100;
  }
  *pct = (uint8_t)soc;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_battery_mv(uint16_t *mv) {
  if (!s_available || !mv) {
    return ESP_ERR_INVALID_STATE;
  }
  return bq_read_word(BQ27220_CMD_VOLTAGE, mv);
}

esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  if (!s_available || !status) {
    return ESP_ERR_INVALID_STATE;
  }
  uint16_t st = 0;
  ESP_RETURN_ON_ERROR(bq_read_word(BQ27220_CMD_BATTERY_STATUS, &st), TAG,
                      "read status");
  if (st & BQ27220_STATUS_FC) {
    *status = BSP_PMIC_CHG_FULL;
  } else if (st & BQ27220_STATUS_DSG) {
    *status = BSP_PMIC_CHG_DISCHARGING;
  } else {
    *status = BSP_PMIC_CHG_CHARGING;
  }
  return ESP_OK;
}

bool bsp_pmic_is_vbus_present(void) {
  if (!s_available) {
    return false;
  }
  uint16_t st = 0;
  if (bq_read_word(BQ27220_CMD_BATTERY_STATUS, &st) != ESP_OK) {
    return false;
  }
  /* Not discharging => charger present. */
  return (st & BQ27220_STATUS_DSG) == 0;
}

bool bsp_pmic_is_available(void) { return s_available; }

bool bsp_pmic_can_power_off(void) { return false; }
