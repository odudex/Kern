#include "bsp/pmic.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_35.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"

static const char *TAG = "axp2101";

/* AXP2101 I2C address (7-bit) */
#define AXP2101_ADDR 0x34

/* Register map (only what we need) */
#define REG_STATUS0 0x00
#define REG_STATUS1 0x01
#define REG_CHIP_ID 0x03
#define REG_PMU_CONFIG 0x10
#define REG_GAUGE_ENABLE 0x18
#define REG_ADC_ENABLE 0x30
#define REG_VBAT_H 0x34
#define REG_VBAT_L 0x35
#define REG_SOC 0xA4

/* Expected chip ID for AXP2101 */
#define AXP2101_CHIP_ID 0x4A

/* I2C timeout */
#define I2C_TIMEOUT_MS 100

static i2c_master_dev_handle_t pmic_dev = NULL;
static bool pmic_available = false;

static esp_err_t pmic_read_u8(uint8_t reg, uint8_t *val) {
  return i2c_master_transmit_receive(pmic_dev, &reg, 1, val, 1, I2C_TIMEOUT_MS);
}

static esp_err_t pmic_write_u8(uint8_t reg, uint8_t val) {
  uint8_t buf[2] = {reg, val};
  return i2c_master_transmit(pmic_dev, buf, 2, I2C_TIMEOUT_MS);
}

static esp_err_t pmic_set_bits(uint8_t reg, uint8_t mask) {
  uint8_t val;
  ESP_RETURN_ON_ERROR(pmic_read_u8(reg, &val), TAG, "read reg 0x%02x", reg);
  val |= mask;
  return pmic_write_u8(reg, val);
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
      .device_address = AXP2101_ADDR,
      .scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ,
  };
  ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &pmic_dev), TAG,
                      "add AXP2101 device");

  /* Probe: read chip ID */
  uint8_t chip_id = 0;
  esp_err_t ret = pmic_read_u8(REG_CHIP_ID, &chip_id);
  if (ret != ESP_OK || chip_id != AXP2101_CHIP_ID) {
    ESP_LOGW(TAG, "AXP2101 not found (id=0x%02x, err=%d)", chip_id, ret);
    i2c_master_bus_rm_device(pmic_dev);
    pmic_dev = NULL;
    return ESP_ERR_NOT_FOUND;
  }

  ESP_LOGI(TAG, "AXP2101 detected (chip_id=0x%02x)", chip_id);

  /* Enable battery voltage ADC (bit 0 of ADC_ENABLE) */
  ESP_RETURN_ON_ERROR(pmic_set_bits(REG_ADC_ENABLE, 0x01), TAG,
                      "enable battery ADC");

  /* Enable fuel gauge (bit 0 of GAUGE_ENABLE) */
  ESP_RETURN_ON_ERROR(pmic_set_bits(REG_GAUGE_ENABLE, 0x01), TAG,
                      "enable gauge");

  pmic_available = true;
  return ESP_OK;
}

esp_err_t bsp_pmic_power_off(void) {
  if (!pmic_available) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  /* Set SOFT_PWROFF bit (bit 0) in PMU_CONFIG register */
  return pmic_set_bits(REG_PMU_CONFIG, 0x01);
}

esp_err_t bsp_pmic_get_battery_percent(uint8_t *pct) {
  if (!pmic_available || !pct) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  uint8_t val;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_SOC, &val), TAG, "read SOC");
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
  uint8_t h, l;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_VBAT_H, &h), TAG, "read VBAT_H");
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_VBAT_L, &l), TAG, "read VBAT_L");
  /* 14-bit value: high byte [13:6], low byte [5:0] */
  uint16_t raw = ((uint16_t)h << 6) | (l & 0x3F);
  /* AXP2101 battery ADC: 1.1mV per LSB */
  *mv = raw;
  return ESP_OK;
}

esp_err_t bsp_pmic_get_charge_status(bsp_pmic_chg_t *status) {
  if (!pmic_available || !status) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  uint8_t val;
  ESP_RETURN_ON_ERROR(pmic_read_u8(REG_STATUS1, &val), TAG, "read STATUS1");
  /* Bits [6:5] of STATUS1: charging status */
  uint8_t chg = (val >> 5) & 0x03;
  switch (chg) {
  case 0:
    *status = BSP_PMIC_CHG_DISCHARGING;
    break;
  case 1:
    *status = BSP_PMIC_CHG_CHARGING;
    break;
  case 2:
    *status = BSP_PMIC_CHG_FULL;
    break;
  default:
    *status = BSP_PMIC_CHG_ABSENT;
    break;
  }
  return ESP_OK;
}

bool bsp_pmic_is_vbus_present(void) {
  if (!pmic_available) {
    return false;
  }
  uint8_t val;
  if (pmic_read_u8(REG_STATUS0, &val) != ESP_OK) {
    return false;
  }
  /* Bit 5 of STATUS0: VBUS present */
  return (val >> 5) & 0x01;
}

bool bsp_pmic_is_available(void) { return pmic_available; }

/* The AXP2101 supports software power-off (SOFT_PWROFF). */
bool bsp_pmic_can_power_off(void) { return pmic_available; }
