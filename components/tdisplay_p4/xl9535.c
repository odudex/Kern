#include "xl9535.h"
#include "esp_check.h"
#include "esp_log.h"

static const char *TAG = "xl9535";

#define XL9535_REG_INPUT0 0x00
#define XL9535_REG_OUTPUT0 0x02
#define XL9535_REG_CONFIG0 0x06

#define XL9535_I2C_TIMEOUT_MS 100

static i2c_master_dev_handle_t s_dev = NULL;
/* Register shadows prevent single-pin writes from disturbing other outputs. */
static uint8_t s_output[2];
static uint8_t s_config[2];

/* Map a LilyGO IO number to (port, bit): IO0..7 -> port0 bit0..7,
 * IO10..17 -> port1 bit0..7. Returns false for invalid pins. */
static bool pin_to_port_bit(uint8_t pin, uint8_t *port, uint8_t *bit) {
  if (pin <= 7) {
    *port = 0;
    *bit = pin;
    return true;
  }
  if (pin >= 10 && pin <= 17) {
    *port = 1;
    *bit = pin - 10;
    return true;
  }
  return false;
}

static esp_err_t reg_write(uint8_t reg, uint8_t val) {
  uint8_t buf[2] = {reg, val};
  return i2c_master_transmit(s_dev, buf, sizeof(buf), XL9535_I2C_TIMEOUT_MS);
}

static esp_err_t reg_read(uint8_t reg, uint8_t *val) {
  return i2c_master_transmit_receive(s_dev, &reg, 1, val, 1,
                                     XL9535_I2C_TIMEOUT_MS);
}

esp_err_t xl9535_init(i2c_master_bus_handle_t bus, uint8_t addr) {
  if (s_dev) {
    return ESP_OK;
  }
  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = addr,
      .scl_speed_hz = 100000,
  };
  ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev), TAG,
                      "add device failed");

  /* Preserve the current state of pins not managed by Kern. */
  ESP_RETURN_ON_ERROR(reg_read(XL9535_REG_OUTPUT0, &s_output[0]), TAG,
                      "read output0");
  ESP_RETURN_ON_ERROR(reg_read(XL9535_REG_OUTPUT0 + 1, &s_output[1]), TAG,
                      "read output1");
  ESP_RETURN_ON_ERROR(reg_read(XL9535_REG_CONFIG0, &s_config[0]), TAG,
                      "read config0");
  ESP_RETURN_ON_ERROR(reg_read(XL9535_REG_CONFIG0 + 1, &s_config[1]), TAG,
                      "read config1");
  ESP_LOGI(TAG, "XL9535 ready at 0x%02X", addr);
  return ESP_OK;
}

esp_err_t xl9535_set_direction(uint8_t pin, bool output) {
  uint8_t port, bit;
  if (!s_dev) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!pin_to_port_bit(pin, &port, &bit)) {
    return ESP_ERR_INVALID_ARG;
  }

  uint8_t next =
      output ? (s_config[port] & ~(1u << bit)) : (s_config[port] | (1u << bit));
  if (next != s_config[port]) {
    s_config[port] = next;
    ESP_RETURN_ON_ERROR(reg_write(XL9535_REG_CONFIG0 + port, s_config[port]),
                        TAG, "write config");
  }
  return ESP_OK;
}

esp_err_t xl9535_set_level(uint8_t pin, uint8_t level) {
  uint8_t port, bit;
  if (!s_dev) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!pin_to_port_bit(pin, &port, &bit)) {
    return ESP_ERR_INVALID_ARG;
  }

  uint8_t next =
      level ? (s_output[port] | (1u << bit)) : (s_output[port] & ~(1u << bit));
  if (next != s_output[port]) {
    s_output[port] = next;
    ESP_RETURN_ON_ERROR(reg_write(XL9535_REG_OUTPUT0 + port, s_output[port]),
                        TAG, "write output");
  }
  return ESP_OK;
}
