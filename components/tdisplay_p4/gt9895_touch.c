#include "gt9895_touch.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "gt9895";

#define GT9895_ADDR 0x5D
#define GT9895_I2C_HZ 400000
#define GT9895_I2C_TIMEOUT_MS 20

/* GT9895 uses 32-bit big-endian register addresses. */
#define GT9895_REG_IC_INFO 0x00010070u /* first byte == chip id 0xAD */
#define GT9895_REG_TOUCH_INFO 0x00010308u
#define GT9895_CHIP_ID 0xAD

#define GT9895_TOUCH_HEADER 8 /* bytes before the first touch point */
#define GT9895_POINT_SIZE 8   /* bytes per touch point */
#define GT9895_STATUS_EDGE 0x84

/* Raw coordinate range reported by the controller. */
#define GT9895_RAW_X_MAX 1060
#define GT9895_RAW_Y_MAX 2400

static i2c_master_dev_handle_t s_dev = NULL;

static esp_err_t gt9895_read(uint32_t reg, uint8_t *data, size_t len) {
  uint8_t addr[4] = {
      (uint8_t)(reg >> 24),
      (uint8_t)(reg >> 16),
      (uint8_t)(reg >> 8),
      (uint8_t)(reg),
  };
  return i2c_master_transmit_receive(s_dev, addr, sizeof(addr), data, len,
                                     GT9895_I2C_TIMEOUT_MS);
}

static esp_err_t gt9895_read_data(esp_lcd_touch_handle_t tp) {
  uint8_t buf[GT9895_TOUCH_HEADER + GT9895_POINT_SIZE] = {0};
  if (gt9895_read(GT9895_REG_TOUCH_INFO, buf, sizeof(buf)) != ESP_OK) {
    return ESP_OK; /* transient bus error: report "no touch" this cycle */
  }

  uint8_t fingers = buf[2];
  uint8_t points = 0;
  uint16_t x = 0, y = 0;

  /* Ignore edge-only reports (status 0x84 with no real coordinate). */
  if (fingers >= 1 && fingers <= 10 && buf[0] != GT9895_STATUS_EDGE) {
    const uint8_t *p = &buf[GT9895_TOUCH_HEADER];
    uint16_t raw_x = (uint16_t)(p[2] | (p[3] << 8));
    uint16_t raw_y = (uint16_t)(p[4] | (p[5] << 8));
    x = (uint16_t)((uint32_t)raw_x * tp->config.x_max / GT9895_RAW_X_MAX);
    y = (uint16_t)((uint32_t)raw_y * tp->config.y_max / GT9895_RAW_Y_MAX);
    if (x >= tp->config.x_max) {
      x = tp->config.x_max - 1;
    }
    if (y >= tp->config.y_max) {
      y = tp->config.y_max - 1;
    }
    points = 1;
  }

  portENTER_CRITICAL(&tp->data.lock);
  tp->data.points = points;
  if (points) {
    tp->data.coords[0].x = x;
    tp->data.coords[0].y = y;
    tp->data.coords[0].strength = 0;
  }
  portEXIT_CRITICAL(&tp->data.lock);
  return ESP_OK;
}

static bool gt9895_get_xy(esp_lcd_touch_handle_t tp, uint16_t *x, uint16_t *y,
                          uint16_t *strength, uint8_t *point_num,
                          uint8_t max_point_num) {
  portENTER_CRITICAL(&tp->data.lock);
  uint8_t n = tp->data.points;
  if (n > max_point_num) {
    n = max_point_num;
  }
  for (uint8_t i = 0; i < n; i++) {
    x[i] = tp->data.coords[i].x;
    y[i] = tp->data.coords[i].y;
    if (strength) {
      strength[i] = tp->data.coords[i].strength;
    }
  }
  tp->data.points = 0;
  portEXIT_CRITICAL(&tp->data.lock);
  *point_num = n;
  return n > 0;
}

static esp_err_t gt9895_del(esp_lcd_touch_handle_t tp) {
  if (s_dev) {
    i2c_master_bus_rm_device(s_dev);
    s_dev = NULL;
  }
  free(tp);
  return ESP_OK;
}

esp_err_t gt9895_touch_new(i2c_master_bus_handle_t bus,
                           const esp_lcd_touch_config_t *config,
                           esp_lcd_touch_handle_t *out) {
  ESP_RETURN_ON_FALSE(bus && config && out, ESP_ERR_INVALID_ARG, TAG,
                      "bad args");

  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = GT9895_ADDR,
      .scl_speed_hz = GT9895_I2C_HZ,
  };
  ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev), TAG,
                      "add device failed");

  uint8_t id = 0;
  esp_err_t ret = gt9895_read(GT9895_REG_IC_INFO, &id, sizeof(id));
  if (ret != ESP_OK || id != GT9895_CHIP_ID) {
    i2c_master_bus_rm_device(s_dev);
    s_dev = NULL;
    if (ret != ESP_OK) {
      return ret;
    }
    ESP_LOGE(TAG, "GT9895 id mismatch (got 0x%02X, expected 0x%02X)", id,
             GT9895_CHIP_ID);
    return ESP_ERR_INVALID_RESPONSE;
  }
  ESP_LOGI(TAG, "GT9895 detected (id=0x%02X)", id);

  esp_lcd_touch_handle_t tp = calloc(1, sizeof(esp_lcd_touch_t));
  if (!tp) {
    i2c_master_bus_rm_device(s_dev);
    s_dev = NULL;
    return ESP_ERR_NO_MEM;
  }
  tp->config = *config;
  tp->read_data = gt9895_read_data;
  tp->get_xy = gt9895_get_xy;
  tp->del = gt9895_del;
  portMUX_INITIALIZE(&tp->data.lock);

  *out = tp;
  return ESP_OK;
}
