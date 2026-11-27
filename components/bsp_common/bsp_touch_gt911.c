#include "bsp/bsp_common.h"
#include "bsp_err_check.h"
#include "esp_check.h"
#include "esp_lcd_touch_gt911.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "bsp_gt911";

static void gt911_hw_reset(gpio_num_t rst_gpio) {
  if (rst_gpio == GPIO_NUM_NC) {
    return;
  }
  const gpio_config_t rst_cfg = {
      .mode = GPIO_MODE_OUTPUT,
      .pin_bit_mask = BIT64(rst_gpio),
  };
  gpio_config(&rst_cfg);
  gpio_set_level(rst_gpio, 0);
  vTaskDelay(pdMS_TO_TICKS(10));
  gpio_set_level(rst_gpio, 1);
  vTaskDelay(pdMS_TO_TICKS(200));
}

esp_err_t bsp_common_touch_gt911_new(const bsp_gt911_touch_cfg_t *cfg,
                                     esp_lcd_touch_handle_t *ret_touch) {
  esp_lcd_touch_io_gt911_config_t gt911_config = {
      .dev_addr = ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS,
  };

  if (cfg->manual_reset_retry) {
    /* The GT911 driver only waits 10 ms after reset — too short for some
     * units. Handle the reset with 200 ms settling and pass rst_gpio_num=NC
     * so the driver skips its own reset. */
    gt911_hw_reset(cfg->rst_gpio_num);
  }

  esp_lcd_touch_config_t tp_cfg = {
      .x_max = cfg->x_max,
      .y_max = cfg->y_max,
      .rst_gpio_num = cfg->manual_reset_retry ? GPIO_NUM_NC : cfg->rst_gpio_num,
      .int_gpio_num = cfg->int_gpio_num,
      .levels =
          {
              .reset = 0,
              .interrupt = 0,
          },
      .flags =
          {
              .swap_xy = 0,
              .mirror_x = cfg->mirror_x ? 1 : 0,
              .mirror_y = cfg->mirror_y ? 1 : 0,
          },
      .driver_data = cfg->pass_driver_data ? &gt911_config : NULL,
  };

  esp_lcd_panel_io_i2c_config_t tp_io_config =
      ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG();
  if (cfg->probe_backup_addr) {
    if (bsp_common_i2c_probe(ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS) == ESP_OK) {
      ESP_LOGI(TAG, "GT911 found at 0x%02X",
               ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS);
    } else if (bsp_common_i2c_probe(
                   ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP) == ESP_OK) {
      ESP_LOGI(TAG, "GT911 found at 0x%02X",
               ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP);
      tp_io_config.dev_addr = ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP;
      gt911_config.dev_addr = ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP;
    } else {
      ESP_LOGE(TAG, "GT911 not found at either I2C address");
      return ESP_ERR_NOT_FOUND;
    }
  }
  tp_io_config.scl_speed_hz = CONFIG_BSP_I2C_CLK_SPEED_HZ;

  esp_lcd_panel_io_handle_t tp_io_handle = NULL;
  ESP_RETURN_ON_ERROR(esp_lcd_new_panel_io_i2c(bsp_common_i2c_get_handle(),
                                               &tp_io_config, &tp_io_handle),
                      TAG, "");

  if (!cfg->manual_reset_retry) {
    return esp_lcd_touch_new_i2c_gt911(tp_io_handle, &tp_cfg, ret_touch);
  }

  esp_err_t ret = ESP_FAIL;
  for (int attempt = 0; attempt < 3; attempt++) {
    ret = esp_lcd_touch_new_i2c_gt911(tp_io_handle, &tp_cfg, ret_touch);
    if (ret == ESP_OK) {
      return ESP_OK;
    }
    ESP_LOGW(TAG, "GT911 init attempt %d/3 failed (0x%x), retrying...",
             attempt + 1, ret);
    gt911_hw_reset(cfg->rst_gpio_num);
  }
  return ret;
}
