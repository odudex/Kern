#pragma once

#include "esp_err.h"

/* Watchdog stubs — no-ops in simulator */
static inline esp_err_t esp_task_wdt_reset(void)              { return ESP_OK; }
static inline esp_err_t esp_task_wdt_add(void *handle)        { (void)handle; return ESP_OK; }
static inline esp_err_t esp_task_wdt_delete(void *handle)     { (void)handle; return ESP_OK; }
static inline esp_err_t esp_task_wdt_init(uint32_t t, bool p) { (void)t; (void)p; return ESP_OK; }
