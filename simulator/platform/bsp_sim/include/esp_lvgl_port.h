#pragma once
#include "esp_err.h"
#include "lvgl.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int task_priority;
    int task_stack;
    int task_affinity;
    int task_max_sleep_ms;
    unsigned task_stack_caps;
    int timer_period_ms;
} lvgl_port_cfg_t;

#define ESP_LVGL_PORT_INIT_CONFIG() \
    { .task_priority = 4, .task_stack = 7168, .task_affinity = -1, \
      .task_max_sleep_ms = 500, .task_stack_caps = 0, .timer_period_ms = 5 }

esp_err_t lvgl_port_init(const lvgl_port_cfg_t *cfg);
esp_err_t lvgl_port_deinit(void);
bool      lvgl_port_lock(uint32_t timeout_ms);
void      lvgl_port_unlock(void);
void      lvgl_port_flush_ready(lv_display_t *disp);
