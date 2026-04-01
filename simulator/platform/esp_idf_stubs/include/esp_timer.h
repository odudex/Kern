#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef struct sim_esp_timer *esp_timer_handle_t;
typedef void (*esp_timer_cb_t)(void *arg);

typedef enum { ESP_TIMER_TASK = 0, ESP_TIMER_ISR = 1 } esp_timer_dispatch_t;

typedef struct {
    esp_timer_cb_t        callback;
    void                 *arg;
    const char           *name;
    bool                  skip_unhandled_events;
    esp_timer_dispatch_t  dispatch_method;
} esp_timer_create_args_t;

// Returns microseconds since simulator start (uses CLOCK_MONOTONIC)
int64_t   esp_timer_get_time(void);

esp_err_t esp_timer_create(const esp_timer_create_args_t *args,
                            esp_timer_handle_t *out_handle);
esp_err_t esp_timer_start_once(esp_timer_handle_t timer, uint64_t timeout_us);
esp_err_t esp_timer_start_periodic(esp_timer_handle_t timer, uint64_t period_us);
esp_err_t esp_timer_stop(esp_timer_handle_t timer);
esp_err_t esp_timer_delete(esp_timer_handle_t timer);
