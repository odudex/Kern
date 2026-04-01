#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_heap_caps.h"

#define configTICK_RATE_HZ   1000U
#define portMAX_DELAY        ((TickType_t)0xFFFFFFFFU)

#define pdTRUE   1
#define pdFALSE  0
#define pdPASS   pdTRUE
#define pdFAIL   pdFALSE

/* ms → ticks at 1000 Hz is a 1:1 mapping */
#define pdMS_TO_TICKS(ms)  ((TickType_t)(ms))

#define configASSERT(x)    assert(x)

/* Critical section no-ops for single-threaded LVGL main loop */
#define portENTER_CRITICAL()     ((void)0)
#define portEXIT_CRITICAL()      ((void)0)
#define portENTER_CRITICAL_ISR() ((void)0)
#define portEXIT_CRITICAL_ISR()  ((void)0)

typedef uint32_t     TickType_t;
typedef int          BaseType_t;
typedef unsigned int UBaseType_t;
typedef uint32_t     EventBits_t;

/* BIT macro (also used by event flags in application code) */
#ifndef BIT
#define BIT(n)  (1UL << (n))
#endif

/* CONFIG placeholder used by capture_entropy.c */
#ifndef CONFIG_CACHE_L2_CACHE_LINE_SIZE
#define CONFIG_CACHE_L2_CACHE_LINE_SIZE  64
#endif

/* EventGroup (declared here to avoid circular includes with event_groups.h) */
typedef void *EventGroupHandle_t;

EventGroupHandle_t xEventGroupCreate(void);
EventBits_t        xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t        xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t        xEventGroupGetBits(EventGroupHandle_t group);
EventBits_t        xEventGroupWaitBits(EventGroupHandle_t group,
                                       EventBits_t bits_to_wait,
                                       BaseType_t clear_on_exit,
                                       BaseType_t wait_all,
                                       TickType_t timeout);
void               vEventGroupDelete(EventGroupHandle_t group);
