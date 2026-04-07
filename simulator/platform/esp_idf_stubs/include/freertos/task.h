#pragma once

#include "FreeRTOS.h"
#include <stddef.h>

typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);

BaseType_t xTaskCreate(TaskFunction_t func, const char *name,
                       uint32_t stack_size, void *param,
                       UBaseType_t priority, TaskHandle_t *handle);

BaseType_t xTaskCreatePinnedToCore(TaskFunction_t func, const char *name,
                                   uint32_t stack_size, void *param,
                                   UBaseType_t priority, TaskHandle_t *handle,
                                   int core_id);

void vTaskDelete(TaskHandle_t handle);
void vTaskDelay(TickType_t ticks);
void vTaskSuspend(TaskHandle_t handle);

static inline TaskHandle_t xTaskGetIdleTaskHandleForCore(int core_id) {
    (void)core_id;
    return NULL;
}
