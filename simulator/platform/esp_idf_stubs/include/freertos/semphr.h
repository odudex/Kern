#pragma once

#include "FreeRTOS.h"

typedef void *SemaphoreHandle_t;

SemaphoreHandle_t xSemaphoreCreateBinary(void);
SemaphoreHandle_t xSemaphoreCreateMutex(void);
BaseType_t        xSemaphoreTake(SemaphoreHandle_t sem, TickType_t timeout);
BaseType_t        xSemaphoreGive(SemaphoreHandle_t sem);
void              vSemaphoreDelete(SemaphoreHandle_t sem);
