#pragma once

#include "FreeRTOS.h"

typedef void *QueueHandle_t;

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size);
BaseType_t    xQueueSend(QueueHandle_t queue, const void *item,
                         TickType_t timeout);
BaseType_t    xQueueReceive(QueueHandle_t queue, void *buffer,
                            TickType_t timeout);
void          vQueueDelete(QueueHandle_t queue);
