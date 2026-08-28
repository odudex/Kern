#include "worker_task.h"
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/idf_additions.h>
#include <freertos/task.h>

#define WORKER_TASK_PRIORITY 5
#define WORKER_TASK_CORE 1

typedef struct {
  worker_task_fn_t fn;
  volatile bool *done_flag;
} worker_ctx_t;

static worker_ctx_t worker_ctx;

static void worker_trampoline(void *arg) {
  (void)arg;

  TaskHandle_t idle = xTaskGetIdleTaskHandleForCore(WORKER_TASK_CORE);
  esp_task_wdt_delete(idle);

  worker_ctx.fn();

  esp_task_wdt_add(idle);
  *worker_ctx.done_flag = true;
  vTaskDelete(NULL);
}

bool worker_task_start(const char *name, uint32_t stack_bytes,
                       worker_task_fn_t fn, volatile bool *done_flag) {
  if (!fn || !done_flag)
    return false;

  worker_ctx.fn = fn;
  worker_ctx.done_flag = done_flag;

  return xTaskCreatePinnedToCore(worker_trampoline, name, stack_bytes, NULL,
                                 WORKER_TASK_PRIORITY, NULL,
                                 WORKER_TASK_CORE) == pdPASS;
}
