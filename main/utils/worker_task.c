#include "worker_task.h"
#include <esp_heap_caps.h>
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
static bool worker_running;
static TaskHandle_t worker_handle;

static void worker_trampoline(void *arg) {
  (void)arg;

  TaskHandle_t idle = xTaskGetIdleTaskHandleForCore(WORKER_TASK_CORE);
  esp_task_wdt_delete(idle);

  worker_ctx.fn();

  esp_task_wdt_add(idle);
  *worker_ctx.done_flag = true;
  __atomic_store_n(&worker_running, false, __ATOMIC_RELEASE);
  // The UI joins and deletes this task with its owned stack. Self-deletion
  // would defer stack erasure to an idle task, possibly beyond session lock.
  vTaskSuspend(NULL);
}

void worker_task_wait(void) {
  while (__atomic_load_n(&worker_running, __ATOMIC_ACQUIRE))
    vTaskDelay(1);
  if (worker_handle) {
    vTaskDeleteWithCaps(worker_handle);
    worker_handle = NULL;
    worker_ctx = (worker_ctx_t){0};
  }
}

bool worker_task_start(const char *name, uint32_t stack_bytes,
                       worker_task_fn_t fn, volatile bool *done_flag) {
  if (!fn || !done_flag)
    return false;

  if (__atomic_load_n(&worker_running, __ATOMIC_ACQUIRE))
    return false;
  worker_task_wait();

  bool expected = false;
  if (!__atomic_compare_exchange_n(&worker_running, &expected, true, false,
                                   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    return false;

  worker_ctx.fn = fn;
  worker_ctx.done_flag = done_flag;

  bool started = xTaskCreatePinnedToCoreWithCaps(
                     worker_trampoline, name, stack_bytes, NULL,
                     WORKER_TASK_PRIORITY, &worker_handle, WORKER_TASK_CORE,
                     MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) == pdPASS;
  if (!started)
    __atomic_store_n(&worker_running, false, __ATOMIC_RELEASE);
  return started;
}
