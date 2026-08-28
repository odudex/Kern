/*
 * Worker Task
 * Runs a long crypto operation off the LVGL thread.
 *
 * PBKDF2 at 100k+ iterations starves the core it runs on, so the work is
 * pinned to CPU 1 with that core's idle task temporarily unsubscribed from
 * the task watchdog.  The re-subscribe is guaranteed by the trampoline, so
 * no caller can leak it by returning early.
 *
 * The worker owns its own lifetime: it self-deletes and is never killed from
 * outside, which is what keeps the handle from going stale.  Callers poll
 * *done_flag from an LVGL timer.
 */

#ifndef WORKER_TASK_H
#define WORKER_TASK_H

#include "attributes.h"
#include <stdbool.h>
#include <stdint.h>

typedef void (*worker_task_fn_t)(void);

/*
 * Run fn() on CPU 1, then set *done_flag and self-delete.
 *
 * name        — FreeRTOS task name
 * stack_bytes — task stack size
 * fn          — work to run; must not touch LVGL
 * done_flag   — set true once fn() has returned and the WDT is restored
 *
 * Returns false if the task could not be created (done_flag is left alone).
 */
KERN_WARN_UNUSED_RESULT bool worker_task_start(const char *name,
                                               uint32_t stack_bytes,
                                               worker_task_fn_t fn,
                                               volatile bool *done_flag);

#endif /* WORKER_TASK_H */
