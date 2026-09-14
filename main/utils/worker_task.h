/*
 * Worker Task
 * Runs a long crypto operation off the LVGL thread.
 *
 * PBKDF2 at 100k+ iterations starves the core it runs on, so the work is
 * pinned to CPU 1 with that core's idle task temporarily unsubscribed from
 * the task watchdog.  The re-subscribe is guaranteed by the trampoline, so
 * no caller can leak it by returning early.
 *
 * Callers poll *done_flag from an LVGL timer and join with worker_task_wait()
 * before releasing inputs or finishing the flow. The worker suspends after
 * completion so the join can synchronously release and erase its stack.
 */

#ifndef WORKER_TASK_H
#define WORKER_TASK_H

#include "attributes.h"
#include <stdbool.h>
#include <stdint.h>

typedef void (*worker_task_fn_t)(void);

/* Join work before releasing its inputs or deleting its completion timer.
 * Workers never take the LVGL lock, so the UI thread can safely wait here. */
void worker_task_wait(void);

/*
 * Run fn() on CPU 1, then set *done_flag and suspend until joined.
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
