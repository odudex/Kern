#pragma once
#include <stdint.h>
#include <time.h>

// Host stub: no cycle counter, so use the monotonic clock's nanosecond field.
// Same role - a fast-moving counter sampled at asynchronous event times.
static inline uint32_t esp_cpu_get_cycle_count(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_nsec;
}
