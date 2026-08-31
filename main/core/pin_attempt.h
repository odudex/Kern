#ifndef PIN_ATTEMPT_H
#define PIN_ATTEMPT_H

#include "pin.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  PIN_ATTEMPT_ACCEPT,
  PIN_ATTEMPT_RETRY,
  PIN_ATTEMPT_WIPE,
} pin_attempt_decision_t;

/* A threshold outside the configurable range can only come from a corrupted
 * record or a downgrade from firmware with a wider range. Fall back to the
 * default instead of wiping: a denied attempt is recoverable, a wiped seed is
 * not. */
static inline uint8_t pin_attempt_clamp_max_failures(uint8_t max_failures) {
  if (max_failures < PIN_MIN_MAX_FAILURES ||
      max_failures > PIN_MAX_MAX_FAILURES)
    return PIN_DEFAULT_MAX_FAILURES;
  return max_failures;
}

/* Decide the outcome only after both PIN hashes were computed and compared. */
static inline pin_attempt_decision_t pin_attempt_decide(bool pin_matches,
                                                        uint8_t pending_count,
                                                        uint8_t max_failures) {
  if (pin_matches)
    return PIN_ATTEMPT_ACCEPT;
  if (pending_count >= max_failures)
    return PIN_ATTEMPT_WIPE;
  return PIN_ATTEMPT_RETRY;
}

#endif // PIN_ATTEMPT_H
