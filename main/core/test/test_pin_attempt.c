#include "core/pin_attempt.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static int failures = 0;

#define CHECK(actual, expected, message)                                       \
  do {                                                                         \
    if ((actual) != (expected)) {                                              \
      fprintf(stderr, "FAIL: %s\n", message);                                  \
      failures++;                                                              \
    }                                                                          \
  } while (0)

int main(void) {
  const uint8_t max_fail = 10;

  CHECK(pin_attempt_decide(true, max_fail - 1, max_fail), PIN_ATTEMPT_ACCEPT,
        "correct PIN before threshold unlocks");
  CHECK(pin_attempt_decide(false, max_fail - 1, max_fail), PIN_ATTEMPT_RETRY,
        "incorrect PIN before threshold retries");
  CHECK(pin_attempt_decide(true, max_fail, max_fail), PIN_ATTEMPT_ACCEPT,
        "correct PIN at threshold unlocks");
  CHECK(pin_attempt_decide(false, max_fail, max_fail), PIN_ATTEMPT_WIPE,
        "incorrect PIN at threshold wipes");
  CHECK(pin_attempt_decide(true, max_fail + 1, max_fail), PIN_ATTEMPT_ACCEPT,
        "correct PIN past threshold unlocks after an interrupted wipe");

  CHECK(pin_attempt_decide(true, 5, 5), PIN_ATTEMPT_ACCEPT,
        "correct PIN at minimum valid threshold unlocks");
  CHECK(pin_attempt_decide(false, 4, 5), PIN_ATTEMPT_RETRY,
        "incorrect PIN before minimum valid threshold retries");
  CHECK(pin_attempt_decide(false, 5, 5), PIN_ATTEMPT_WIPE,
        "incorrect PIN at minimum valid threshold wipes");
  CHECK(pin_attempt_decide(true, 50, 50), PIN_ATTEMPT_ACCEPT,
        "correct PIN at maximum valid threshold unlocks");
  CHECK(pin_attempt_decide(false, 49, 50), PIN_ATTEMPT_RETRY,
        "incorrect PIN before maximum valid threshold retries");
  CHECK(pin_attempt_decide(false, 50, 50), PIN_ATTEMPT_WIPE,
        "incorrect PIN at maximum valid threshold wipes");

  for (uint16_t threshold = 0; threshold <= UINT8_MAX; threshold++) {
    uint8_t clamped = pin_attempt_clamp_max_failures((uint8_t)threshold);
    if (threshold >= PIN_MIN_MAX_FAILURES && threshold <= PIN_MAX_MAX_FAILURES)
      CHECK(clamped, (uint8_t)threshold, "valid thresholds are kept as-is");
    else
      CHECK(clamped, PIN_DEFAULT_MAX_FAILURES,
            "invalid thresholds fall back to the default");
  }

  /* A corrupted threshold must never cost the owner their seed. */
  CHECK(pin_attempt_decide(true, 1, pin_attempt_clamp_max_failures(0)),
        PIN_ATTEMPT_ACCEPT, "correct PIN with zero threshold unlocks");
  CHECK(pin_attempt_decide(true, 1, pin_attempt_clamp_max_failures(255)),
        PIN_ATTEMPT_ACCEPT, "correct PIN with 255 threshold unlocks");
  CHECK(pin_attempt_decide(false, 1, pin_attempt_clamp_max_failures(0)),
        PIN_ATTEMPT_RETRY, "incorrect PIN with zero threshold retries");
  CHECK(pin_attempt_decide(false, PIN_DEFAULT_MAX_FAILURES,
                           pin_attempt_clamp_max_failures(255)),
        PIN_ATTEMPT_WIPE, "incorrect PIN at the clamped threshold still wipes");

  if (failures) {
    fprintf(stderr, "%d PIN attempt decision test(s) failed\n", failures);
    return 1;
  }

  puts("All PIN attempt decision tests passed");
  return 0;
}
