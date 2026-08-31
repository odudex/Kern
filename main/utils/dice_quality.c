#include "dice_quality.h"

#include "estimated_entropy.h"
#include <math.h>
#include <string.h>

#define D6_SIDES 6U
#define D6_DERIVATIVE_BINS (D6_SIDES * 2U - 1U)
#define PATTERN_DETECTION_TOLERANCE_PERCENT 30U

bool dice_quality_analyze_d6(const char *rolls, size_t roll_count,
                             size_t minimum_rolls,
                             uint32_t target_estimated_entropy_bits,
                             dice_quality_result_t *result) {
  if (!rolls || roll_count == 0 || minimum_rolls == 0 || !result)
    return false;

  memset(result, 0, sizeof(*result));

  uint32_t roll_counts[D6_SIDES] = {0};
  for (size_t i = 0; i < roll_count; i++) {
    if (rolls[i] < '1' || rolls[i] > '6')
      return false;
    roll_counts[(size_t)(rolls[i] - '1')]++;
  }

  result->estimated_entropy_bits =
      estimated_shannon_entropy_from_counts(roll_counts, D6_SIDES, roll_count) *
      (double)roll_count;
  result->low_estimated_entropy =
      result->estimated_entropy_bits <= (double)target_estimated_entropy_bits;

  // Match Krux's behavior: wait for half the required rolls before attempting
  // to infer a pattern from consecutive-roll differences.
  if (roll_count < minimum_rolls / 2 || roll_count < 2)
    return true;

  uint32_t derivative_counts[D6_DERIVATIVE_BINS] = {0};
  for (size_t i = 1; i < roll_count; i++) {
    int derivative = rolls[i] - rolls[i - 1];
    size_t derivative_index = (size_t)(derivative + (int)D6_SIDES - 1);
    derivative_counts[derivative_index]++;
  }

  double derivative_estimate = estimated_shannon_entropy_from_counts(
      derivative_counts, D6_DERIVATIVE_BINS, roll_count - 1);
  double maximum_estimate = log2((double)D6_DERIVATIVE_BINS);
  double pattern_score =
      derivative_estimate < maximum_estimate
          ? (maximum_estimate - derivative_estimate) / maximum_estimate * 100.0
          : 0.0;

  // Krux truncates the score before applying its 30% threshold.
  result->pattern_detected =
      (uint32_t)pattern_score > PATTERN_DETECTION_TOLERANCE_PERCENT;
  return true;
}
