#ifndef DICE_QUALITY_H
#define DICE_QUALITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  double estimated_entropy_bits;
  bool low_estimated_entropy;
  bool pattern_detected;
} dice_quality_result_t;

/**
 * Analyze ASCII d6 rolls using the distribution and derivative checks used by
 * Krux. The estimated entropy is an observation-based Shannon estimate, not a
 * measurement of cryptographic entropy.
 *
 * low_estimated_entropy is set unless the total estimate is strictly greater
 * than target_estimated_entropy_bits.
 *
 * Returns false if the arguments or a roll value are invalid.
 */
bool dice_quality_analyze_d6(const char *rolls, size_t roll_count,
                             size_t minimum_rolls,
                             uint32_t target_estimated_entropy_bits,
                             dice_quality_result_t *result);

#endif // DICE_QUALITY_H
