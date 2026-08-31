#include "estimated_entropy.h"

#include <math.h>

double estimated_shannon_entropy_from_counts(const uint32_t *counts,
                                             size_t bin_count,
                                             size_t sample_count) {
  if (!counts || bin_count == 0 || sample_count == 0)
    return 0.0;

  double estimated_entropy = 0.0;
  for (size_t i = 0; i < bin_count; i++) {
    if (counts[i] == 0)
      continue;

    double probability = (double)counts[i] / (double)sample_count;
    estimated_entropy -= probability * log2(probability);
  }

  return estimated_entropy;
}

float estimated_shannon_entropy_from_counts_f(const uint32_t *counts,
                                              size_t bin_count,
                                              size_t sample_count) {
  if (!counts || bin_count == 0 || sample_count == 0)
    return 0.0f;

  double weighted_log_sum = 0.0;
  for (size_t i = 0; i < bin_count; i++) {
    if (counts[i] == 0)
      continue;

    float count = (float)counts[i];
    weighted_log_sum += (double)(count * log2f(count));
  }

  float estimated_entropy = log2f((float)sample_count) -
                            (float)(weighted_log_sum / (double)sample_count);

  return estimated_entropy > 0.0f ? estimated_entropy : 0.0f;
}
