#ifndef ESTIMATED_ENTROPY_H
#define ESTIMATED_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

/**
 * Estimate the Shannon entropy of an observed histogram, in bits per sample.
 *
 * This describes the distribution of the supplied samples. It is not an
 * estimate of cryptographic entropy.
 */
double estimated_shannon_entropy_from_counts(const uint32_t *counts,
                                             size_t bin_count,
                                             size_t sample_count);

/**
 * Single-precision variant for large histograms, using the algebraically
 * folded form H = log2(N) - (1/N) * sum(c_i * log2(c_i)) so the per-bin divide
 * disappears. The ESP32-P4 FPU is single-precision only, so log2f() is a
 * hardware op where log2() traps into soft-float; the sum is still accumulated
 * in double to avoid drift over tens of thousands of bins.
 *
 * Accurate to a few decimal places, which is ample for threshold comparisons.
 * Use the double version where exact agreement with a reference is needed.
 */
float estimated_shannon_entropy_from_counts_f(const uint32_t *counts,
                                              size_t bin_count,
                                              size_t sample_count);

#endif // ESTIMATED_ENTROPY_H
