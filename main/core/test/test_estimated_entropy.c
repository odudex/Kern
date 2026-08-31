#include "utils/dice_quality.h"
#include "utils/estimated_entropy.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAIL: %s\n", message);                                  \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static void test_histogram_estimate(void) {
  const uint32_t fair_d6[] = {10, 10, 10, 10, 10, 10};
  double estimate = estimated_shannon_entropy_from_counts(fair_d6, 6, 60);
  CHECK(fabs(estimate - log2(6.0)) < 0.000001, "fair d6 histogram estimate");

  const uint32_t single_value[] = {50, 0, 0, 0, 0, 0};
  estimate = estimated_shannon_entropy_from_counts(single_value, 6, 50);
  CHECK(fabs(estimate) < 0.000001, "single-value histogram estimate");
  CHECK(estimated_shannon_entropy_from_counts(NULL, 6, 50) == 0.0,
        "NULL histogram");
  CHECK(estimated_shannon_entropy_from_counts(fair_d6, 6, 0) == 0.0,
        "empty histogram");
}

static void test_single_precision_variant(void) {
  const uint32_t fair_d6[] = {10, 10, 10, 10, 10, 10};
  CHECK(fabsf(estimated_shannon_entropy_from_counts_f(fair_d6, 6, 60) -
              (float)log2(6.0)) < 0.0001f,
        "float fair d6 histogram estimate");

  const uint32_t single_value[] = {50, 0, 0, 0, 0, 0};
  CHECK(estimated_shannon_entropy_from_counts_f(single_value, 6, 50) == 0.0f,
        "float single-value histogram estimate");
  CHECK(estimated_shannon_entropy_from_counts_f(NULL, 6, 50) == 0.0f,
        "float NULL histogram");
  CHECK(estimated_shannon_entropy_from_counts_f(fair_d6, 6, 0) == 0.0f,
        "float empty histogram");

  // A camera-sized histogram: 65536 RGB565 bins over 720x720 pixels. The
  // folded single-precision form must track the double reference closely
  // enough for the 6.0 bits-per-pixel threshold to behave identically.
  static uint32_t histogram[65536];
  size_t total = 0;
  for (size_t i = 0; i < 65536; i++) {
    histogram[i] = (uint32_t)(i % 37);
    total += histogram[i];
  }
  double reference =
      estimated_shannon_entropy_from_counts(histogram, 65536, total);
  float folded =
      estimated_shannon_entropy_from_counts_f(histogram, 65536, total);
  CHECK(fabs((double)folded - reference) < 0.001,
        "float variant matches double reference on a camera-sized histogram");

  // Skewed histogram: one dominant bin plus a long tail.
  memset(histogram, 0, sizeof(histogram));
  histogram[0] = 500000;
  total = 500000;
  for (size_t i = 1; i < 65536; i++) {
    histogram[i] = (uint32_t)(i % 5);
    total += histogram[i];
  }
  reference = estimated_shannon_entropy_from_counts(histogram, 65536, total);
  folded = estimated_shannon_entropy_from_counts_f(histogram, 65536, total);
  CHECK(fabs((double)folded - reference) < 0.001,
        "float variant matches double reference on a skewed histogram");
}

static void test_dice_quality(void) {
  // These fixtures include the good and poor d6 sequences in Krux's tests.
  const char below_target[] =
      "25631435566616343636163254164521414665325265631441";
  const char above_target[] =
      "61425214614536152352236121565246153162534334421463";
  char poor[51];
  size_t offset = 0;
  const size_t poor_counts[] = {10, 10, 10, 10, 6, 4};
  for (size_t side = 0; side < 6; side++) {
    memset(poor + offset, (int)('1' + side), poor_counts[side]);
    offset += poor_counts[side];
  }
  poor[offset] = '\0';

  dice_quality_result_t quality;
  CHECK(dice_quality_analyze_d6(below_target, strlen(below_target), 50, 128,
                                &quality),
        "analyze rolls below 12-word target");
  CHECK(fabs(quality.estimated_entropy_bits - 126.47745267846521) < 0.000001,
        "unrounded estimated entropy bits");
  CHECK(quality.low_estimated_entropy,
        "sequence below 128 bits fails estimated entropy check");
  CHECK(!quality.pattern_detected,
        "below-target sequence has no detected pattern");

  CHECK(dice_quality_analyze_d6(above_target, strlen(above_target), 50, 128,
                                &quality),
        "analyze rolls above 12-word target");
  CHECK(quality.estimated_entropy_bits > 128.0,
        "sequence exceeds 128 estimated bits");
  CHECK(!quality.low_estimated_entropy,
        "sequence above 128 bits passes estimated entropy check");
  CHECK(!quality.pattern_detected,
        "above-target sequence has no detected pattern");

  CHECK(dice_quality_analyze_d6(poor, strlen(poor), 50, 128, &quality),
        "analyze poor rolls");
  CHECK(fabs(quality.estimated_entropy_bits - 125.8059106889148) < 0.000001,
        "poor estimated entropy bits");
  CHECK(quality.low_estimated_entropy,
        "poor sequence fails estimated entropy check");
  CHECK(quality.pattern_detected, "poor sequence pattern detected");

  const char low_only[] = "51324213614436142352236111554235142152434234421363";
  CHECK(dice_quality_analyze_d6(low_only, strlen(low_only), 50, 128, &quality),
        "analyze low-estimate rolls without pattern");
  CHECK(quality.low_estimated_entropy,
        "low-only sequence fails estimated entropy check");
  CHECK(!quality.pattern_detected, "low-only sequence has no detected pattern");

  char above_24_word_target[101];
  memcpy(above_24_word_target, above_target, 50);
  memcpy(above_24_word_target + 50, above_target, 51);
  CHECK(dice_quality_analyze_d6(above_24_word_target, 100, 99, 256, &quality),
        "analyze rolls above 24-word target");
  CHECK(quality.estimated_entropy_bits > 256.0,
        "sequence exceeds 256 estimated bits");
  CHECK(!quality.low_estimated_entropy,
        "sequence above 256 bits passes estimated entropy check");

  CHECK(dice_quality_analyze_d6("1", 1, 1, 0, &quality),
        "analyze exact-threshold sequence");
  CHECK(quality.low_estimated_entropy,
        "exact threshold does not satisfy strict greater-than requirement");

  char cycle[51];
  for (size_t i = 0; i < 50; i++)
    cycle[i] = (char)('1' + i % 6);
  cycle[50] = '\0';
  CHECK(dice_quality_analyze_d6(cycle, 50, 50, 128, &quality),
        "analyze patterned rolls");
  CHECK(!quality.low_estimated_entropy,
        "balanced pattern passes estimated entropy check");
  CHECK(quality.pattern_detected, "balanced pattern detected");

  CHECK(!dice_quality_analyze_d6("123x", 4, 50, 128, &quality),
        "reject invalid d6 roll");
}

int main(void) {
  test_histogram_estimate();
  test_single_precision_variant();
  test_dice_quality();

  if (failures) {
    fprintf(stderr, "%d estimated entropy test(s) failed\n", failures);
    return 1;
  }

  puts("All estimated entropy tests passed");
  return 0;
}
