#include "../parser.h"
#include "bbqr.h"
#include "ur_decoder.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(QR_PARSER_MAX_MULTIPART_PARTS == 1024,
               "update multipart limit boundary fixtures");

static int failures;

// Counts down on each malloc; the call that reaches zero fails.
static int malloc_fail_countdown;

void *__real_malloc(size_t size);

void *__wrap_malloc(size_t size) {
  if (malloc_fail_countdown > 0 && --malloc_fail_countdown == 0) {
    return NULL;
  }
  return __real_malloc(size);
}

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #condition);     \
      failures++;                                                              \
      return;                                                                  \
    }                                                                          \
  } while (0)

static int parse_str(QRPartParser *parser, const char *data) {
  return qr_parser_parse_with_len(parser, data, strlen(data));
}

static char *pmofn_frame(int index, int total, size_t payload_len, char fill) {
  int prefix_len = snprintf(NULL, 0, "p%dof%d ", index, total);
  if (prefix_len < 0 || payload_len > SIZE_MAX - (size_t)prefix_len - 1) {
    return NULL;
  }
  char *frame = malloc((size_t)prefix_len + payload_len + 1);
  if (!frame) {
    return NULL;
  }
  snprintf(frame, (size_t)prefix_len + 1, "p%dof%d ", index, total);
  memset(frame + prefix_len, fill, payload_len);
  frame[(size_t)prefix_len + payload_len] = '\0';
  return frame;
}

static void test_format_none_still_completes(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  int parse_result = parse_str(parser, "plain text");
  CHECK(parse_result == -1);
  CHECK(qr_parser_get_format(parser) == FORMAT_NONE);
  CHECK(qr_parser_is_complete(parser));
  CHECK(!qr_parser_is_failed(parser));
  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  CHECK(result != NULL);
  CHECK(result_len == 10);
  CHECK(memcmp(result, "plain text", result_len) == 0);
  free(result);
  qr_parser_destroy(parser);
}

static void test_incomplete_pmofn_like_text_remains_plain(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "p1of2") == -1);
  CHECK(qr_parser_get_format(parser) == FORMAT_NONE);
  CHECK(qr_parser_is_complete(parser));
  CHECK(!qr_parser_is_failed(parser));
  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  CHECK(result != NULL);
  CHECK(result_len == 5);
  CHECK(memcmp(result, "p1of2", result_len) == 0);
  free(result);
  qr_parser_destroy(parser);
}

static void test_valid_pmofn_still_assembles(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "p2of2 world") == 1);
  CHECK(parse_str(parser, "p1of2 hello ") == 0);
  CHECK(qr_parser_is_complete(parser));
  CHECK(!qr_parser_is_failed(parser));
  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  CHECK(result != NULL);
  CHECK(result_len == 11);
  CHECK(memcmp(result, "hello world", result_len) == 0);
  free(result);
  qr_parser_destroy(parser);
}

static void test_pmofn_rejects_nonpositive_and_overflow_metadata(void) {
  const char *invalid[] = {
      "p0of2 zero",
      "p1of0 zero",
      "p-1of2 negative",
      "p1of-2 negative",
      "p999999999999999999999999of2 overflow",
      "p1of999999999999999999999999 overflow",
      "p3of2 range",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    CHECK(parse_str(parser, invalid[i]) == -1);
    CHECK(qr_parser_is_failed(parser));
    CHECK(!qr_parser_is_complete(parser));
    qr_parser_destroy(parser);
  }
}

static void test_pmofn_rejects_part_count_over_limit(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "p1of1025 data") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->parts_count == 0);
  qr_parser_destroy(parser);
}

static void test_pmofn_binds_total_to_first_accepted_frame(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "p1of2 first") == 0);
  CHECK(parse_str(parser, "p2of3 second") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->parts_count == 1);
  CHECK(parse_str(parser, "p2of2 ignored") == -1);
  CHECK(parser->parts_count == 1);
  qr_parser_destroy(parser);
}

static void test_pmofn_rejects_aggregate_budget_at_insertion(void) {
  QRPartParser *parser = qr_parser_create();
  char *large = pmofn_frame(1, 2, QR_PARSER_MAX_STORED_BYTES, 'A');
  CHECK(parser != NULL);
  CHECK(large != NULL);
  CHECK(parse_str(parser, large) == 0);
  CHECK(parse_str(parser, "p2of2 B") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->too_large);
  CHECK(parser->parts_count == 1);
  free(large);
  qr_parser_destroy(parser);
}

static void test_pmofn_replacement_updates_aggregate_accounting(void) {
  QRPartParser *parser = qr_parser_create();
  char *large_first = pmofn_frame(1, 2, QR_PARSER_MAX_STORED_BYTES - 1, 'A');
  char *large_second = pmofn_frame(2, 2, QR_PARSER_MAX_STORED_BYTES - 1, 'B');
  CHECK(parser != NULL);
  CHECK(large_first != NULL);
  CHECK(large_second != NULL);
  CHECK(parse_str(parser, large_first) == 0);
  CHECK(parse_str(parser, "p1of2 C") == 0);
  CHECK(parse_str(parser, large_second) == 1);
  CHECK(qr_parser_is_complete(parser));
  CHECK(!qr_parser_is_failed(parser));
  free(large_first);
  free(large_second);
  qr_parser_destroy(parser);
}

static void test_allocation_failure_is_terminal(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  malloc_fail_countdown = 1;
  CHECK(parse_str(parser, "p1of2 hello ") == -1);
  malloc_fail_countdown = 0;
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->alloc_failed);
  CHECK(!qr_parser_is_complete(parser));
  CHECK(parser->parts_count == 0);
  CHECK(parse_str(parser, "p1of2 hello ") == -1);
  CHECK(parser->parts_count == 0);
  CHECK(qr_parser_result(parser, NULL) == NULL);
  qr_parser_destroy(parser);
}

static void test_metadata_failure_is_not_an_allocation_failure(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "p3of2 range") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(!parser->alloc_failed);
  qr_parser_destroy(parser);
}

static void test_bbqr_binds_total_encoding_and_file_type(void) {
  const char *inconsistent[] = {
      "B$HU030141", /* total */
      "B$2U020141", /* encoding */
      "B$HP020141", /* file type */
  };
  for (size_t i = 0; i < sizeof(inconsistent) / sizeof(inconsistent[0]); i++) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    CHECK(parse_str(parser, "B$HU020041") == 0);
    CHECK(parse_str(parser, inconsistent[i]) == -1);
    CHECK(qr_parser_is_failed(parser));
    CHECK(parser->parts_count == 1);
    qr_parser_destroy(parser);
  }
}

static void test_bbqr_rejects_part_count_over_limit(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "B$HUSH0041") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->too_large);
  CHECK(parser->parts_count == 0);
  qr_parser_destroy(parser);
}

static char *bbqr_frame(int index, int total, size_t payload_len) {
  char *frame = malloc(BBQR_HEADER_LEN + payload_len + 1);
  if (!frame)
    return NULL;
  memcpy(frame, "B$HP", 4);
  bbqr_base36_encode(total, &frame[4], &frame[5]);
  bbqr_base36_encode(index, &frame[6], &frame[7]);
  memset(frame + BBQR_HEADER_LEN, 'A', payload_len);
  frame[BBQR_HEADER_LEN + payload_len] = '\0';
  return frame;
}

static void test_bbqr_rejects_oversized_sequence_on_first_frame(void) {
  // Realistic QR payloads, even HEX lengths: 1023 * 1026 exceeds 1 MiB.
  char *frame = bbqr_frame(0, 1024, 1026);
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(frame != NULL);
  CHECK(parse_str(parser, frame) == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->too_large);
  CHECK(!parser->alloc_failed);
  CHECK(parser->parts_count == 0);
  free(frame);
  qr_parser_destroy(parser);
}

static void test_bbqr_large_roundtrips(void) {
  const int totals[] = {100, 101, 1024};
  for (size_t t = 0; t < sizeof(totals) / sizeof(totals[0]); t++) {
    int total = totals[t];
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    for (int i = total - 1; i >= 0; i--) {
      // Reverse order, including last-frame-first and repeated frames.
      char *frame = bbqr_frame(i, total, 1024);
      CHECK(frame != NULL);
      CHECK(parse_str(parser, frame) == i);
      CHECK(parse_str(parser, frame) == i);
      CHECK(parser->parts_count == total - i);
      CHECK(qr_parser_is_complete(parser) == (i == 0));
      free(frame);
    }
    CHECK(parser->stored_bytes == (size_t)total * 1024);
    size_t len = 0;
    char *result = qr_parser_result(parser, &len);
    CHECK(result != NULL);
    CHECK(len == (size_t)total * 512);
    qr_parser_destroy(parser); // The result belongs entirely to the caller.
    for (size_t i = 0; i < len; i++)
      CHECK((unsigned char)result[i] == 0xAA);
    CHECK(result[len] == '\0');
    free(result);
  }
}

static void test_bbqr_short_last_frame_arrives_first(void) {
  for (size_t payload_len = 1024; payload_len <= 1026; payload_len += 2) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    char *last = bbqr_frame(1023, 1024, 2);
    CHECK(last != NULL);
    CHECK(parse_str(parser, last) == 1023);
    CHECK(!qr_parser_is_failed(parser));
    free(last);
    for (int i = 0; i < 1023; i++) {
      char *full = bbqr_frame(i, 1024, payload_len);
      CHECK(full != NULL);
      int rc = parse_str(parser, full);
      free(full);
      if (payload_len == 1026) {
        CHECK(rc == -1);
        CHECK(parser->too_large);
        CHECK(parser->parts_count == 1);
        break;
      }
      CHECK(rc == i);
    }
    if (payload_len == 1024) {
      CHECK(qr_parser_is_complete(parser));
      size_t len = 0;
      char *result = qr_parser_result(parser, &len);
      CHECK(result != NULL);
      CHECK(len == 1023 * 512 + 1);
      CHECK(result[len] == '\0');
      free(result);
    }
    qr_parser_destroy(parser);
  }
}

static void test_pmofn_variable_lengths_within_budget(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  for (int i = 1; i <= 1024; i++) {
    char *frame = pmofn_frame(i, 1024, i == 1 ? 1028 : 1000, 'A');
    CHECK(frame != NULL);
    CHECK(parse_str(parser, frame) == i - 1);
    free(frame);
  }
  CHECK(qr_parser_is_complete(parser));
  CHECK(parser->stored_bytes == 1024028);
  size_t len = 0;
  char *result = qr_parser_result(parser, &len);
  CHECK(result != NULL);
  CHECK(len == 1024028);
  free(result);
  qr_parser_destroy(parser);
}

static void test_identical_duplicates_do_not_allocate(void) {
  const char *frames[] = {"p1of2 AAAA", "B$HP0200AAAA"};
  for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    CHECK(parse_str(parser, frames[i]) == 0);
    malloc_fail_countdown = 1;
    int rc = parse_str(parser, frames[i]);
    int remaining = malloc_fail_countdown;
    malloc_fail_countdown = 0;
    CHECK(rc == 0);
    CHECK(remaining == 1);
    CHECK(!qr_parser_is_failed(parser));
    CHECK(parser->parts_count == 1);
    CHECK(parser->stored_bytes == 4);
    qr_parser_destroy(parser);
  }
}

static void test_bbqr_binary_result_encodings(void) {
  // All three encodings must return caller-owned, terminated binary data.
  const char *frames[] = {"B$HP010000FF", "B$2P0100AD7Q", "B$ZP0100MP4A6AA"};
  for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    CHECK(parse_str(parser, frames[i]) == 0);
    size_t len = 99;
    // HEX/Base32 need just the assembled input and decoded output allocations;
    // a third allocation for a retained result copy would fail this test.
    if (i < 2)
      malloc_fail_countdown = 3;
    char *result = qr_parser_result(parser, &len);
    int remaining = malloc_fail_countdown;
    malloc_fail_countdown = 0;
    CHECK(result != NULL);
    CHECK(i >= 2 || remaining == 1);
    CHECK(len == 2);
    qr_parser_destroy(parser);
    CHECK(result[0] == 0 && (unsigned char)result[1] == 0xFF);
    CHECK(result[2] == 0);
    free(result);
  }
}

static void test_bbqr_result_failure_clears_length(void) {
  const char *frames[] = {"B$HP0100AA", "B$HP0100A"};
  for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
    QRPartParser *parser = qr_parser_create();
    CHECK(parser != NULL);
    CHECK(parse_str(parser, frames[i]) == 0);
    // Exercise both allocation failure and invalid encoded data.
    malloc_fail_countdown = i == 0 ? 1 : 0;
    size_t len = 99;
    char *result = qr_parser_result(parser, &len);
    malloc_fail_countdown = 0;
    CHECK(result == NULL);
    CHECK(len == 0);
    qr_parser_destroy(parser);
  }
}

static void test_valid_bbqr_still_assembles(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, "B$HU020142") == 1);
  CHECK(parse_str(parser, "B$HU020041") == 0);
  CHECK(qr_parser_is_complete(parser));
  CHECK(!qr_parser_is_failed(parser));
  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  CHECK(result != NULL);
  CHECK(result_len == 2);
  CHECK(memcmp(result, "AB", result_len) == 0);
  free(result);
  qr_parser_destroy(parser);
}

static void test_valid_ur_still_processes(void) {
  const char *fragment =
      "UR:BYTES/41-7/LPCSDTATCFADGUCYIMCWLYCTHDEHGEKKJLHSFWIMHFHKGEGRGOFGHD"
      "ESGRIEKKIDEEIYIOFGHSFGGOGYJNHTGLFLGOEMEHGYEHKTHTIOHTINFLGTEHFLJLEMJO"
      "ECESSFSBRDAX";
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(parse_str(parser, fragment) >= 0);
  CHECK(qr_parser_get_format(parser) == FORMAT_UR);
  CHECK(!qr_parser_is_failed(parser));
  CHECK(ur_decoder_processed_parts_count(parser->ur_decoder) == 1);
  qr_parser_destroy(parser);
}

int main(void) {
  test_format_none_still_completes();
  test_incomplete_pmofn_like_text_remains_plain();
  test_valid_pmofn_still_assembles();
  test_pmofn_rejects_nonpositive_and_overflow_metadata();
  test_pmofn_rejects_part_count_over_limit();
  test_pmofn_binds_total_to_first_accepted_frame();
  test_pmofn_rejects_aggregate_budget_at_insertion();
  test_pmofn_replacement_updates_aggregate_accounting();
  test_allocation_failure_is_terminal();
  test_metadata_failure_is_not_an_allocation_failure();
  test_bbqr_binds_total_encoding_and_file_type();
  test_bbqr_rejects_part_count_over_limit();
  test_bbqr_rejects_oversized_sequence_on_first_frame();
  test_bbqr_large_roundtrips();
  test_bbqr_short_last_frame_arrives_first();
  test_pmofn_variable_lengths_within_budget();
  test_identical_duplicates_do_not_allocate();
  test_bbqr_binary_result_encodings();
  test_bbqr_result_failure_clears_length();
  test_valid_bbqr_still_assembles();
  test_valid_ur_still_processes();

  if (failures != 0) {
    fprintf(stderr, "%d QR parser test(s) failed\n", failures);
    return 1;
  }
  puts("All QR parser tests passed.");
  return 0;
}
