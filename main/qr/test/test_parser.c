#include "../parser.h"

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
  int parse_result = qr_parser_parse(parser, "plain text");
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
  CHECK(qr_parser_parse(parser, "p1of2") == -1);
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
  CHECK(qr_parser_parse(parser, "p2of2 world") == 1);
  CHECK(qr_parser_parse(parser, "p1of2 hello ") == 0);
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
    CHECK(qr_parser_parse(parser, invalid[i]) == -1);
    CHECK(qr_parser_is_failed(parser));
    CHECK(!qr_parser_is_complete(parser));
    qr_parser_destroy(parser);
  }
}

static void test_pmofn_rejects_part_count_over_limit(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(qr_parser_parse(parser, "p1of1025 data") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(qr_parser_parsed_count(parser) == 0);
  qr_parser_destroy(parser);
}

static void test_pmofn_binds_total_to_first_accepted_frame(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(qr_parser_parse(parser, "p1of2 first") == 0);
  CHECK(qr_parser_parse(parser, "p2of3 second") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(qr_parser_parsed_count(parser) == 1);
  CHECK(qr_parser_parse(parser, "p2of2 ignored") == -1);
  CHECK(qr_parser_parsed_count(parser) == 1);
  qr_parser_destroy(parser);
}

static void test_pmofn_rejects_aggregate_budget_at_insertion(void) {
  QRPartParser *parser = qr_parser_create();
  char *large = pmofn_frame(1, 2, QR_PARSER_MAX_STORED_BYTES, 'A');
  CHECK(parser != NULL);
  CHECK(large != NULL);
  CHECK(qr_parser_parse(parser, large) == 0);
  CHECK(qr_parser_parse(parser, "p2of2 B") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(qr_parser_parsed_count(parser) == 1);
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
  CHECK(qr_parser_parse(parser, large_first) == 0);
  CHECK(qr_parser_parse(parser, "p1of2 C") == 0);
  CHECK(qr_parser_parse(parser, large_second) == 1);
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
  CHECK(qr_parser_parse(parser, "p1of2 hello ") == -1);
  malloc_fail_countdown = 0;
  CHECK(qr_parser_is_failed(parser));
  CHECK(parser->alloc_failed);
  CHECK(!qr_parser_is_complete(parser));
  CHECK(qr_parser_parsed_count(parser) == 0);
  CHECK(qr_parser_parse(parser, "p1of2 hello ") == -1);
  CHECK(qr_parser_parsed_count(parser) == 0);
  CHECK(qr_parser_result(parser, NULL) == NULL);
  qr_parser_destroy(parser);
}

static void test_metadata_failure_is_not_an_allocation_failure(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(qr_parser_parse(parser, "p3of2 range") == -1);
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
    CHECK(qr_parser_parse(parser, "B$HU020041") == 0);
    CHECK(qr_parser_parse(parser, inconsistent[i]) == -1);
    CHECK(qr_parser_is_failed(parser));
    CHECK(qr_parser_parsed_count(parser) == 1);
    qr_parser_destroy(parser);
  }
}

static void test_bbqr_rejects_part_count_over_limit(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(qr_parser_parse(parser, "B$HUSH0041") == -1);
  CHECK(qr_parser_is_failed(parser));
  CHECK(qr_parser_parsed_count(parser) == 0);
  qr_parser_destroy(parser);
}

static void test_valid_bbqr_still_assembles(void) {
  QRPartParser *parser = qr_parser_create();
  CHECK(parser != NULL);
  CHECK(qr_parser_parse(parser, "B$HU020142") == 1);
  CHECK(qr_parser_parse(parser, "B$HU020041") == 0);
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
  CHECK(qr_parser_parse(parser, fragment) >= 0);
  CHECK(qr_parser_get_format(parser) == FORMAT_UR);
  CHECK(!qr_parser_is_failed(parser));
  CHECK(qr_parser_processed_parts_count(parser) == 1);
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
  test_valid_bbqr_still_assembles();
  test_valid_ur_still_processes();

  if (failures != 0) {
    fprintf(stderr, "%d QR parser test(s) failed\n", failures);
    return 1;
  }
  puts("All QR parser tests passed.");
  return 0;
}
