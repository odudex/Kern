#include "../parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../components/cUR/src/ur_decoder.h"

ur_decoder_t *ur_decoder_new(void) { return NULL; }
void ur_decoder_free(ur_decoder_t *decoder) { (void)decoder; }
ur_decoder_state_t ur_decoder_receive_part(ur_decoder_t *decoder,
                                           const char *part_str) {
  (void)decoder;
  (void)part_str;
  return UR_DECODER_ERROR_NULL_POINTER;
}
ur_decoder_state_t ur_decoder_get_state(const ur_decoder_t *decoder) {
  (void)decoder;
  return UR_DECODER_ERROR_NULL_POINTER;
}
ur_result_t *ur_decoder_get_result(ur_decoder_t *decoder) {
  (void)decoder;
  return NULL;
}
size_t ur_decoder_expected_part_count(ur_decoder_t *decoder) {
  (void)decoder;
  return 0;
}
size_t ur_decoder_processed_parts_count(ur_decoder_t *decoder) {
  (void)decoder;
  return 0;
}

static int failures = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    printf("Testing: %s... ", name);                                          \
    fflush(stdout);                                                            \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                        \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                \
    failures++;                                                                \
    return;                                                                    \
  } while (0)

static void test_bbqr_trims_frame_whitespace(void) {
  static const char *frame =
      " \n\tB$HB0100"
      "42495058585801010E151E957222A2B72C605E0A16E9F5740A"
      "048000003080000000800000008000000204800000308000000080000001800000020"
      "480000030800000008000000280000002048000003080000000800000038000000204"
      "800000308000000080000004800000020480000030800000008000000580000002048"
      "000003080000000800000068000000204800000308000000080000007800000020480"
      "0000308000000080000008800000020480000030800000008000000980000002"
      " \r\n";
  static const unsigned char expected_prefix[] = {
      0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x01,
      0x0e, 0x15, 0x1e, 0x95, 0x72, 0x22, 0xa2, 0xb7,
      0x2c, 0x60, 0x5e, 0x0a, 0x16, 0xe9, 0xf5, 0x74,
      0x0a};

  TEST("BBQr frame whitespace is ignored before hex decode");
  QRPartParser *parser = qr_parser_create();
  if (!parser)
    FAIL("parser allocation failed");

  int part = qr_parser_parse_with_len(parser, frame, strlen(frame));
  if (part != 0) {
    qr_parser_destroy(parser);
    FAIL("part did not parse as single BBQr frame");
  }
  if (!qr_parser_is_complete(parser)) {
    qr_parser_destroy(parser);
    FAIL("parser did not complete");
  }
  if (qr_parser_get_format(parser) != FORMAT_BBQR) {
    qr_parser_destroy(parser);
    FAIL("parser did not detect BBQr");
  }
  if (qr_parser_get_bbqr_file_type(parser) != 'B') {
    qr_parser_destroy(parser);
    FAIL("parser did not preserve binary file type");
  }

  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  if (!result) {
    qr_parser_destroy(parser);
    FAIL("failed to decode BBQr payload");
  }
  if (result_len != 195) {
    free(result);
    qr_parser_destroy(parser);
    FAIL("decoded payload length mismatch");
  }
  if (memcmp(result, expected_prefix, sizeof(expected_prefix)) != 0) {
    free(result);
    qr_parser_destroy(parser);
    FAIL("decoded protocol prefix mismatch");
  }

  free(result);
  qr_parser_destroy(parser);
  PASS();
}

static void test_bbqr_accepts_lowercase_prefix(void) {
  static const char *frame =
      "b$hb0100"
      "42495058585801010E151E957222A2B72C605E0A16E9F5740A"
      "04800000308000000080000000800000080000000";

  TEST("BBQr lowercase prefix is accepted");
  QRPartParser *parser = qr_parser_create();
  if (!parser)
    FAIL("parser allocation failed");

  int part = qr_parser_parse_with_len(parser, frame, strlen(frame));
  if (part != 0) {
    qr_parser_destroy(parser);
    FAIL("part did not parse as BBQr frame");
  }
  if (qr_parser_get_format(parser) != FORMAT_BBQR) {
    qr_parser_destroy(parser);
    FAIL("parser did not detect BBQr");
  }

  qr_parser_destroy(parser);
  PASS();
}

static void test_liana_bip_request_frame_decodes(void) {
  static const char *frame =
      "B$HB0100"
      "4249505858580101A70DB351AA24F14ECBA588202BC904E30A04800000308000000"
      "080000000800000020480000030800000008000000180000002048000003080000000"
      "800000028000000204800000308000000080000003800000020480000030800000008"
      "000000480000002048000003080000000800000058000000204800000308000000080"
      "000006800000020480000030800000008000000780000002048000003080000000800"
      "00008800000020480000030800000008000000980000002 ";
  static const unsigned char expected_prefix[] = {
      0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x01,
      0xa7, 0x0d, 0xb3, 0x51, 0xaa, 0x24, 0xf1, 0x4e,
      0xcb, 0xa5, 0x88, 0x20, 0x2b, 0xc9, 0x04, 0xe3,
      0x0a};

  TEST("Liana BIP request BBQr frame decodes as binary protocol payload");
  QRPartParser *parser = qr_parser_create();
  if (!parser)
    FAIL("parser allocation failed");

  int part = qr_parser_parse_with_len(parser, frame, strlen(frame));
  if (part != 0) {
    qr_parser_destroy(parser);
    FAIL("part did not parse as single BBQr frame");
  }
  if (!qr_parser_is_complete(parser)) {
    qr_parser_destroy(parser);
    FAIL("parser did not complete");
  }
  if (qr_parser_get_bbqr_file_type(parser) != 'B') {
    qr_parser_destroy(parser);
    FAIL("parser did not preserve binary file type");
  }

  size_t result_len = 0;
  char *result = qr_parser_result(parser, &result_len);
  if (!result) {
    qr_parser_destroy(parser);
    FAIL("failed to decode BBQr payload");
  }
  if (result_len != 195) {
    free(result);
    qr_parser_destroy(parser);
    FAIL("decoded payload length mismatch");
  }
  if (memcmp(result, expected_prefix, sizeof(expected_prefix)) != 0) {
    free(result);
    qr_parser_destroy(parser);
    FAIL("decoded protocol prefix mismatch");
  }

  free(result);
  qr_parser_destroy(parser);
  PASS();
}

int main(void) {
  printf("QR Parser Test Suite\n");
  printf("====================\n\n");

  test_bbqr_trims_frame_whitespace();
  test_bbqr_accepts_lowercase_prefix();
  test_liana_bip_request_frame_decodes();

  printf("\n====================\n");
  printf("Results: %d failed\n", failures);
  return failures == 0 ? 0 : 1;
}
