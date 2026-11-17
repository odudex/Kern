/*
 * psbt_parse_payload(): trailing-byte and padding handling.
 *
 * A valid PSBT prefix followed by attacker-chosen bytes must not parse, or the
 * device reviews and signs one reading of a payload another parser could read
 * differently. Trailing whitespace is the exception: a serialized PSBT ends on
 * its 0x00 separator, so whitespace after it is container padding (an editor's
 * newline on an SD card file) and must not cost the user a valid file.
 */

#include "core/psbt.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    printf("Testing: %s... ", name);                                           \
    tests_run++;                                                               \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* Minimal signable PSBT (same fixture as the BIP322 tests). */
static const char PSBT_HEX[] =
    "70736274ff01003d00000000017189d386a21d477ce6809ef31f0dfe076f32b6c82d065b"
    "2b50cc5c9867fd85f6000000000000000000010000000000000000016a00000000010"
    "90b48656c6c6f20576f726c640001011f000000000000000016001481407ea42dd4f1e3"
    "8cfff569aea3b2b85b9d53dc01030401000000220603c4c806d0c119b335e39b144bc4ba"
    "b1a51006cf3d975dbe7407e31ee75939e9e01865fb43fe5400008001000080000000800"
    "0000000010000000000";

/* libwally's "PSET Version 2 Minimal" vector. The same bytes under the PSBT
 * magic are a valid PSBT, so a rejection can only come from the magic. */
static const char PSET_HEX[] =
    "70736574ff01020402000000010401000105010001fb040200000000";
static const char PSET_BASE64[] = "cHNldP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==";
/* sp_fixture.h's UNSIGNED_PSBT, a silent payment send, with an explicit
 * PSBT_IN_SIGHASH_TYPE on its input: SIGHASH_DEFAULT (0), then SIGHASH_ALL */
static const char SP_SIGHASH_DEFAULT_PSBT_HEX[] =
    "70736274ff0102040200000001030400000000010401010105010201fb04020000000001"
    "012ba086010000000000225120cba15611f961103c8738f27fefa7b774bc6b242f17b55d"
    "ae832a3ae2efe332ed010e20222222222222222222222222222222222222222222222222"
    "2222222222222222010f0400000000012020111111111111111111111111111111111111"
    "1111111111111111111111111111010304000000000001030860ea000000000000010942"
    "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4025cc9"
    "856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36000103085898"
    "000000000000010942024139b0f81042e243a90478e43990c6a27be0e3346f0c71adbbcd"
    "d511beaea1e3031ec096b3e9917a43e81c6d014acab0dfa32151ea7dcdfa56a1dc89f0ae"
    "c04ef8010a040000000000";
static const char SP_SIGHASH_ALL_PSBT_HEX[] =
    "70736274ff0102040200000001030400000000010401010105010201fb04020000000001"
    "012ba086010000000000225120cba15611f961103c8738f27fefa7b774bc6b242f17b55d"
    "ae832a3ae2efe332ed010e20222222222222222222222222222222222222222222222222"
    "2222222222222222010f0400000000012020111111111111111111111111111111111111"
    "1111111111111111111111111111010304010000000001030860ea000000000000010942"
    "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4025cc9"
    "856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36000103085898"
    "000000000000010942024139b0f81042e243a90478e43990c6a27be0e3346f0c71adbbcd"
    "d511beaea1e3031ec096b3e9917a43e81c6d014acab0dfa32151ea7dcdfa56a1dc89f0ae"
    "c04ef8010a040000000000";

/* PSBT_HEX with its explicit SIGHASH_ALL turned into SIGHASH_DEFAULT (0) */
static const char SIGHASH_DEFAULT_PSBT_HEX[] =
    "70736274ff01003d00000000017189d386a21d477ce6809ef31f0dfe076f32b6c82d065b"
    "2b50cc5c9867fd85f6000000000000000000010000000000000000016a00000000010"
    "90b48656c6c6f20576f726c640001011f000000000000000016001481407ea42dd4f1e3"
    "8cfff569aea3b2b85b9d53dc01030400000000220603c4c806d0c119b335e39b144bc4ba"
    "b1a51006cf3d975dbe7407e31ee75939e9e01865fb43fe5400008001000080000000800"
    "0000000010000000000";

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_size) {
  size_t len = strlen(hex) / 2;
  if (len > out_size)
    return 0;
  for (size_t i = 0; i < len; i++) {
    unsigned int byte;
    if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
      return 0;
    out[i] = (uint8_t)byte;
  }
  return len;
}

static uint8_t base[512];
static size_t base_len;

/* Build base PSBT + `suffix`, then assert psbt_parse_payload's verdict. */
static void check_suffix(const char *name, const void *suffix,
                         size_t suffix_len, bool want_ok) {
  uint8_t buf[640];
  TEST(name);
  if (base_len + suffix_len > sizeof(buf)) {
    FAIL("fixture too large");
    return;
  }
  memcpy(buf, base, base_len);
  if (suffix_len)
    memcpy(buf + base_len, suffix, suffix_len);

  struct wally_psbt *psbt = NULL;
  const bool ok = psbt_parse_payload(buf, base_len + suffix_len, &psbt);
  if (ok != want_ok) {
    FAIL(want_ok ? "expected the parse to succeed"
                 : "expected the parse to be rejected");
  } else if (ok && !psbt) {
    FAIL("reported success without returning a PSBT");
  } else if (!ok && psbt) {
    FAIL("left a PSBT behind on failure");
  } else {
    PASS();
  }
  if (psbt)
    wally_psbt_free(psbt);
}

static void test_pset_rejected(void) {
  TEST("libwally built without Elements");
  size_t is_elements = 1;
  if (wally_is_elements_build(&is_elements) == WALLY_OK && !is_elements)
    PASS();
  else
    FAIL("libwally was built with Elements support");

  uint8_t buf[32];
  const size_t len = hex_decode(PSET_HEX, buf, sizeof(buf));

  TEST("PSET bytes rejected");
  struct wally_psbt *psbt = NULL;
  if (len && !psbt_parse_payload(buf, len, &psbt) && !psbt) {
    PASS();
  } else {
    FAIL("a PSET parsed");
    if (psbt)
      wally_psbt_free(psbt);
  }

  /* The base64 scan path calls wally_psbt_from_base64 with no flags. */
  TEST("PSET base64 rejected");
  psbt = NULL;
  if (wally_psbt_from_base64(PSET_BASE64, 0, &psbt) != WALLY_OK && !psbt) {
    PASS();
  } else {
    FAIL("a base64 PSET parsed");
    if (psbt)
      wally_psbt_free(psbt);
  }

  TEST("same body under the PSBT magic parses");
  psbt = NULL;
  memcpy(buf, "psbt", 4);
  if (len && psbt_parse_payload(buf, len, &psbt) && psbt) {
    PASS();
  } else {
    FAIL("the PSBT control did not parse");
  }
  if (psbt)
    wally_psbt_free(psbt);
}

/* Parse the PSBT `hex` and assert psbt_parse_payload_result's verdict. */
static void check_hex(const char *name, const char *hex,
                      psbt_parse_result_t want) {
  uint8_t buf[640];
  size_t len = hex_decode(hex, buf, sizeof(buf));
  struct wally_psbt *psbt = NULL;
  TEST(name);
  if (len && psbt_parse_payload_result(buf, len, &psbt) == want &&
      (psbt != NULL) == (want == PSBT_PARSE_OK))
    PASS();
  else
    FAIL(want == PSBT_PARSE_OK ? "expected the parse to succeed"
                               : "expected the parse to fail for that reason");
  wally_psbt_free(psbt);
}

int main(void) {
  /* The host libwally hashes through PSA, as the device does, which needs
   * wally_init. */
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
  base_len = hex_decode(PSBT_HEX, base, sizeof(base));
  if (!base_len) {
    printf("FAIL: could not decode the PSBT fixture\n");
    return 1;
  }

  check_suffix("unpadded PSBT parses", NULL, 0, true);

  /* Trailing payload: silently dropped before WALLY_PSBT_PARSE_FLAG_COMPLETE */
  check_suffix("trailing NUL rejected", "\x00", 1, false);
  check_suffix("trailing arbitrary byte rejected", "\xff", 1, false);
  check_suffix("trailing ASCII text rejected", "gotcha", 6, false);
  check_suffix("trailing second PSBT header rejected", "\x70\x73\x62\x74\xff",
               5, false);
  check_suffix("long trailing payload rejected",
               "\x01\x02\x03\x04\x05\x06\x07\x08", 8, false);

  /* Whitespace padding: tolerated */
  check_suffix("trailing newline accepted", "\n", 1, true);
  check_suffix("trailing CRLF accepted", "\r\n", 2, true);
  check_suffix("trailing space accepted", " ", 1, true);
  check_suffix("trailing tab accepted", "\t", 1, true);
  check_suffix("trailing mixed whitespace accepted", " \t\r\n\n  ", 7, true);

  /* Padding must not become a smuggling channel */
  check_suffix("whitespace then payload rejected", "\n\nX", 3, false);
  check_suffix("payload then whitespace rejected", "X\n", 2, false);
  check_suffix("whitespace around payload rejected", " X ", 3, false);
  check_suffix("embedded NUL after whitespace rejected", " \x00", 2, false);

  /* Degenerate inputs */
  TEST("truncated PSBT rejected");
  struct wally_psbt *psbt = NULL;
  if (!psbt_parse_payload(base, base_len - 8, &psbt) && !psbt) {
    PASS();
  } else {
    FAIL("a truncated PSBT parsed");
    if (psbt)
      wally_psbt_free(psbt);
  }

  TEST("whitespace-only input rejected");
  psbt = NULL;
  if (!psbt_parse_payload((const uint8_t *)"\n\n  \t", 5, &psbt) && !psbt) {
    PASS();
  } else {
    FAIL("whitespace alone parsed");
    if (psbt)
      wally_psbt_free(psbt);
  }

  TEST("empty input rejected");
  psbt = NULL;
  if (!psbt_parse_payload((const uint8_t *)"", 0, &psbt) && !psbt) {
    PASS();
  } else {
    FAIL("an empty payload parsed");
    if (psbt)
      wally_psbt_free(psbt);
  }

  TEST("NULL arguments rejected");
  psbt = NULL;
  if (!psbt_parse_payload(NULL, 4, &psbt) &&
      !psbt_parse_payload(base, base_len, NULL)) {
    PASS();
  } else {
    FAIL("a NULL argument was accepted");
  }

  test_pset_rejected();
  check_hex("an explicit SIGHASH_DEFAULT with silent payment outputs is "
            "refused for its sighash",
            SP_SIGHASH_DEFAULT_PSBT_HEX, PSBT_PARSE_SP_SIGHASH);
  check_hex("an explicit SIGHASH_ALL with silent payment outputs parses",
            SP_SIGHASH_ALL_PSBT_HEX, PSBT_PARSE_OK);
  check_hex("an explicit SIGHASH_DEFAULT without silent payment outputs "
            "parses",
            SIGHASH_DEFAULT_PSBT_HEX, PSBT_PARSE_OK);

  TEST("a truncated PSBT is invalid, not refused for its sighash");
  psbt = NULL;
  if (psbt_parse_payload_result(base, base_len - 8, &psbt) ==
          PSBT_PARSE_INVALID &&
      !psbt)
    PASS();
  else
    FAIL("expected PSBT_PARSE_INVALID");
  wally_psbt_free(psbt);

  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed ? 1 : 0;
}
