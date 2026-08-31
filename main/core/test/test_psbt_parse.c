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

int main(void) {
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

  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed ? 1 : 0;
}
