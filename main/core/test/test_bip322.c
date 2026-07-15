#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_psbt.h>

#include "core/bip322.h"
#include "core/psbt.h"
#include "core/script_templates.h"

/* psbt.c pulls in the whole classification stack; the address helper is a
 * one-line wrapper, so stub it the same way here. */
char *psbt_scriptpubkey_to_address(const unsigned char *script,
                                   size_t script_len, bool is_testnet) {
  return script_template_address_from_spk(script, script_len, is_testnet);
}

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* BIP322 to_sign PSBT for the message "Hello World", proving
 * tb1qs9q8afpd6nc78r8l7456agajhpde657uzn9uh4. Carries the
 * PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) field with the message as
 * value. */
static const char PSBT_HEX[] =
    "70736274ff01003d00000000017189d386a21d477ce6809ef31f0dfe076f32b6c82d065b"
    "2b50cc5c9867fd85f6000000000000000000010000000000000000016a00000000010"
    "90b48656c6c6f20576f726c640001011f000000000000000016001481407ea42dd4f1e3"
    "8cfff569aea3b2b85b9d53dc01030401000000220603c4c806d0c119b335e39b144bc4ba"
    "b1a51006cf3d975dbe7407e31ee75939e9e01865fb43fe5400008001000080000000800"
    "0000000010000000000";

/* Same request generated with an empty message (forgotten in the
 * coordinator): field 0x09 has a zero-length value, which upstream libwally
 * rejects at parse time — and which bip322_parse refuses regardless. */
static const char PSBT_EMPTY_MSG_HEX[] =
    "70736274ff01003d000000000104261bcacbcc020306d7458d93e92e87af3ab8d0fa9b7c"
    "fb537a1a739f6cfb26000000000000000000010000000000000000016a00000000010900"
    "0001011f000000000000000016001481407ea42dd4f1e38cfff569aea3b2b85b9d53dc01"
    "030401000000220603c4c806d0c119b335e39b144bc4bab1a51006cf3d975dbe7407e31e"
    "e75939e9e01865fb43fe54000080010000800000008000000000010000000000";

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

int main(void) {
  uint8_t raw[512];
  size_t raw_len = hex_decode(PSBT_HEX, raw, sizeof(raw));

  TEST("BIP322 PSBT parses");
  struct wally_psbt *psbt = NULL;
  if (raw_len > 0 &&
      wally_psbt_from_bytes(raw, raw_len, 0, &psbt) == WALLY_OK) {
    PASS();
  } else {
    FAIL("wally_psbt_from_bytes rejected the PSBT");
  }

  if (psbt) {
    TEST("bip322_detect finds the message field");
    if (bip322_detect(psbt))
      PASS();
    else
      FAIL("field 0x09 not detected");

    TEST("bip322_parse validates commitment and extracts request");
    bip322_request_t req = {0};
    if (bip322_parse(psbt, true, &req) && req.message &&
        strcmp(req.message, "Hello World") == 0 && req.address &&
        strcmp(req.address, "tb1qs9q8afpd6nc78r8l7456agajhpde657uzn9uh4") ==
            0) {
      PASS();
    } else {
      FAIL("parse failed or wrong message/address");
    }
    bip322_request_free(&req);
    wally_psbt_free(psbt);
    psbt = NULL;
  }

  TEST("bip322_parse rejects tampered to_spend commitment");
  uint8_t tampered[512];
  memcpy(tampered, raw, raw_len);
  tampered[13] ^= 0x01; /* first byte of the to_spend txid in the tx value */
  if (wally_psbt_from_bytes(tampered, raw_len, 0, &psbt) == WALLY_OK) {
    bip322_request_t req = {0};
    if (!bip322_parse(psbt, true, &req))
      PASS();
    else
      FAIL("tampered commitment accepted");
    bip322_request_free(&req);
    wally_psbt_free(psbt);
    psbt = NULL;
  } else {
    FAIL("tampered PSBT failed to parse");
  }

  TEST("bip322_detect ignores regular PSBTs");
  /* Strip the 0x09 global entry ("01 09 0b" + 11 message bytes at offsets
   * 69..82). */
  uint8_t regular[512];
  memcpy(regular, raw, 69);
  memcpy(regular + 69, raw + 83, raw_len - 83);
  if (wally_psbt_from_bytes(regular, raw_len - 14, 0, &psbt) == WALLY_OK) {
    if (!bip322_detect(psbt))
      PASS();
    else
      FAIL("detected on a PSBT without field 0x09");
    wally_psbt_free(psbt);
    psbt = NULL;
  } else {
    FAIL("regular PSBT failed to parse");
  }

  TEST("empty-message request is rejected");
  uint8_t empty[512];
  size_t empty_len = hex_decode(PSBT_EMPTY_MSG_HEX, empty, sizeof(empty));
  if (wally_psbt_from_bytes(empty, empty_len, 0, &psbt) == WALLY_OK) {
    /* If libwally ever starts accepting empty unknown-field values, the
     * explicit empty-message check must still refuse the request. */
    bip322_request_t req = {0};
    if (!bip322_parse(psbt, true, &req))
      PASS();
    else
      FAIL("empty message accepted");
    bip322_request_free(&req);
    wally_psbt_free(psbt);
    psbt = NULL;
  } else {
    PASS(); /* rejected at parse time (current upstream behavior) */
  }

  printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
