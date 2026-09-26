#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/message_sign.h"
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

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

/* Give every character-policy case a valid commitment, so rejection cannot
 * be caused by a mismatched to_spend hash. */
static struct wally_psbt *request_for_message(const unsigned char *msg,
                                              size_t len) {
  uint8_t raw[512];
  size_t raw_len = hex_decode(PSBT_HEX, raw, sizeof(raw));
  struct wally_psbt *psbt = NULL;
  struct wally_tx *to_spend = NULL;
  unsigned char tag_hash[32], preimage[256], hash[32];
  unsigned char scriptsig[34] = {0, 32}, null_hash[32] = {0};
  const char *tag = "BIP0322-signed-message";
  if (len > sizeof(preimage) - 64 ||
      wally_psbt_from_bytes(raw, raw_len, 0, &psbt) != WALLY_OK ||
      wally_sha256((const unsigned char *)tag, strlen(tag), tag_hash, 32) !=
          WALLY_OK)
    goto fail;
  memcpy(preimage, tag_hash, 32);
  memcpy(preimage + 32, tag_hash, 32);
  memcpy(preimage + 64, msg, len);
  if (wally_sha256(preimage, 64 + len, hash, 32) != WALLY_OK)
    goto fail;
  memcpy(scriptsig + 2, hash, 32);
  const struct wally_tx_output *utxo = psbt->inputs[0].witness_utxo;
  if (wally_tx_init_alloc(0, 0, 1, 1, &to_spend) != WALLY_OK ||
      wally_tx_add_raw_input(to_spend, null_hash, 32, 0xffffffff, 0, scriptsig,
                             sizeof(scriptsig), NULL, 0) != WALLY_OK ||
      wally_tx_add_raw_output(to_spend, 0, utxo->script, utxo->script_len, 0) !=
          WALLY_OK ||
      wally_tx_get_txid(to_spend, psbt->tx->inputs[0].txhash, 32) != WALLY_OK)
    goto fail;
  wally_tx_free(to_spend);
  /* The fixture's sole unknown global field is the signed message. */
  struct wally_map_item *item = &psbt->unknowns.items[0];
  unsigned char *value = malloc(len);
  if (!value) {
    wally_psbt_free(psbt);
    return NULL;
  }
  memcpy(value, msg, len);
  free(item->value);
  item->value = value;
  item->value_len = len;
  return psbt;
fail:
  wally_tx_free(to_spend);
  wally_psbt_free(psbt);
  return NULL;
}

static void test_message_characters(void) {
  static const struct {
    const char *name, *message;
    size_t len;
    bool accepted;
  } cases[] = {
#define CASE(name, text, accepted) {name, text, sizeof(text) - 1, accepted}
      CASE("embedded NUL", "shown\0hidden", false),
      CASE("tab", "a\tb", false),
      CASE("non-ASCII byte",
           "a\x80"
           "b",
           false),
      CASE("UTF-8 character", "caf\xc3\xa9", false),
      CASE("bare CR", "a\rb", false),
      CASE("trailing CR", "a\r", false),
      CASE("double CR", "a\r\r\nb", false),
      CASE("DEL",
           "a\x7f"
           "b",
           false),
      CASE("control byte",
           "a\x01"
           "b",
           false),
      CASE("printable boundaries", " ~", true),
      CASE("LF", "first\nsecond\n", true),
      CASE("multi-line CRLF", "first\r\nsecond\r\n", true),
#undef CASE
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    printf("BIP322 %s: ", cases[i].name);
    struct wally_psbt *psbt = request_for_message(
        (const unsigned char *)cases[i].message, cases[i].len);
    bip322_request_t req = {0};
    if (psbt && bip322_parse(psbt, true, &req) == cases[i].accepted &&
        (cases[i].accepted
             ? req.message && strlen(req.message) == cases[i].len &&
                   memcmp(req.message, cases[i].message, cases[i].len) == 0
             : !req.message && !req.address))
      PASS();
    else
      FAIL("unexpected parse result or changed message");
    bip322_request_free(&req);
    wally_psbt_free(psbt);

    /* The legacy API receives a C string, so NUL terminates its message. */
    if (strlen(cases[i].message) != cases[i].len)
      continue;
    printf("signmessage %s: ", cases[i].name);
    char content[256];
    snprintf(content, sizeof(content), "signmessage m/84h/0h/0h/0/0 ascii:%s",
             cases[i].message);
    parsed_sign_message_t parsed = {0};
    if (message_sign_parse(content, &parsed) == cases[i].accepted &&
        (cases[i].accepted
             ? parsed.message &&
                   strcmp(parsed.message, cases[i].message) == 0 &&
                   strcmp(parsed.derivation_path, "m/84'/0'/0'/0/0") == 0
             : !parsed.message && !parsed.derivation_path))
      PASS();
    else
      FAIL("unexpected parse result or changed message");
    message_sign_free_parsed(&parsed);
  }
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

  test_message_characters();

  printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
