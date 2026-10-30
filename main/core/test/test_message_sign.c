#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>

#include "core/crypto_init.h"
#include "core/key.h"
#include "core/message_sign.h"
#include "core/secp_hardening.h"

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

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

static void expect_parse(const char *name, const char *request, bool ok) {
  TEST(name);
  parsed_sign_message_t parsed;
  bool got = message_sign_parse(request, &parsed);
  if (got)
    message_sign_free_parsed(&parsed);
  if (got == ok)
    PASS();
  else
    FAIL(ok ? "should parse" : "should be refused");
}

static void expect_address(const char *name, const char *path,
                           const char *want) {
  TEST(name);
  char *address = NULL;
  if (!message_sign_get_address(path, false, &address))
    FAIL("no address");
  else if (strcmp(address, want) != 0)
    FAIL(address);
  else
    PASS();
  wally_free_string(address);
}

/* The address shown is the one the signature verifies against. */
static void test_signature_recovers_key(void) {
  TEST("signature recovers the path's public key");
  const char *path = "m/84'/0'/0'/0/0";
  const char *message = "Hello Kern";
  char *b64 = NULL;
  struct ext_key *key = NULL;
  /* Decoding needs room for the maximum length the text could hold. */
  unsigned char sig[EC_SIGNATURE_RECOVERABLE_LEN + 3], hash[SHA256_LEN];
  unsigned char pub[EC_PUBLIC_KEY_LEN];
  size_t sig_len = 0, written = 0;
  bool ok =
      message_sign_sign(path, message, &b64) &&
      wally_base64_to_bytes(b64, 0, sig, sizeof(sig), &sig_len) == WALLY_OK &&
      sig_len == EC_SIGNATURE_RECOVERABLE_LEN &&
      wally_format_bitcoin_message((const unsigned char *)message,
                                   strlen(message), BITCOIN_MESSAGE_FLAG_HASH,
                                   hash, sizeof(hash), &written) == WALLY_OK &&
      wally_ec_sig_to_public_key(hash, sizeof(hash), sig,
                                 EC_SIGNATURE_RECOVERABLE_LEN, pub,
                                 sizeof(pub)) == WALLY_OK &&
      key_get_derived_key(path, &key) &&
      memcmp(pub, key->pub_key, sizeof(pub)) == 0;
  if (ok)
    PASS();
  else
    FAIL("recovered key differs");
  wally_free_string(b64);
  bip32_key_free(key);
}

static char *sign_hello(void) {
  char *b64 = NULL;
  if (!message_sign_sign("m/84'/0'/0'/0/0", "Hello Kern", &b64))
    return NULL;
  return b64;
}

/* "Hello Kern" signed at m/84'/0'/0'/0/0 by an independent RFC6979
 * implementation (HMAC-SHA256, low S), from BIP84's private key for that path.
 */
static const char *HELLO_RFC6979 =
    "H6/HLXbHJ4WR/1apaOHCnsBah1Zecvpahhr1VvIIjeROOrvlI0Ky150kTVQeiGhSKWabus6Hu7"
    "NzUXbrWKvVWLs=";

/* Blinding changes how the computation runs, never its result: signatures stay
 * RFC6979's, so anyone holding the seed can reproduce them. */
static void test_signing_is_deterministic(void) {
  char *a = sign_hello(), *b = sign_hello();
  TEST("the signature is RFC6979's, with nothing else in the nonce");
  if (a && strcmp(a, HELLO_RFC6979) == 0)
    PASS();
  else
    FAIL(a ? a : "no signature");

  TEST("signing the same message twice gives the same signature");
  if (a && b && strcmp(a, b) == 0)
    PASS();
  else
    FAIL("expected identical signatures");
  wally_free_string(b);

  TEST("refreshing the blinding leaves RFC6979 signatures unchanged");
  bool refreshed = secp_blind_refresh();
  b = sign_hello();
  if (refreshed && a && b && strcmp(a, b) == 0)
    PASS();
  else
    FAIL("expected the same signature after a refresh");
  wally_free_string(a);
  wally_free_string(b);
}

int main(void) {
  /* Set up libwally as the firmware does, hooks included. */
  if (!crypto_init()) {
    printf("ABORT: crypto_init failed\n");
    return 1;
  }
  printf("=== message_sign tests ===\n\n");
  if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false)) {
    printf("ABORT: failed to load mnemonic\n");
    return 1;
  }

  expect_parse("BIP44 path accepted", "signmessage m/44h/0h/0h/0/0 ascii:hi",
               true);
  expect_parse("BIP49 path accepted", "signmessage m/49h/0h/0h/0/0 ascii:hi",
               true);
  expect_parse("BIP84 path accepted", "signmessage m/84h/0h/0h/0/0 ascii:hi",
               true);
  expect_parse("BIP86 path refused (ECDSA cannot prove a taproot address)",
               "signmessage m/86h/0h/0h/0/0 ascii:hi", false);
  expect_parse("unknown purpose refused", "signmessage m/0/1 ascii:hi", false);
  expect_parse("unhardened purpose refused",
               "signmessage m/84/0h/0h/0/0 ascii:hi", false);

  expect_address("BIP44 shows a P2PKH address", "m/44'/0'/0'/0/0",
                 "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
  expect_address("BIP49 shows a P2SH-P2WPKH address", "m/49'/0'/0'/0/0",
                 "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
  expect_address("BIP84 shows a P2WPKH address", "m/84'/0'/0'/0/0",
                 "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  test_signature_recovers_key();
  test_signing_is_deterministic();

  key_unload();
  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
