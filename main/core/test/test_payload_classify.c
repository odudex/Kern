/* Host unit tests for core/payload_classify.c: QR / file payload heuristics,
 * priority ordering, BIP21/address network detection, and binary safety. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

#include "core/entropy_pool.h"
#include "core/kef.h"
#include "core/payload_classify.h"
#include "qr/seedqr.h"

static int failures = 0;

static void check(const char *name, bool cond) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  }
}

static void test_psbt_magic(void) {
  const uint8_t raw_psbt[] = {'p', 's', 'b', 't', 0xff, 0x01};
  const char *b64_psbt = "cHNidP8BAHECAAAA";
  check("binary PSBT magic detected",
        payload_looks_like_psbt(raw_psbt, sizeof(raw_psbt)));
  check("base64 PSBT prefix detected",
        payload_looks_like_psbt((const uint8_t *)b64_psbt, strlen(b64_psbt)));
  check("short buffer not PSBT", payload_looks_like_psbt(raw_psbt, 4) == false);
  check("NULL not PSBT", payload_looks_like_psbt(NULL, 10) == false);
  check("plain text not PSBT",
        payload_looks_like_psbt((const uint8_t *)"hello world", 11) == false);
}

static void test_address_detection(void) {
  /* Mainnet bech32, bech32m, legacy P2PKH, BIP21 */
  check("mainnet P2WPKH", payload_detect_address_network(
                              "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") ==
                              PAYLOAD_ADDRESS_MAINNET);
  check("mainnet P2TR",
        payload_detect_address_network(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr") ==
            PAYLOAD_ADDRESS_MAINNET);
  check("mainnet legacy P2PKH",
        payload_detect_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") ==
            PAYLOAD_ADDRESS_MAINNET);
  check("mainnet BIP21 URI with query",
        payload_detect_address_network(
            "BITCOIN:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.5") ==
            PAYLOAD_ADDRESS_MAINNET);

  /* Testnet bech32, legacy, BIP21 */
  check("testnet P2WPKH", payload_detect_address_network(
                              "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") ==
                              PAYLOAD_ADDRESS_TESTNET);
  check("testnet BIP21 URI",
        payload_detect_address_network(
            "bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx?label=test") ==
            PAYLOAD_ADDRESS_TESTNET);

  /* Invalid / empty */
  check("garbage is NONE", payload_detect_address_network("not-an-address") ==
                               PAYLOAD_ADDRESS_NONE);
  check("empty is NONE",
        payload_detect_address_network("") == PAYLOAD_ADDRESS_NONE);
  check("NULL is NONE",
        payload_detect_address_network(NULL) == PAYLOAD_ADDRESS_NONE);
}

static void test_classify_priority_and_kinds(void) {
  payload_classification_t c;

  /* 1. Valid and invalid message signing */
  const char *valid_msg = "signmessage m/84h/0h/0h/0/0 ascii:hello kern";
  payload_classify_text(valid_msg, strlen(valid_msg), &c);
  check("valid signmessage classified", c.kind == PAYLOAD_KIND_MESSAGE_SIGN);
  payload_classify_free(&c);

  const char *bad_msg = "signmessage not_a_path";
  payload_classify_text(bad_msg, strlen(bad_msg), &c);
  check("malformed signmessage flagged as INVALID_MESSAGE_SIGN",
        c.kind == PAYLOAD_KIND_INVALID_MESSAGE_SIGN);
  payload_classify_free(&c);

  /* 2. Base64 PSBT */
  struct wally_tx *tx = NULL;
  check("alloc minimal tx", wally_tx_init_alloc(2, 0, 1, 1, &tx) == WALLY_OK);
  unsigned char txhash[32] = {1};
  unsigned char spk[22] = {0x00, 0x14, 0x22};
  check("add tx in", wally_tx_add_raw_input(tx, txhash, 32, 0, 0xffffffffu,
                                            NULL, 0, NULL, 0) == WALLY_OK);
  check("add tx out",
        wally_tx_add_raw_output(tx, 1000, spk, sizeof(spk), 0) == WALLY_OK);
  struct wally_psbt *psbt = NULL;
  check("alloc minimal psbt", wally_psbt_init_alloc(WALLY_PSBT_VERSION_0, 1, 1,
                                                    0, 0, &psbt) == WALLY_OK);
  check("set global tx", wally_psbt_set_global_tx(psbt, tx) == WALLY_OK);
  wally_tx_free(tx);
  char *b64 = NULL;
  check("psbt to base64", wally_psbt_to_base64(psbt, 0, &b64) == WALLY_OK);
  wally_psbt_free(psbt);

  payload_classify_text(b64, strlen(b64), &c);
  check("base64 PSBT classified as PSBT (not KEF)",
        c.kind == PAYLOAD_KIND_PSBT && c.psbt != NULL && c.psbt_is_base64);
  payload_classify_free(&c);
  wally_free_string(b64);

  /* 3. Descriptors (standard prefix + BlueWallet Policy:) */
  const char *wpkh_desc = "wpkh([73c5da0a/84'/0'/0']xpub.../0/*)";
  payload_classify_text(wpkh_desc, strlen(wpkh_desc), &c);
  check("wpkh descriptor classified", c.kind == PAYLOAD_KIND_DESCRIPTOR);
  payload_classify_free(&c);

  const char *bw_desc = "Name: Vault\nPolicy: 2 of 3\nFormat: "
                        "P2WSH\nDerivation: m/48'/0'/0'/2'\n";
  payload_classify_text(bw_desc, strlen(bw_desc), &c);
  check("BlueWallet Policy: text classified as descriptor",
        c.kind == PAYLOAD_KIND_DESCRIPTOR);
  payload_classify_free(&c);

  /* 4. Address */
  const char *addr = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
  payload_classify_text(addr, strlen(addr), &c);
  check("BIP21 address classified with mainnet network",
        c.kind == PAYLOAD_KIND_ADDRESS &&
            c.address_network == PAYLOAD_ADDRESS_MAINNET);
  payload_classify_free(&c);

  /* 5. Mnemonics: plaintext, SeedQR, and Compact SeedQR with embedded NULs */
  const char *words =
      "abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon about";
  payload_classify_text(words, strlen(words), &c);
  check("plaintext mnemonic classified", c.kind == PAYLOAD_KIND_MNEMONIC);
  payload_classify_free(&c);

  char *seedqr = mnemonic_to_seedqr(words);
  check("encode seedqr", seedqr != NULL);
  payload_classify_text(seedqr, strlen(seedqr), &c);
  check("SeedQR classified as mnemonic", c.kind == PAYLOAD_KIND_MNEMONIC);
  payload_classify_free(&c);
  free(seedqr);

  /* 16 bytes of all-zero entropy -> valid 12-word Compact SeedQR with NULs */
  char compact[17] = {0};
  payload_classify_text(compact, 16, &c);
  check("binary Compact SeedQR with NULs classified as mnemonic",
        c.kind == PAYLOAD_KIND_MNEMONIC);
  payload_classify_free(&c);

  /* 6. KEF envelope (raw binary and base64-armored) */
  uint8_t *env = NULL;
  size_t env_len = 0;
  kef_error_t kerr = kef_encrypt((const uint8_t *)"id", 2, KEF_V20_GCM_E4,
                                 (const uint8_t *)"pw", 2, 10000,
                                 (const uint8_t *)"hello", 5, &env, &env_len);
  check("kef_encrypt test vector", kerr == KEF_OK && env != NULL);
  char *env_nul = malloc(env_len + 1);
  memcpy(env_nul, env, env_len);
  env_nul[env_len] = '\0';
  payload_classify_text(env_nul, env_len, &c);
  check("raw KEF envelope classified", c.kind == PAYLOAD_KIND_KEF &&
                                           c.kef_envelope != NULL &&
                                           c.kef_envelope_len == env_len);
  payload_classify_free(&c);
  free(env_nul);
  free(env);

  /* 7. Unknown and empty/NULL */
  const char *unknown = "just some random text";
  payload_classify_text(unknown, strlen(unknown), &c);
  check("unrecognized text is UNKNOWN", c.kind == PAYLOAD_KIND_UNKNOWN);
  payload_classify_free(&c);

  payload_classify_text(NULL, 0, &c);
  check("NULL input is UNKNOWN", c.kind == PAYLOAD_KIND_UNKNOWN);
}

int main(void) {
  entropy_pool_init();
  if (wally_init(0) != WALLY_OK) {
    fprintf(stderr, "init failed\n");
    return 1;
  }
  test_psbt_magic();
  test_address_detection();
  test_classify_priority_and_kinds();

  if (failures) {
    fprintf(stderr, "payload_classify: %d failures\n", failures);
    return 1;
  }
  printf("payload_classify tests passed\n");
  return 0;
}
