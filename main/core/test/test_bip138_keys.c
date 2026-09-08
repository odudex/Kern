/*
 * BIP138 recipient key extraction (core/bip138_keys.c): the BIP's
 * keys_types.json vectors plus descriptor-level extraction rules.
 */

#include "../bip138_keys.h"
#include "vectors.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <wally_address.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

#define TPUB_A                                                                 \
  "tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52M"  \
  "BoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw"
#define TPUB_B                                                                 \
  "tpubDFTxBKyUCgkwp5enwZh3t2FJ5AMJqmCWoh1NRT13qNYQb1iKTUrAG6u5gpsDYhG8cZGXo"  \
  "uYWuQtzcuSVjPStTc4dwU6JqPMFtgaLGvSQXhi"
#define KEY_A "[58b7f8dc/48'/1'/0'/2']" TPUB_A
#define KEY_B "[d4ab66f1/48'/1'/1'/2']" TPUB_B
#define LITERAL                                                                \
  "02ebd252ca0877aae09b9d058219682775aa3cbcd049c12f07832f2cf6a3b51708"

static const uint8_t xonly_a[32] = {
    0xeb, 0xd2, 0x52, 0xca, 0x08, 0x77, 0xaa, 0xe0, 0x9b, 0x9d, 0x05,
    0x82, 0x19, 0x68, 0x27, 0x75, 0xaa, 0x3c, 0xbc, 0xd0, 0x49, 0xc1,
    0x2f, 0x07, 0x83, 0x2f, 0x2c, 0xf6, 0xa3, 0xb5, 0x17, 0x08};
static const uint32_t origin_a[] = {48 | 0x80000000u, 1 | 0x80000000u,
                                    0 | 0x80000000u, 2 | 0x80000000u};

static void test_vectors(void) {
  for (size_t i = 0; i < TV_KEY_TYPE_COUNT; i++) {
    const tv_key_type *tv = &tv_key_type_vectors[i];
    uint8_t out[32] = {0};
    bool ok = bip138_key_from_expression(tv->key, out);
    if (tv->expected.p)
      check(tv->desc, ok && memcmp(out, tv->expected.p, 32) == 0);
    else
      check(tv->desc, !ok);
  }
}

static void test_descriptors(void) {
  uint8_t keys[BIP138_KEYS_MAX * 32];
  bip138_key_origin origins[BIP138_KEYS_MAX];
  size_t count = 0;
  const uint32_t testnet = WALLY_NETWORK_BITCOIN_TESTNET;

  const char *multisig =
      "wsh(sortedmulti(1," KEY_A "/<0;1>/*," KEY_B "/<0;1>/*))";
  check("multisig extracts two keys",
        bip138_keys_from_descriptor(multisig, testnet, keys, origins,
                                    BIP138_KEYS_MAX, &count) &&
            count == 2);
  check("first key matches the vector", memcmp(keys, xonly_a, 32) == 0);
  check("first origin is 48'/1'/0'/2'",
        origins[0].depth == 4 && memcmp(origins[0].child, origin_a, 16) == 0);
  check("second origin is 48'/1'/1'/2'",
        origins[1].depth == 4 && origins[1].child[2] == (1 | 0x80000000u));
  check("keys are distinct", memcmp(keys, keys + 32, 32) != 0);
  check("max_keys is enforced",
        !bip138_keys_from_descriptor(multisig, testnet, keys, NULL, 1, &count));
  check("wrong network fails",
        !bip138_keys_from_descriptor(multisig, WALLY_NETWORK_BITCOIN_MAINNET,
                                     keys, NULL, BIP138_KEYS_MAX, &count));

  const char *mixed = "wsh(multi(1," KEY_A "/<0;1>/*," LITERAL "))";
  check("literal pubkey is skipped",
        bip138_keys_from_descriptor(mixed, testnet, keys, origins,
                                    BIP138_KEYS_MAX, &count) &&
            count == 1 && memcmp(keys, xonly_a, 32) == 0);

  const char *taproot = "tr(" KEY_A "/<0;1>/*)";
  check("taproot key extracts",
        bip138_keys_from_descriptor(taproot, testnet, keys, NULL,
                                    BIP138_KEYS_MAX, &count) &&
            count == 1 && memcmp(keys, xonly_a, 32) == 0);

  const char *bare = "wpkh(" TPUB_B ")";
  check("bare xpub yields no key",
        !bip138_keys_from_descriptor(bare, testnet, keys, NULL, BIP138_KEYS_MAX,
                                     &count));

  const char *no_origin = "wpkh(" TPUB_A "/0/*)";
  check("key without origin has depth 0",
        bip138_keys_from_descriptor(no_origin, testnet, keys, origins,
                                    BIP138_KEYS_MAX, &count) &&
            count == 1 && origins[0].depth == 0);

  const char *repeated = "wsh(or_d(pk(" KEY_A "/<0;1>/*),and_v(v:pk(" TPUB_A
                         "/<2;3>/*),older(100))))";
  check("repeated key is deduplicated",
        bip138_keys_from_descriptor(repeated, testnet, keys, origins,
                                    BIP138_KEYS_MAX, &count) &&
            count == 1 && origins[0].depth == 4);

  check("NULL descriptor fails",
        !bip138_keys_from_descriptor(NULL, testnet, keys, NULL, BIP138_KEYS_MAX,
                                     &count));
  check("garbage fails",
        !bip138_keys_from_descriptor("wpkh(", testnet, keys, NULL,
                                     BIP138_KEYS_MAX, &count));
}

int main(void) {
  test_vectors();
  test_descriptors();
  printf("\n%d tests, %d failed\n", tests_run, tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
