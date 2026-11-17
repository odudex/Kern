#include "../bip388.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

#define KEY_A "[f5acc2fd/48'/1'/0'/2']tpubA"
#define KEY_B "[00000000/48'/1'/0'/2']tpubB"

static const char *const KEYS[] = {KEY_A, KEY_B};

static void expect_descriptor(const char *name, const char *policy,
                              const char *const *keys, size_t key_count,
                              const char *expected) {
  TEST(name);
  char *got = bip388_descriptor_alloc(policy, keys, key_count);
  if (!got)
    FAIL("no descriptor");
  else if (!bip388_policy_is_valid(policy, keys, key_count))
    FAIL("policy not valid");
  else if (strcmp(got, expected) != 0)
    FAIL(got);
  else
    PASS();
  free(got);
}

static void expect_refused(const char *name, const char *policy,
                           const char *const *keys, size_t key_count) {
  TEST(name);
  char *got = bip388_descriptor_alloc(policy, keys, key_count);
  if (got)
    FAIL(got);
  else if (bip388_policy_is_valid(policy, keys, key_count))
    FAIL("policy valid");
  else
    PASS();
  free(got);
}

static void test_expanded(void) {
  expect_descriptor("/** becomes /<0;1>/*", "wpkh(@0/**)", KEYS, 1,
                    "wpkh(" KEY_A "/<0;1>/*)");
  expect_descriptor("an explicit multipath is kept", "wpkh(@0/<0;1>/*)", KEYS,
                    1, "wpkh(" KEY_A "/<0;1>/*)");
  expect_descriptor("a key used twice is written twice",
                    "wsh(or_d(pk(@0/**),and_v(v:pk(@0/<2;3>/*),older(10))))",
                    KEYS, 1,
                    "wsh(or_d(pk(" KEY_A "/<0;1>/*),and_v(v:pk(" KEY_A
                    "/<2;3>/*),older(10))))");
  expect_descriptor("/** after musig() is expanded", "tr(musig(@0,@1)/**)",
                    KEYS, 2, "tr(musig(" KEY_A "," KEY_B ")/<0;1>/*)");
  expect_descriptor("keys are taken by index",
                    "wsh(sortedmulti(1,@1/**,@0/**))", KEYS, 2,
                    "wsh(sortedmulti(1," KEY_B "/<0;1>/*," KEY_A "/<0;1>/*))");

  const char *const eleven[] = {"k0", "k1", "k2", "k3", "k4", "k5",
                                "k6", "k7", "k8", "k9", "k10"};
  expect_descriptor("a two digit index", "pk(@10/**)", eleven, 11,
                    "pk(k10/<0;1>/*)");
}

static void test_refused(void) {
  expect_refused("an index past the keys is refused", "wpkh(@1/**)", KEYS, 1);
  expect_refused("an index far past the keys is refused",
                 "wpkh(@99999999999999999999/**)", KEYS, 2);
  expect_refused("@ without an index is refused", "wpkh(@/**)", KEYS, 1);
  expect_refused("a policy without keys is refused", "wpkh(@0/**)", NULL, 0);
  const char *const missing[] = {NULL};
  expect_refused("a NULL key is refused", "wpkh(@0/**)", missing, 1);
  expect_refused("a NULL policy is refused", NULL, KEYS, 1);
}

int main(void) {
  printf("BIP-388 wallet policy tests\n");
  printf("===========================\n\n");

  test_expanded();
  test_refused();

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
