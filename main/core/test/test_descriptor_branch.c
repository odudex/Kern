/*
 * Per-branch descriptor tests (core/descriptor_branch.c).
 *
 * A branch copy must pay exactly what the original pays at its multipath
 * group, for every child: checked against the original for children 0-199.
 */

#include "../descriptor_branch.h"
#include "../wallet.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#define H BIP32_INITIAL_HARDENED_CHILD
#define CHILDREN 200

wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

static char *make_xpub(unsigned char fill, bool testnet) {
  unsigned char seed[32];
  memset(seed, fill, sizeof(seed));
  struct ext_key master, account;
  const uint32_t path[4] = {48 | H, (testnet ? 1 : 0) | H, 0 | H, 2 | H};
  char *out = NULL;
  if (bip32_key_from_seed(seed, sizeof(seed),
                          testnet ? BIP32_VER_TEST_PRIVATE
                                  : BIP32_VER_MAIN_PRIVATE,
                          0, &master) != WALLY_OK ||
      bip32_key_from_parent_path(&master, path, 4, BIP32_FLAG_KEY_PRIVATE,
                                 &account) != WALLY_OK ||
      bip32_key_to_base58(&account, BIP32_FLAG_KEY_PUBLIC, &out) != WALLY_OK)
    return NULL;
  return out;
}

static struct wally_descriptor *parse(const char *text, bool testnet) {
  struct wally_descriptor *desc = NULL;
  if (wallet_descriptor_parse(text, NULL,
                              testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                      : WALLY_NETWORK_BITCOIN_MAINNET,
                              &desc) != WALLY_OK)
    return NULL;
  return desc;
}

static bool same_addresses(const struct wally_descriptor *desc,
                           uint32_t multi_index,
                           const struct wally_descriptor *branch) {
  for (uint32_t i = 0; i < CHILDREN; i++) {
    char *a = NULL, *b = NULL;
    bool same =
        wally_descriptor_to_address(desc, 0, multi_index, i, 0, &a) ==
            WALLY_OK &&
        wally_descriptor_to_address(branch, 0, 0, i, 0, &b) == WALLY_OK &&
        strcmp(a, b) == 0;
    wally_free_string(a);
    wally_free_string(b);
    if (!same) {
      printf("  child %u differs\n", i);
      return false;
    }
  }
  return true;
}

static void check_branches(const char *name, const char *text, bool testnet) {
  char label[128];
  struct wally_descriptor *desc = parse(text, testnet);
  uint32_t num_paths = 0;
  snprintf(label, sizeof(label), "%s parses", name);
  check(label,
        desc && wally_descriptor_get_num_paths(desc, &num_paths) == WALLY_OK);
  if (!desc)
    return;
  for (uint32_t mi = 0; mi < num_paths; mi++) {
    struct wally_descriptor *branch = descriptor_branch_alloc(desc, mi);
    uint32_t branch_paths = 0;
    snprintf(label, sizeof(label),
             "%s: branch %u is single-path and pays the same for %d children",
             name, mi, CHILDREN);
    check(label, branch &&
                     wally_descriptor_get_num_paths(branch, &branch_paths) ==
                         WALLY_OK &&
                     branch_paths == 1 && same_addresses(desc, mi, branch));
    wally_descriptor_free(branch);
  }
  wally_descriptor_free(desc);
}

int main(void) {
  /* The host libwally hashes through PSA, as the device does, which needs
   * wally_init. */
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
  printf("=== descriptor_branch tests ===\n\n");

  char *k1 = make_xpub(1, false), *k2 = make_xpub(2, false),
       *k3 = make_xpub(3, false);
  char *t1 = make_xpub(4, true), *t2 = make_xpub(5, true);
  if (!k1 || !k2 || !k3 || !t1 || !t2) {
    printf("ABORT: key setup failed\n");
    return 1;
  }
  char text[1024];

  snprintf(text, sizeof(text),
           "wsh(sortedmulti(2,[aaaaaaaa/48h/0h/0h/2h]%s/<0;1>/*,"
           "[bbbbbbbb/48h/0h/0h/2h]%s/<0;1>/*,[cccccccc/48h/0h/0h/2h]%s/<0;1>/"
           "*))",
           k1, k2, k3);
  check_branches("wsh sortedmulti 2-of-3", text, false);

  snprintf(text, sizeof(text),
           "wsh(or_d(pk(%s/<0;1>/*),and_v(v:pkh(%s/<0;1>/*),older(1000))))", k1,
           k2);
  check_branches("wsh miniscript", text, false);

  snprintf(text, sizeof(text), "tr(%s/<0;1>/*,{pk(%s/<0;1>/*),pk(%s/<0;1>/*)})",
           k1, k2, k3);
  check_branches("tr() tree", text, false);

  snprintf(text, sizeof(text), "wsh(sortedmulti(2,%s/0/*,%s/0/*))", k1, k2);
  check_branches("single-path wsh", text, false);

  snprintf(text, sizeof(text),
           "wsh(multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2"
           "815b16f81798,%s/<0;1>/*))",
           k1);
  check_branches("raw key beside an xpub", text, false);

  snprintf(text, sizeof(text), "wsh(multi(1,%s/7/<0;1>/*,%s/<0;1>/3/*))", k1,
           k2);
  check_branches("multipath step mid-path", text, false);

  snprintf(text, sizeof(text), "wsh(sortedmulti(1,%s/<0;1>/*,%s/<0;1>/*))", t1,
           t2);
  check_branches("testnet", text, true);

  snprintf(text, sizeof(text), "wsh(pk(%s))", k1);
  struct wally_descriptor *desc = parse(text, false);
  check("a key with nothing to derive gives no branch",
        desc && descriptor_branch_alloc(desc, 0) == NULL);
  wally_descriptor_free(desc);

  snprintf(text, sizeof(text), "wsh(multi(1,%s/<0;1>/*))", k1);
  desc = parse(text, false);
  check("a multipath group the descriptor lacks gives no branch",
        desc && descriptor_branch_alloc(desc, 2) == NULL);
  wally_descriptor_free(desc);
  check("NULL gives no branch", descriptor_branch_alloc(NULL, 0) == NULL);

  wally_free_string(k1);
  wally_free_string(k2);
  wally_free_string(k3);
  wally_free_string(t1);
  wally_free_string(t2);
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
