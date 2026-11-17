#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>

#include "core/key.h"
#include "core/silent_payments.h"

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

/* BIP39 test mnemonic, empty passphrase */
static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* The test mnemonic's mainnet scan and spend public keys, as bwk derives
 * them */
static const char MAINNET_SCAN_PUBKEY[] =
    "024139b0f81042e243a90478e43990c6a27be0e3346f0c71adbbcdd511beaea1e3";
static const char MAINNET_SPEND_PUBKEY[] =
    "02fa210b3c4a60b80dd1616f48ae53bbdf0db744b3f9083385108f81be0acb58c6";

/* BIP352 vector "Simple send: two inputs" recipient */
static const char VECTOR_SCAN_PUBKEY[] =
    "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4";
static const char VECTOR_SPEND_PUBKEY[] =
    "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
static const char VECTOR_ADDRESS[] =
    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56s"
    "uy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

static bool hex_to(const char *hex, unsigned char *out, size_t len) {
  size_t written;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

static void test_keys(void) {
  struct sp_keys keys;
  unsigned char scan[SP_PUBKEY_LEN], spend[SP_PUBKEY_LEN];
  TEST("sp_keys_derive gives bwk's mainnet scan and spend keys");
  if (hex_to(MAINNET_SCAN_PUBKEY, scan, sizeof(scan)) &&
      hex_to(MAINNET_SPEND_PUBKEY, spend, sizeof(spend)) &&
      sp_keys_derive(false, &keys) &&
      memcmp(keys.scan_pubkey, scan, sizeof(scan)) == 0 &&
      memcmp(keys.spend_pubkey, spend, sizeof(spend)) == 0)
    PASS();
  else
    FAIL("derived keys differ");
  sp_keys_wipe(&keys);
}

static void test_address(void) {
  unsigned char scan[SP_PUBKEY_LEN], spend[SP_PUBKEY_LEN];
  char *address = NULL;
  TEST("sp_address_alloc builds the BIP352 vector address");
  if (hex_to(VECTOR_SCAN_PUBKEY, scan, sizeof(scan)) &&
      hex_to(VECTOR_SPEND_PUBKEY, spend, sizeof(spend)) &&
      sp_address_alloc(scan, spend, false, &address) &&
      strcmp(address, VECTOR_ADDRESS) == 0)
    PASS();
  else
    FAIL(address ? address : "sp_address_alloc failed");
  free(address);
}

#define H(n) ((n) | BIP32_INITIAL_HARDENED_CHILD)

static void test_path_on_branch(void) {
  const uint32_t scan_0[] = {H(352), H(0), H(0), H(1), 0};
  const uint32_t scan_5[] = {H(352), H(0), H(0), H(1), 5};
  const uint32_t unhardened_purpose[] = {352, H(0), H(0), H(1), 0};
  const uint32_t spend[] = {H(352), H(0), H(0), H(0), 0};

  TEST("sp_path_on_branch matches the scan branch at any index");
  if (sp_path_on_branch(scan_0, 5, false, SP_SCAN_BRANCH) &&
      sp_path_on_branch(scan_5, 5, false, SP_SCAN_BRANCH))
    PASS();
  else
    FAIL("scan path rejected");

  TEST("sp_path_on_branch rejects other coins, purposes, depths, branches");
  if (!sp_path_on_branch(scan_0, 5, true, SP_SCAN_BRANCH) &&
      !sp_path_on_branch(unhardened_purpose, 5, false, SP_SCAN_BRANCH) &&
      !sp_path_on_branch(scan_0, 4, false, SP_SCAN_BRANCH) &&
      !sp_path_on_branch(spend, 5, false, SP_SCAN_BRANCH))
    PASS();
  else
    FAIL("foreign path accepted");
}

int main(void) {
  test_path_on_branch();

  if (!key_load_from_mnemonic(TEST_MNEMONIC, NULL, false)) {
    printf("FAIL: could not load the test mnemonic\n");
    return 1;
  }
  test_keys();
  test_address();
  key_unload();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
