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

/* Printed by bwk's SpDescriptor (bwk 24bfd42) for the test mnemonic, built as
 * Silent's hot.rs sp_descriptor builds it */
static const char MAINNET_DESCRIPTOR[] =
    "sp([73c5da0a/352'/0'/0']spscan1q0rnl6lft0gkpg4nsn528qgdpytfdej40atdqgrxpq"
    "qsg8c5r8vys973ppv7y5c9cphgkzm6g4efmhhcdkazt87ggxwz3pruphc9vkkxxhtvyag)#"
    "429s66dn";
static const char TESTNET_DESCRIPTOR[] =
    "sp([73c5da0a/352'/1'/0']tspscan1q8pjcdy7qzlzxl44chw2tsanvzg7dtwhkqf3nsvzm"
    "davls2ekl8qq9qesshy6w9knddr825kqp442302zuwddh6vtqk7zqvgszace9aczgnuqn3)#"
    "ke33wu3h";
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

static void test_descriptor(const char *name, bool is_testnet,
                            const char *expected) {
  char *descriptor = NULL;
  TEST(name);
  if (sp_descriptor_alloc(is_testnet, &descriptor) &&
      strcmp(descriptor, expected) == 0)
    PASS();
  else
    FAIL(descriptor ? descriptor : "sp_descriptor_alloc failed");
  free(descriptor);
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

int main(void) {
  TEST("sp_descriptor_alloc fails without a loaded key");
  char *descriptor = NULL;
  if (!sp_descriptor_alloc(false, &descriptor) && !descriptor)
    PASS();
  else
    FAIL("descriptor built without a key");

  if (!key_load_from_mnemonic(TEST_MNEMONIC, NULL, false)) {
    printf("FAIL: could not load the test mnemonic\n");
    return 1;
  }
  test_keys();
  test_descriptor("sp_descriptor_alloc matches bwk on mainnet", false,
                  MAINNET_DESCRIPTOR);
  test_descriptor("sp_descriptor_alloc matches bwk on testnet", true,
                  TESTNET_DESCRIPTOR);
  test_address();
  key_unload();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
