#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bip377.h>
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

/* BIP352 receiving vectors' scan secret, whose public key is
 * VECTOR_SCAN_PUBKEY, and its labelled addresses with VECTOR_SPEND_PUBKEY */
static const char VECTOR_SCAN_SECRET[] =
    "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
static const char VECTOR_LABEL_1_ADDRESS[] =
    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cg"
    "hth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj";
static const char VECTOR_LABEL_2_ADDRESS[] =
    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw"
    "353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq";
static const char VECTOR_LABEL_1001337_ADDRESS[] =
    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5y"
    "ecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5";
static const char VECTOR_TESTNET_LABEL_1_ADDRESS[] =
    "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05c"
    "ghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y9weewf";
/* VECTOR_TESTNET_LABEL_1_ADDRESS re-encoded under sprt with the reference
 * bech32m implementation */
static const char VECTOR_REGTEST_LABEL_1_ADDRESS[] =
    "sprt1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05c"
    "ghth75n0qcj59e3e2anscr0q9wyknjxtxycg07yhdda0m";
static const char VECTOR_LABEL_1_SPEND_PUBKEY[] =
    "03a6739499dc667d308baefea4de0c4a85cc72aece181bc05712d3919662610ff1";

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
      sp_address_alloc(scan, spend, SP_HRP_MAINNET, &address) &&
      strcmp(address, VECTOR_ADDRESS) == 0)
    PASS();
  else
    FAIL(address ? address : "sp_address_alloc failed");
  free(address);
}

static void expect_account_address(const char *name, const uint32_t *label,
                                   size_t label_len, const char *hrp,
                                   const char *expected) {
  unsigned char scan_secret[SP_SECRET_LEN], spend[SP_PUBKEY_LEN];
  char *address = NULL;
  TEST(name);
  if (hex_to(VECTOR_SCAN_SECRET, scan_secret, sizeof(scan_secret)) &&
      hex_to(VECTOR_SPEND_PUBKEY, spend, sizeof(spend)) &&
      sp_account_address_alloc(scan_secret, spend, label, label_len, hrp,
                               &address) == SP_ADDRESS_OK &&
      strcmp(address, expected) == 0)
    PASS();
  else
    FAIL(address ? address : "sp_account_address_alloc failed");
  free(address);
}

static void expect_account_address_error(const char *name,
                                         const char *scan_secret_hex,
                                         const uint32_t *label,
                                         size_t label_len,
                                         sp_address_result_t expected) {
  unsigned char scan_secret[SP_SECRET_LEN], spend[SP_PUBKEY_LEN];
  char *address = NULL;
  TEST(name);
  if (hex_to(scan_secret_hex, scan_secret, sizeof(scan_secret)) &&
      hex_to(VECTOR_SPEND_PUBKEY, spend, sizeof(spend)) &&
      sp_account_address_alloc(scan_secret, spend, label, label_len,
                               SP_HRP_MAINNET, &address) == expected &&
      !address)
    PASS();
  else
    FAIL(address ? address : "unexpected result");
  free(address);
}

static void test_account_address(void) {
  const uint32_t label_0[] = {0};
  const uint32_t label_1[] = {1};
  const uint32_t label_2[] = {2};
  const uint32_t label_1001337[] = {1001337};
  const uint32_t two_steps[] = {1, 2};
  unsigned char scan_secret[SP_SECRET_LEN], spend[SP_PUBKEY_LEN];
  unsigned char labeled[SP_PUBKEY_LEN], expected[SP_PUBKEY_LEN];

  expect_account_address("sp_account_address_alloc gives the base address",
                         NULL, 0, SP_HRP_MAINNET, VECTOR_ADDRESS);
  expect_account_address("sp_account_address_alloc labels with m = 1", label_1,
                         1, SP_HRP_MAINNET, VECTOR_LABEL_1_ADDRESS);
  expect_account_address("sp_account_address_alloc labels with m = 2", label_2,
                         1, SP_HRP_MAINNET, VECTOR_LABEL_2_ADDRESS);
  expect_account_address("sp_account_address_alloc labels with m = 1001337",
                         label_1001337, 1, SP_HRP_MAINNET,
                         VECTOR_LABEL_1001337_ADDRESS);
  expect_account_address("sp_account_address_alloc encodes tsp on testnet",
                         label_1, 1, SP_HRP_TESTNET,
                         VECTOR_TESTNET_LABEL_1_ADDRESS);
  expect_account_address("sp_account_address_alloc encodes sprt on regtest",
                         label_1, 1, SP_HRP_REGTEST,
                         VECTOR_REGTEST_LABEL_1_ADDRESS);
  expect_account_address_error(
      "sp_account_address_alloc refuses the change label", VECTOR_SCAN_SECRET,
      label_0, 1, SP_ADDRESS_ERR_LABEL);
  expect_account_address_error(
      "sp_account_address_alloc refuses a two step label path",
      VECTOR_SCAN_SECRET, two_steps, 2, SP_ADDRESS_ERR_LABEL);
  expect_account_address_error(
      "sp_account_address_alloc refuses a zero scan secret",
      "0000000000000000000000000000000000000000000000000000000000000000", NULL,
      0, SP_ADDRESS_ERR_KEY);

  TEST("sp_labeled_spend_pubkey labels the spend key with m = 1");
  if (hex_to(VECTOR_SCAN_SECRET, scan_secret, sizeof(scan_secret)) &&
      hex_to(VECTOR_SPEND_PUBKEY, spend, sizeof(spend)) &&
      hex_to(VECTOR_LABEL_1_SPEND_PUBKEY, expected, sizeof(expected)) &&
      sp_labeled_spend_pubkey(scan_secret, spend, 1, labeled) &&
      memcmp(labeled, expected, sizeof(expected)) == 0)
    PASS();
  else
    FAIL("labelled spend key differs");
}

static void test_descriptor_ownership(void) {
  char without_checksum[sizeof(MAINNET_DESCRIPTOR)];
  size_t body_len = strchr(MAINNET_DESCRIPTOR, '#') - MAINNET_DESCRIPTOR;
  memcpy(without_checksum, MAINNET_DESCRIPTOR, body_len);
  without_checksum[body_len] = '\0';

  TEST("sp_descriptor_is_sp tells sp() descriptors apart");
  if (sp_descriptor_is_sp(MAINNET_DESCRIPTOR) &&
      !sp_descriptor_is_sp("tr([73c5da0a/86'/0'/0']xpub)") &&
      !sp_descriptor_is_sp(NULL))
    PASS();
  else
    FAIL("sp() detection wrong");

  TEST("sp_descriptor_is_ours accepts our descriptor, its checksum aside");
  if (sp_descriptor_is_ours(MAINNET_DESCRIPTOR, false) &&
      sp_descriptor_is_ours(without_checksum, false) &&
      sp_descriptor_is_ours(TESTNET_DESCRIPTOR, true))
    PASS();
  else
    FAIL("own descriptor rejected");

  TEST("sp_descriptor_is_ours rejects another network or account");
  without_checksum[body_len - 2] ^= 1;
  if (!sp_descriptor_is_ours(MAINNET_DESCRIPTOR, true) &&
      !sp_descriptor_is_ours(TESTNET_DESCRIPTOR, false) &&
      !sp_descriptor_is_ours(without_checksum, false))
    PASS();
  else
    FAIL("foreign descriptor accepted");
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

/* Register Descriptor "3f82-9b" for our testnet spend key m/352'/1'/0'/0'/0
 * with the scan key REQUEST_SCAN_SECRET, not ours (SCAN_PATH absent) */
static const char REGISTER_FOREIGN_SCAN_REQUEST[] =
    "4249503337370103000607336638322d3962010373c5da0a058000016080000001800000"
    "00800000000000000000019573aff499b1755c5fbfd127f508c7d2bcb5dd8cb052f26661"
    "04db6fdf41e14f";
static const char REQUEST_SCAN_SECRET[] =
    "9573aff499b1755c5fbfd127f508c7d2bcb5dd8cb052f2666104db6fdf41e14f";
static const char REQUEST_SCAN_PUBKEY[] =
    "0395e054d3750420f2c79241842553e15b3cfe43f71fb07152fb37191af292e7b6";
/* bip377 test vector address_verification_sp_foreign_scan_request:
 * label 2 of our testnet spend key with VECTOR_SCAN_SECRET */
static const char VERIFY_FOREIGN_SCAN_REQUEST[] =
    "42495033373701040001046d61696e010000000201077370317178797a010373c5da0a05"
    "800001608000000180000000800000000000000000010f694e068028a717f8af6b9411f9"
    "a133dd3565258714cc226594b34db90c1f2c00";
/* Label 2 of our testnet spend key with VECTOR_SCAN_SECRET, by the BIP352
 * label tweak computed outside Kern */
static const char VECTOR_SCAN_OUR_SPEND_LABEL_2_TESTNET_ADDRESS[] =
    "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqugu2zk2789znj8"
    "xw9343a505wg8yymzuxxl9fg5e2utfgrm3tjhseudh47";
/* Our testnet scan secret, in TESTNET_DESCRIPTOR */
static const char TESTNET_SCAN_SECRET[] =
    "38658693c017c46fd6b8bb94b8766c123cd5baf6026338305b6f59f82b36f9c0";
/* The secp256k1 group order, not a valid secret key */
static const char CURVE_ORDER[] =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

static const unsigned char OUR_FINGERPRINT[4] = {0x73, 0xc5, 0xda, 0x0a};
static const unsigned char OTHER_FINGERPRINT[4] = {0x73, 0xc5, 0xda, 0x0b};
static const uint32_t TESTNET_SPEND[] = {H(352), H(1), H(0), H(0), 0};
static const uint32_t TESTNET_SPEND_1[] = {H(352), H(1), H(0), H(0), 1};
static const uint32_t TESTNET_SCAN[] = {H(352), H(1), H(0), H(1), 0};
static const uint32_t TESTNET_SCAN_1[] = {H(352), H(1), H(0), H(1), 1};
static const uint32_t MAINNET_SPEND[] = {H(352), H(0), H(0), H(0), 0};

static void expect_account(const char *name, const unsigned char *fingerprint,
                           const uint32_t *spend, const uint32_t *scan_path,
                           const char *scan_key_hex, bool is_testnet,
                           sp_account_t expected) {
  unsigned char scan_key[SP_SECRET_LEN];
  TEST(name);
  if (scan_key_hex && !hex_to(scan_key_hex, scan_key, sizeof(scan_key)))
    FAIL("bad scan key fixture");
  else if (sp_account_classify(
               fingerprint, spend, 5, scan_path, scan_path ? 5 : 0,
               scan_key_hex ? scan_key : NULL, is_testnet) != expected)
    FAIL("unexpected account");
  else
    PASS();
}

static void test_account_classify(void) {
  expect_account("our spend key with our scan path is our account",
                 OUR_FINGERPRINT, TESTNET_SPEND, TESTNET_SCAN, NULL, true,
                 SP_ACCOUNT_OURS);
  expect_account("our spend key with our scan key by value is our account",
                 OUR_FINGERPRINT, TESTNET_SPEND, NULL, TESTNET_SCAN_SECRET,
                 true, SP_ACCOUNT_OURS);
  expect_account("our spend key with a scan key not ours is taken",
                 OUR_FINGERPRINT, TESTNET_SPEND, NULL, REQUEST_SCAN_SECRET,
                 true, SP_ACCOUNT_FOREIGN_SCAN);
  expect_account("the BIP352 vectors' scan key is not ours", OUR_FINGERPRINT,
                 TESTNET_SPEND, NULL, VECTOR_SCAN_SECRET, true,
                 SP_ACCOUNT_FOREIGN_SCAN);
  expect_account("a zero scan key is refused", OUR_FINGERPRINT, TESTNET_SPEND,
                 NULL,
                 "0000000000000000000000000000000000000000000000000000000000"
                 "000000",
                 true, SP_ACCOUNT_BAD_SCAN_KEY);
  expect_account("a scan key equal to the group order is refused",
                 OUR_FINGERPRINT, TESTNET_SPEND, NULL, CURVE_ORDER, true,
                 SP_ACCOUNT_BAD_SCAN_KEY);
  expect_account("another master key is not ours", OTHER_FINGERPRINT,
                 TESTNET_SPEND, NULL, REQUEST_SCAN_SECRET, true,
                 SP_ACCOUNT_NOT_OURS);
  expect_account("another spend index is not ours", OUR_FINGERPRINT,
                 TESTNET_SPEND_1, NULL, REQUEST_SCAN_SECRET, true,
                 SP_ACCOUNT_NOT_OURS);
  expect_account("a spend path on the scan branch is not ours", OUR_FINGERPRINT,
                 TESTNET_SCAN, NULL, REQUEST_SCAN_SECRET, true,
                 SP_ACCOUNT_NOT_OURS);
  expect_account("another scan index is not ours", OUR_FINGERPRINT,
                 TESTNET_SPEND, TESTNET_SCAN_1, NULL, true,
                 SP_ACCOUNT_NOT_OURS);
  expect_account("a scan path on the spend branch is not ours", OUR_FINGERPRINT,
                 TESTNET_SPEND, TESTNET_SPEND, NULL, true, SP_ACCOUNT_NOT_OURS);
  expect_account("a testnet spend key on mainnet is the other network",
                 OUR_FINGERPRINT, TESTNET_SPEND, NULL, REQUEST_SCAN_SECRET,
                 false, SP_ACCOUNT_OTHER_NETWORK);
  expect_account("a mainnet spend key on testnet is the other network",
                 OUR_FINGERPRINT, MAINNET_SPEND, TESTNET_SCAN, NULL, true,
                 SP_ACCOUNT_OTHER_NETWORK);
}

static void test_account_keys(void) {
  unsigned char scan_secret[SP_SECRET_LEN], scan_pubkey[SP_PUBKEY_LEN];
  struct sp_keys ours, account;
  bool ok = hex_to(REQUEST_SCAN_SECRET, scan_secret, sizeof(scan_secret)) &&
            hex_to(REQUEST_SCAN_PUBKEY, scan_pubkey, sizeof(scan_pubkey)) &&
            sp_keys_derive(true, &ours);

  TEST("sp_account_keys_derive without a scan key gives our keys");
  if (ok && sp_account_keys_derive(true, NULL, &account) &&
      memcmp(&account, &ours, sizeof(ours)) == 0)
    PASS();
  else
    FAIL("keys differ");

  TEST("sp_account_keys_derive pairs our spend key with the scan key");
  if (ok && sp_account_keys_derive(true, scan_secret, &account) &&
      memcmp(account.scan_secret, scan_secret, SP_SECRET_LEN) == 0 &&
      memcmp(account.scan_pubkey, scan_pubkey, SP_PUBKEY_LEN) == 0 &&
      memcmp(account.spend_secret, ours.spend_secret, SP_SECRET_LEN) == 0 &&
      memcmp(account.spend_pubkey, ours.spend_pubkey, SP_PUBKEY_LEN) == 0)
    PASS();
  else
    FAIL("account keys wrong");
  sp_keys_wipe(&ours);
  sp_keys_wipe(&account);
}

static const bip377_request *decode_hex(const char *hex) {
  unsigned char bytes[256];
  size_t len = 0;
  const bip377_request *request = NULL;
  if (wally_hex_to_bytes(hex, bytes, sizeof(bytes), &len) != WALLY_OK ||
      bip377_request_decode(bytes, len, &request, NULL) != BIP377_OK)
    return NULL;
  return request;
}

static sp_account_t request_account(const bip377_sp_keys *sp, bool is_testnet) {
  bool by_path = sp->scan_kind == BIP377_SCAN_PATH;
  return sp_account_classify(
      sp->fingerprint, sp->spend_path.ptr, sp->spend_path.len,
      by_path ? sp->scan.path.ptr : NULL, by_path ? sp->scan.path.len : 0,
      by_path ? NULL : sp->scan.key, is_testnet);
}

static void test_register_foreign_scan_request(void) {
  unsigned char scan_secret[SP_SECRET_LEN];
  const bip377_request *request = decode_hex(REGISTER_FOREIGN_SCAN_REQUEST);
  const bip377_register_descriptor *reg =
      request ? &request->body.register_descriptor : NULL;
  const bip377_descriptor_body *body = reg ? reg->descriptor : NULL;
  const bip377_sp_keys *sp = body ? &body->value.sp_keys : NULL;

  TEST("the Register Descriptor request with a scan key decodes");
  if (sp && request->message_type == BIP377_MESSAGE_REGISTER_DESCRIPTOR &&
      strcmp(reg->descriptor_alias, "3f82-9b") == 0 &&
      body->tag == BIP377_DESCRIPTOR_SP_KEYS &&
      memcmp(sp->fingerprint, OUR_FINGERPRINT, 4) == 0 &&
      sp->spend_path.len == 5 &&
      memcmp(sp->spend_path.ptr, TESTNET_SPEND, sizeof(TESTNET_SPEND)) == 0 &&
      sp->scan_kind == BIP377_SCAN_KEY &&
      hex_to(REQUEST_SCAN_SECRET, scan_secret, sizeof(scan_secret)) &&
      memcmp(sp->scan.key, scan_secret, SP_SECRET_LEN) == 0)
    PASS();
  else
    FAIL("unexpected request");

  TEST("its keys are our spend key with a scan key not ours");
  if (sp && request_account(sp, true) == SP_ACCOUNT_FOREIGN_SCAN)
    PASS();
  else
    FAIL("account refused");
  bip377_request_free(request);
}

static void test_verify_foreign_scan_request(void) {
  const bip377_request *request = decode_hex(VERIFY_FOREIGN_SCAN_REQUEST);
  const bip377_verify_address *verify =
      request ? &request->body.verify_address : NULL;
  const bip377_sp_keys *sp =
      verify && verify->descriptor ? &verify->descriptor->value.sp_keys : NULL;
  struct sp_keys keys;
  char *address = NULL;

  TEST("the bip377 labelled scan key vector names our spend key");
  if (sp && request->message_type == BIP377_MESSAGE_ADDRESS_VERIFICATION &&
      request_account(sp, true) == SP_ACCOUNT_FOREIGN_SCAN)
    PASS();
  else
    FAIL("account refused");

  TEST("its label 2 address is computed with its scan key");
  if (sp && verify->derivation_path.len == 1 &&
      verify->derivation_path.ptr[0] == 2 &&
      sp_account_keys_derive(true, sp->scan.key, &keys) &&
      sp_account_address_alloc(keys.scan_secret, keys.spend_pubkey,
                               verify->derivation_path.ptr,
                               verify->derivation_path.len, SP_HRP_TESTNET,
                               &address) == SP_ADDRESS_OK &&
      strcmp(address, VECTOR_SCAN_OUR_SPEND_LABEL_2_TESTNET_ADDRESS) == 0)
    PASS();
  else
    FAIL(address ? address : "no address");
  sp_keys_wipe(&keys);
  free(address);
  bip377_request_free(request);
}

int main(void) {
  test_path_on_branch();
  test_account_address();

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
  test_descriptor_ownership();
  test_account_classify();
  test_account_keys();
  test_register_foreign_scan_request();
  test_verify_foreign_scan_request();
  key_unload();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
