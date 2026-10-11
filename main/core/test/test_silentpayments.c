#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>
#include <wally_core.h>

#include "kern_bech32.h"

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

#define MAX_KEYS 2
#define MAX_RECIPIENTS 3
#define OUTPOINT_LEN 36

/* A BIP352 sending vector (bip352_send_and_receive_test_vectors.json of
 * secp256k1 PR #1765). Outputs are listed as the vector does, unordered. */
struct sender_vector {
  const char *name;
  const char *seckeys[MAX_KEYS];
  size_t n_seckeys;
  const char *taproot_seckeys[MAX_KEYS];
  size_t n_taproot_seckeys;
  const char *outpoint_smallest;
  const char *scan_pubkeys[MAX_RECIPIENTS];
  const char *spend_pubkeys[MAX_RECIPIENTS];
  size_t n_recipients;
  const char *outputs[MAX_RECIPIENTS];
};

static const char SCAN_A[] =
    "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4";
static const char SPEND_A[] =
    "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
static const char SCAN_B[] =
    "02062d49ffc02787d586c608dfbec184aa91a6597d97b463ea5c6babd9d17a95a3";
static const char SPEND_B[] =
    "0381eb9a9a9ec739d527c1631b31b421566f5c2a47b4ab5b1f6a686dfb68eab716";
static const char OUTPOINT_F418[] =
    "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f400000000";

static const struct sender_vector VECTORS[] = {
    {
        .name = "Simple send: two inputs",
        .seckeys = {"eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5"
                    "dff3b1",
                    "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a940"
                    "8aad16"},
        .n_seckeys = 2,
        .outpoint_smallest = OUTPOINT_F418,
        .scan_pubkeys = {SCAN_A},
        .spend_pubkeys = {SPEND_A},
        .n_recipients = 1,
        .outputs = {"3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de"
                    "46e3c1"},
    },
    {
        .name = "Single recipient: taproot only with mixed even/odd y-values",
        .taproot_seckeys = {"eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b4215"
                            "4201b8e5dff3b1",
                            "1d37787c2b7116ee983e9f9c13269df29091b391c04db94239"
                            "e0d2bc2182c3bf"},
        .n_taproot_seckeys = 2,
        .outpoint_smallest = OUTPOINT_F418,
        .scan_pubkeys = {SCAN_A},
        .spend_pubkeys = {SPEND_A},
        .n_recipients = 1,
        .outputs = {"77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf2"
                    "6b99f1"},
    },
    {
        .name = "Multiple outputs: multiple outputs, multiple recipients",
        .seckeys = {"eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5"
                    "dff3b1",
                    "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164"
                    "fad66a"},
        .n_seckeys = 2,
        .outpoint_smallest = OUTPOINT_F418,
        .scan_pubkeys = {SCAN_A, SCAN_B, SCAN_B},
        .spend_pubkeys = {SPEND_A, SPEND_B, SPEND_B},
        .n_recipients = 3,
        .outputs = {"2e847bb01d1b491da512ddd760b8509617ee38057003d6115d00ba5624"
                    "51323a",
                    "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be03"
                    "2d64e8",
                    "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325"
                    "db33ac"},
    },
};

static bool hex_to(const char *hex, unsigned char *out, size_t len) {
  size_t written;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

static bool parse_pubkey(const secp256k1_context *ctx, const char *hex,
                         secp256k1_pubkey *out) {
  unsigned char ser[33];
  return hex_to(hex, ser, sizeof(ser)) &&
         secp256k1_ec_pubkey_parse(ctx, out, ser, sizeof(ser));
}

static bool output_expected(const struct sender_vector *v,
                            const unsigned char *xonly) {
  for (size_t i = 0; i < v->n_recipients; i++) {
    unsigned char expected[32];
    if (hex_to(v->outputs[i], expected, sizeof(expected)) &&
        memcmp(expected, xonly, sizeof(expected)) == 0)
      return true;
  }
  return false;
}

static bool sender_vector_passes(const struct sender_vector *v) {
  const secp256k1_context *ctx = wally_get_secp_context();
  unsigned char seckeys[MAX_KEYS][32];
  const unsigned char *seckey_ptrs[MAX_KEYS];
  secp256k1_keypair keypairs[MAX_KEYS];
  const secp256k1_keypair *keypair_ptrs[MAX_KEYS];
  secp256k1_silentpayments_recipient recipients[MAX_RECIPIENTS];
  const secp256k1_silentpayments_recipient *recipient_ptrs[MAX_RECIPIENTS];
  secp256k1_xonly_pubkey outputs[MAX_RECIPIENTS];
  secp256k1_xonly_pubkey *output_ptrs[MAX_RECIPIENTS];
  unsigned char outpoint[OUTPOINT_LEN];

  for (size_t i = 0; i < v->n_seckeys; i++) {
    if (!hex_to(v->seckeys[i], seckeys[i], 32))
      return false;
    seckey_ptrs[i] = seckeys[i];
  }
  for (size_t i = 0; i < v->n_taproot_seckeys; i++) {
    unsigned char seckey[32];
    if (!hex_to(v->taproot_seckeys[i], seckey, sizeof(seckey)) ||
        !secp256k1_keypair_create(ctx, &keypairs[i], seckey))
      return false;
    keypair_ptrs[i] = &keypairs[i];
  }
  for (size_t i = 0; i < v->n_recipients; i++) {
    if (!parse_pubkey(ctx, v->scan_pubkeys[i], &recipients[i].scan_pubkey) ||
        !parse_pubkey(ctx, v->spend_pubkeys[i], &recipients[i].spend_pubkey))
      return false;
    recipients[i].index = i;
    recipient_ptrs[i] = &recipients[i];
    output_ptrs[i] = &outputs[i];
  }
  if (!hex_to(v->outpoint_smallest, outpoint, sizeof(outpoint)))
    return false;

  if (!secp256k1_silentpayments_sender_create_outputs(
          ctx, output_ptrs, recipient_ptrs, v->n_recipients, outpoint,
          v->n_taproot_seckeys ? keypair_ptrs : NULL, v->n_taproot_seckeys,
          v->n_seckeys ? seckey_ptrs : NULL, v->n_seckeys))
    return false;

  for (size_t i = 0; i < v->n_recipients; i++) {
    unsigned char xonly[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, xonly, &outputs[i]) ||
        !output_expected(v, xonly))
      return false;
  }
  return true;
}

static bool address_encodes(const char *scan_hex, const char *spend_hex,
                            const char *expected) {
  unsigned char keys[66];
  char address[KERN_BECH32M_MAX_LEN + 1];
  return hex_to(scan_hex, keys, 33) && hex_to(spend_hex, keys + 33, 33) &&
         kern_bech32m_encode("sp", 0, keys, sizeof(keys), address,
                             sizeof(address)) == WALLY_OK &&
         strcmp(address, expected) == 0;
}

int main(void) {
  for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
    TEST(VECTORS[i].name);
    if (sender_vector_passes(&VECTORS[i]))
      PASS();
    else
      FAIL("generated outputs differ from the vector");
  }

  TEST("kern_bech32m_encode builds the vector's sp1 address");
  if (address_encodes(
          SCAN_A, SPEND_A,
          "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6m"
          "urw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv") &&
      address_encodes(
          SCAN_B, SPEND_B,
          "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48"
          "k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn"))
    PASS();
  else
    FAIL("address mismatch");

  TEST("kern_bech32m_encode refuses a buffer too small");
  {
    unsigned char keys[66] = {0};
    char address[90];
    if (kern_bech32m_encode("sp", 0, keys, sizeof(keys), address,
                            sizeof(address)) == WALLY_EINVAL)
      PASS();
    else
      FAIL("encoded into a 90-char buffer");
  }

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
