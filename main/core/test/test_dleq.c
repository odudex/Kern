#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <wally_core.h>

#include "core/dleq.h"

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

/* BIP374 vectors, as bwk's sp/src/core/dleq.rs tests carry them */
static const char GEN_SECRET[] =
    "07ff93d43f1012a5d4a44aba55240212ed39c87b3344e46757d99f24177fc576";
static const char GEN_BASE[] =
    "02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f";
static const char GEN_AUX[] =
    "cb979b0fc8ccc7f237751e719d992fcc324b6500af33999cd54a3e5c05fb1ea4";
static const char GEN_GENERATOR[] =
    "02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e";
static const char GEN_MESSAGE[] =
    "efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859";
static const char GEN_PROOF[] =
    "7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94"
    "118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a";

static const char VER_GENERATOR[] =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
static const char VER_PUBLIC[] =
    "03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9";
static const char VER_BASE[] =
    "021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608";
static const char VER_SHARED_SECRET[] =
    "03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a";
static const char VER_PROOF[] =
    "78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6b"
    "de0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb";
static const char VER_MESSAGE[] =
    "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794";
static const char VER_OTHER_MESSAGE[] =
    "22616bb5fb6d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794";

static bool hex_to(const char *hex, unsigned char *out, size_t len) {
  size_t written;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

static secp256k1_pubkey point(const char *hex) {
  secp256k1_pubkey out;
  unsigned char ser[33];
  memset(&out, 0, sizeof(out));
  if (!hex_to(hex, ser, sizeof(ser)) ||
      !secp256k1_ec_pubkey_parse(wally_get_secp_context(), &out, ser,
                                 sizeof(ser)))
    printf("bad test point %s\n", hex);
  return out;
}

static void test_prove_matches_vector(void) {
  unsigned char secret[32], aux[DLEQ_AUX_LEN], message[DLEQ_MESSAGE_LEN];
  unsigned char expected[DLEQ_PROOF_LEN], proof[DLEQ_PROOF_LEN];
  secp256k1_pubkey base = point(GEN_BASE);
  secp256k1_pubkey generator = point(GEN_GENERATOR);

  TEST("dleq_prove matches the BIP374 generation vector");
  if (hex_to(GEN_SECRET, secret, sizeof(secret)) &&
      hex_to(GEN_AUX, aux, sizeof(aux)) &&
      hex_to(GEN_MESSAGE, message, sizeof(message)) &&
      hex_to(GEN_PROOF, expected, sizeof(expected)) &&
      dleq_prove(secret, &base, aux, &generator, message, proof) &&
      memcmp(proof, expected, sizeof(proof)) == 0)
    PASS();
  else
    FAIL("proof differs from the vector");
}

static void test_verify_vectors(void) {
  unsigned char proof[DLEQ_PROOF_LEN];
  unsigned char message[DLEQ_MESSAGE_LEN], other[DLEQ_MESSAGE_LEN];
  secp256k1_pubkey generator = point(VER_GENERATOR);
  secp256k1_pubkey public = point(VER_PUBLIC);
  secp256k1_pubkey base = point(VER_BASE);
  secp256k1_pubkey shared_secret = point(VER_SHARED_SECRET);

  if (!hex_to(VER_PROOF, proof, sizeof(proof)) ||
      !hex_to(VER_MESSAGE, message, sizeof(message)) ||
      !hex_to(VER_OTHER_MESSAGE, other, sizeof(other))) {
    FAIL("bad verification vector");
    return;
  }

  TEST("dleq_verify accepts the BIP374 verification vector");
  if (dleq_verify(&public, &base, &shared_secret, proof, &generator, message))
    PASS();
  else
    FAIL("valid proof rejected");

  TEST("dleq_verify rejects swapped public and base points");
  if (!dleq_verify(&base, &public, &shared_secret, proof, &generator, message))
    PASS();
  else
    FAIL("swapped points accepted");

  TEST("dleq_verify rejects another message");
  if (!dleq_verify(&public, &base, &shared_secret, proof, &generator, other))
    PASS();
  else
    FAIL("other message accepted");

  TEST("dleq_verify rejects a tampered response");
  proof[DLEQ_PROOF_LEN - 1] ^= 0x01;
  if (!dleq_verify(&public, &base, &shared_secret, proof, &generator, message))
    PASS();
  else
    FAIL("tampered proof accepted");
}

/* The silent payments use: generator G and no message */
static void test_prove_without_message(void) {
  const secp256k1_context *ctx = wally_get_secp_context();
  unsigned char secret[32], aux[DLEQ_AUX_LEN] = {0}, proof[DLEQ_PROOF_LEN];
  secp256k1_pubkey generator = point(VER_GENERATOR);
  secp256k1_pubkey base = point(VER_BASE);
  secp256k1_pubkey public, shared_secret;

  shared_secret = base;
  TEST("dleq_prove with G and no message verifies");
  if (hex_to(GEN_SECRET, secret, sizeof(secret)) &&
      secp256k1_ec_pubkey_create(ctx, &public, secret) &&
      secp256k1_ec_pubkey_tweak_mul(ctx, &shared_secret, secret) &&
      dleq_prove(secret, &base, aux, &generator, NULL, proof) &&
      dleq_verify(&public, &base, &shared_secret, proof, &generator, NULL))
    PASS();
  else
    FAIL("proof without message failed");

  TEST("dleq_verify rejects a proof against another base");
  if (!dleq_verify(&public, &generator, &shared_secret, proof, &generator,
                   NULL))
    PASS();
  else
    FAIL("proof accepted for another base");
}

int main(void) {
  test_prove_matches_vector();
  test_verify_vectors();
  test_prove_without_message();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
