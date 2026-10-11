/*
 * BIP374 discrete logarithm equality proofs, ported from bwk's
 * sp/src/core/dleq.rs on top of the public libsecp256k1 API.
 */

#include "dleq.h"
#include "../utils/secure_mem.h"
#include <string.h>
#include <wally_core.h>

#define POINT_LEN 33
#define SCALAR_LEN 32

static const char TAG_AUX[] = "BIP0374/aux";
static const char TAG_NONCE[] = "BIP0374/nonce";
static const char TAG_CHALLENGE[] = "BIP0374/challenge";

static const unsigned char CURVE_ORDER[SCALAR_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
    0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

static bool tagged_hash(const char *tag, const unsigned char *msg,
                        size_t msg_len, unsigned char *out) {
  return secp256k1_tagged_sha256(wally_get_secp_context(), out,
                                 (const unsigned char *)tag, strlen(tag), msg,
                                 msg_len) == 1;
}

static bool is_below_order(const unsigned char *bytes) {
  return memcmp(bytes, CURVE_ORDER, SCALAR_LEN) < 0;
}

// A 256-bit hash is below twice the order, so one subtraction reduces it.
static void reduce_mod_order(unsigned char *bytes) {
  int borrow = 0;
  if (is_below_order(bytes))
    return;
  for (int i = SCALAR_LEN - 1; i >= 0; i--) {
    int value = bytes[i] - CURVE_ORDER[i] - borrow;
    bytes[i] = (unsigned char)value;
    borrow = value < 0;
  }
}

static bool is_zero(const unsigned char *bytes) {
  for (size_t i = 0; i < SCALAR_LEN; i++)
    if (bytes[i])
      return false;
  return true;
}

static bool serialize_point(const secp256k1_pubkey *point, unsigned char *out) {
  size_t len = POINT_LEN;
  return secp256k1_ec_pubkey_serialize(wally_get_secp_context(), out, &len,
                                       point, SECP256K1_EC_COMPRESSED) == 1;
}

static bool mul_point(const secp256k1_pubkey *point,
                      const unsigned char *scalar, secp256k1_pubkey *out) {
  *out = *point;
  return secp256k1_ec_pubkey_tweak_mul(wally_get_secp_context(), out, scalar) ==
         1;
}

// R = response*point - challenge*committed, as BIP374 verification rebuilds it
static bool rebuild_commitment(const secp256k1_pubkey *point,
                               const secp256k1_pubkey *committed,
                               const unsigned char *response,
                               const unsigned char *challenge,
                               secp256k1_pubkey *out) {
  const secp256k1_context *ctx = wally_get_secp_context();
  secp256k1_pubkey response_point, challenge_point;
  const secp256k1_pubkey *terms[2] = {&response_point, &challenge_point};

  return mul_point(point, response, &response_point) &&
         mul_point(committed, challenge, &challenge_point) &&
         secp256k1_ec_pubkey_negate(ctx, &challenge_point) == 1 &&
         secp256k1_ec_pubkey_combine(ctx, out, terms, 2) == 1;
}

// e = hash_challenge(A || B || C || G || R1 || R2 || m)
static bool challenge_hash(const secp256k1_pubkey *points[6],
                           const unsigned char *message, unsigned char *out) {
  unsigned char buf[6 * POINT_LEN + DLEQ_MESSAGE_LEN];
  size_t len = 0;

  for (size_t i = 0; i < 6; i++, len += POINT_LEN)
    if (!serialize_point(points[i], buf + len))
      return false;
  if (message) {
    memcpy(buf + len, message, DLEQ_MESSAGE_LEN);
    len += DLEQ_MESSAGE_LEN;
  }
  return tagged_hash(TAG_CHALLENGE, buf, len, out);
}

// k = hash_nonce((a xor hash_aux(r)) || A || C || m), reduced mod n
static bool nonce_scalar(const unsigned char *secret, const unsigned char *aux,
                         const secp256k1_pubkey *public,
                         const secp256k1_pubkey *shared_secret,
                         const unsigned char *message, unsigned char *out) {
  unsigned char buf[SCALAR_LEN + 2 * POINT_LEN + DLEQ_MESSAGE_LEN];
  size_t len = SCALAR_LEN;
  bool ok = tagged_hash(TAG_AUX, aux, DLEQ_AUX_LEN, buf);

  for (size_t i = 0; ok && i < SCALAR_LEN; i++)
    buf[i] ^= secret[i];
  ok = ok && serialize_point(public, buf + len);
  len += POINT_LEN;
  ok = ok && serialize_point(shared_secret, buf + len);
  len += POINT_LEN;
  if (ok && message) {
    memcpy(buf + len, message, DLEQ_MESSAGE_LEN);
    len += DLEQ_MESSAGE_LEN;
  }
  ok = ok && tagged_hash(TAG_NONCE, buf, len, out);
  secure_memzero(buf, sizeof(buf));
  if (ok)
    reduce_mod_order(out);
  return ok && !is_zero(out);
}

// s = k + e*a
static bool response_scalar(const unsigned char *secret,
                            const unsigned char *nonce,
                            const unsigned char *challenge,
                            unsigned char *out) {
  const secp256k1_context *ctx = wally_get_secp_context();
  memcpy(out, secret, SCALAR_LEN);
  return secp256k1_ec_seckey_tweak_mul(ctx, out, challenge) == 1 &&
         secp256k1_ec_seckey_tweak_add(ctx, out, nonce) == 1;
}

bool dleq_prove(const unsigned char *secret, const secp256k1_pubkey *base,
                const unsigned char *aux, const secp256k1_pubkey *generator,
                const unsigned char *message, unsigned char *proof_out) {
  secp256k1_pubkey public, shared_secret, r1, r2;
  unsigned char nonce[SCALAR_LEN];
  unsigned char challenge[SCALAR_LEN];
  unsigned char challenge_scalar[SCALAR_LEN];
  unsigned char response[SCALAR_LEN];
  bool ok;

  if (!secret || !base || !aux || !generator || !proof_out)
    return false;

  ok = mul_point(generator, secret, &public) &&
       mul_point(base, secret, &shared_secret) &&
       nonce_scalar(secret, aux, &public, &shared_secret, message, nonce) &&
       mul_point(generator, nonce, &r1) && mul_point(base, nonce, &r2);
  if (ok) {
    const secp256k1_pubkey *points[6] = {&public,   base, &shared_secret,
                                         generator, &r1,  &r2};
    ok = challenge_hash(points, message, challenge);
  }
  if (ok) {
    memcpy(challenge_scalar, challenge, SCALAR_LEN);
    reduce_mod_order(challenge_scalar);
    ok = response_scalar(secret, nonce, challenge_scalar, response);
  }
  secure_memzero(nonce, sizeof(nonce));
  if (!ok)
    return false;

  // The proof carries the challenge hash as is, the response as a scalar
  memcpy(proof_out, challenge, SCALAR_LEN);
  memcpy(proof_out + SCALAR_LEN, response, SCALAR_LEN);
  return dleq_verify(&public, base, &shared_secret, proof_out, generator,
                     message);
}

bool dleq_verify(const secp256k1_pubkey *public, const secp256k1_pubkey *base,
                 const secp256k1_pubkey *shared_secret,
                 const unsigned char *proof, const secp256k1_pubkey *generator,
                 const unsigned char *message) {
  const unsigned char *response = proof + SCALAR_LEN;
  unsigned char challenge_scalar[SCALAR_LEN];
  unsigned char expected[SCALAR_LEN];
  secp256k1_pubkey r1, r2;

  if (!public || !base || !shared_secret || !proof || !generator ||
      !is_below_order(response))
    return false;
  memcpy(challenge_scalar, proof, SCALAR_LEN);
  reduce_mod_order(challenge_scalar);
  if (!rebuild_commitment(generator, public, response, challenge_scalar, &r1) ||
      !rebuild_commitment(base, shared_secret, response, challenge_scalar, &r2))
    return false;

  const secp256k1_pubkey *points[6] = {public,    base, shared_secret,
                                       generator, &r1,  &r2};
  return challenge_hash(points, message, expected) &&
         memcmp(expected, proof, SCALAR_LEN) == 0;
}
