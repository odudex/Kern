#include "pbkdf2.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include <hal/sha_types.h>
#include <psa/crypto.h>
#include <sha/sha_core.h>
#include <stdbool.h>
#include <string.h>

#define MAX_BLOCK_SIZE 128
#define MAX_DIGEST_SIZE 64

/*
 * Iterations per hold. While the peripheral is held nothing else on the device
 * can use SHA, AES or the crypto DMA, so the loop is broken into chunks and the
 * hardware handed back between them. At the default this is about 6.6 ms per
 * hold — under one 60 Hz frame — and the reacquires cost roughly 0.3% of the
 * derivation. The chunk boundary is also where a taskYIELD() would go if one is
 * ever wanted; FreeRTOS already preempts on every tick, so only the lock outage
 * needs bounding.
 */
#ifdef CONFIG_KERN_PBKDF2_HW_SHA_CHUNK
#define CHUNK_ITERS CONFIG_KERN_PBKDF2_HW_SHA_CHUNK
#else
#define CHUNK_ITERS 1024
#endif

/* Both low-level SHA calls cast to uint32_t*, so these must stay word-aligned
 */
typedef union {
  uint8_t bytes[MAX_DIGEST_SIZE];
  uint32_t words[MAX_DIGEST_SIZE / 4];
} sha_state_t;

typedef union {
  uint8_t bytes[MAX_BLOCK_SIZE];
  uint32_t words[MAX_BLOCK_SIZE / 4];
} sha_block_t;

typedef struct {
  esp_sha_type mode;
  psa_algorithm_t hash;
  size_t block_size;
  size_t digest_size;
} sha_variant_t;

static const sha_variant_t SHA256_VARIANT = {SHA2_256, PSA_ALG_SHA_256, 64, 32};
static const sha_variant_t SHA512_VARIANT = {SHA2_512, PSA_ALG_SHA_512, 128,
                                             64};

/* ------------------------------------------------------------------ */
/*  PSA reference                                                      */
/* ------------------------------------------------------------------ */

static int psa_reference(const sha_variant_t *v, const uint8_t *password,
                         size_t password_len, const uint8_t *salt,
                         size_t salt_len, uint32_t iterations, uint8_t *key_out,
                         size_t key_len) {
  if (psa_crypto_init() != PSA_SUCCESS)
    return CRYPTO_ERR_INTERNAL;

  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(v->hash));
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                          iterations);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, salt_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        password, password_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_output_bytes(&op, key_out, key_len);
  }
  psa_key_derivation_abort(&op);
  return (st == PSA_SUCCESS) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

int pbkdf2_psa_sha256(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len, uint32_t iterations,
                      uint8_t *key_out, size_t key_len) {
  return psa_reference(&SHA256_VARIANT, password, password_len, salt, salt_len,
                       iterations, key_out, key_len);
}

int pbkdf2_psa_sha512(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len, uint32_t iterations,
                      uint8_t *key_out, size_t key_len) {
  return psa_reference(&SHA512_VARIANT, password, password_len, salt, salt_len,
                       iterations, key_out, key_len);
}

/* ------------------------------------------------------------------ */
/*  Accelerated path                                                   */
/* ------------------------------------------------------------------ */

/*
 * Reacquiring pulses a full peripheral reset, clobbering SHA_MODE_REG along
 * with H_MEM and M_MEM, so the mode has to be reasserted every time. H_MEM and
 * M_MEM are reloaded by the loop itself. Keeping the two calls in one helper
 * is what stops them drifting apart — a missed set_mode leaves the engine in
 * SHA-1 and silently produces wrong keys.
 */
static void hold_begin(const sha_variant_t *v) {
  esp_sha_acquire_hardware();
  esp_sha_set_mode(v->mode);
}

static void hold_end(void) { esp_sha_release_hardware(); }

/*
 * Every message the iteration loop hashes is an ipad/opad block plus a digest:
 * 96 bytes (768 bits) for SHA-256, 192 bytes (1536 bits) for SHA-512. Lay the
 * padding down once — the loop only ever rewrites the digest bytes, because
 * esp_sha_read_digest_state writes exactly one digest and leaves the tail
 * alone.
 */
static void pad_hmac_message(const sha_variant_t *v, sha_block_t *blk) {
  size_t bits = (v->block_size + v->digest_size) * 8;
  memset(blk->bytes, 0, sizeof(blk->bytes));
  blk->bytes[v->digest_size] = 0x80;
  blk->bytes[v->block_size - 2] = (uint8_t)(bits >> 8);
  blk->bytes[v->block_size - 1] = (uint8_t)bits;
}

static int derive(const sha_variant_t *v, const uint8_t *password,
                  size_t password_len, const uint8_t *salt, size_t salt_len,
                  uint32_t iterations, uint8_t *key_out, size_t key_len) {
  uint8_t k0[MAX_BLOCK_SIZE];
  sha_state_t ipad_state, opad_state, accum;
  sha_block_t pad, inner, outer;
  psa_key_derivation_operation_t u1 = PSA_KEY_DERIVATION_OPERATION_INIT;
  int rc = CRYPTO_ERR_INTERNAL;

  /*
   * The HMAC key block. Hashing a long key is a PSA call, so it has to happen
   * before any hardware is held: the crypto lock is not recursive and a second
   * take from this task would hang with no panic.
   */
  if (psa_crypto_init() != PSA_SUCCESS)
    return CRYPTO_ERR_INTERNAL;
  memset(k0, 0, sizeof(k0));
  if (password_len > v->block_size) {
    size_t hashed_len = 0;
    if (psa_hash_compute(v->hash, password, password_len, k0, v->digest_size,
                         &hashed_len) != PSA_SUCCESS ||
        hashed_len != v->digest_size) {
      secure_memzero(k0, sizeof(k0));
      return CRYPTO_ERR_INTERNAL;
    }
  } else {
    memcpy(k0, password, password_len);
  }

  /*
   * U_1 comes from PSA at cost=1. Everything awkward about PBKDF2 — the
   * variable-length salt, the big-endian block counter, the multi-block
   * padding — lives in U_1, and it is one iteration out of a hundred thousand.
   * What is left for the accelerator is the part that is uniform: a fixed
   * 96-byte message, twice per iteration, forever.
   */
  psa_status_t st = psa_key_derivation_setup(&u1, PSA_ALG_PBKDF2_HMAC(v->hash));
  if (st == PSA_SUCCESS)
    st =
        psa_key_derivation_input_integer(&u1, PSA_KEY_DERIVATION_INPUT_COST, 1);
  if (st == PSA_SUCCESS)
    st = psa_key_derivation_input_bytes(&u1, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, salt_len);
  if (st == PSA_SUCCESS)
    st = psa_key_derivation_input_bytes(&u1, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        password, password_len);
  if (st != PSA_SUCCESS)
    goto out;

  if (iterations == 1) {
    st = psa_key_derivation_output_bytes(&u1, key_out, key_len);
    rc = (st == PSA_SUCCESS) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
    goto out;
  }

  /* The two midstates the loop reloads instead of recomputing. Passing
   * is_first_block makes the engine start from the hash's IV. */
  hold_begin(v);
  for (size_t i = 0; i < v->block_size; i++)
    pad.bytes[i] = (uint8_t)(k0[i] ^ 0x36);
  esp_sha_block(v->mode, pad.words, true);
  esp_sha_read_digest_state(v->mode, ipad_state.words);

  for (size_t i = 0; i < v->block_size; i++)
    pad.bytes[i] = (uint8_t)(k0[i] ^ 0x5c);
  esp_sha_block(v->mode, pad.words, true);
  esp_sha_read_digest_state(v->mode, opad_state.words);
  hold_end();

  pad_hmac_message(v, &inner);
  pad_hmac_message(v, &outer);

  for (size_t offset = 0; offset < key_len;) {
    st = psa_key_derivation_output_bytes(&u1, accum.bytes, v->digest_size);
    if (st != PSA_SUCCESS)
      goto out;
    memcpy(inner.bytes, accum.bytes, v->digest_size);

    /*
     * U_n = HMAC(K, U_{n-1}), accumulated by XOR. Two block compressions per
     * iteration and no copies: each digest is read straight into the message
     * block the next compression consumes, whose padding tail is already set.
     *
     * Nothing in this loop may call PSA, mbedTLS, AES or HMAC — they all take
     * the same non-recursive lock this hold owns.
     */
    uint32_t done = 1;
    while (done < iterations) {
      uint32_t chunk_end = done + CHUNK_ITERS;
      if (chunk_end > iterations || chunk_end < done)
        chunk_end = iterations;

      hold_begin(v);
      for (; done < chunk_end; done++) {
        esp_sha_write_digest_state(v->mode, ipad_state.words);
        esp_sha_block(v->mode, inner.words, false);
        esp_sha_read_digest_state(v->mode, outer.words);

        esp_sha_write_digest_state(v->mode, opad_state.words);
        esp_sha_block(v->mode, outer.words, false);
        esp_sha_read_digest_state(v->mode, inner.words);

        for (size_t j = 0; j < v->digest_size / 4; j++)
          accum.words[j] ^= inner.words[j];
      }
      hold_end();
    }

    size_t take = key_len - offset;
    if (take > v->digest_size)
      take = v->digest_size;
    memcpy(key_out + offset, accum.bytes, take);
    offset += take;
  }
  rc = CRYPTO_OK;

out:
  psa_key_derivation_abort(&u1);
  secure_memzero(k0, sizeof(k0));
  secure_memzero(&pad, sizeof(pad));
  secure_memzero(&ipad_state, sizeof(ipad_state));
  secure_memzero(&opad_state, sizeof(opad_state));
  secure_memzero(&accum, sizeof(accum));
  secure_memzero(&inner, sizeof(inner));
  secure_memzero(&outer, sizeof(outer));
  return rc;
}

/*
 * A wrong derivation here would be silent and catastrophic: pin_verify() counts
 * a failed unlock before it derives and wipes at the threshold, so a byte-wrong
 * key would wipe every device that has a PIN. Run one known-answer vector
 * through this exact code path first and fall back to PSA if it disagrees,
 * turning a correctness failure into a performance regression.
 *
 * Checked per call rather than cached: no init order to get right, no
 * thread-safety question, and at roughly 175 us against a 640,000 us derivation
 * it is beneath measurement noise — 0.3% even at KEF's 10,000-iteration floor.
 * The same holds for a BIP39 seed: one vector costs about what two of its
 * 2048 iterations do.
 */
static bool self_check(const sha_variant_t *v) {
  /* PBKDF2-HMAC-SHA256("password", "salt", c=2, dkLen=32) */
  static const uint8_t expected_sha256[32] = {
      0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf,
      0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2,
      0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43};
  /* PBKDF2-HMAC-SHA512("password", "salt", c=2, dkLen=64) */
  static const uint8_t expected_sha512[64] = {
      0xe1, 0xd9, 0xc1, 0x6a, 0xa6, 0x81, 0x70, 0x8a, 0x45, 0xf5, 0xc7,
      0xc4, 0xe2, 0x15, 0xce, 0xb6, 0x6e, 0x01, 0x1a, 0x2e, 0x9f, 0x00,
      0x40, 0x71, 0x3f, 0x18, 0xae, 0xfd, 0xb8, 0x66, 0xd5, 0x3c, 0xf7,
      0x6c, 0xab, 0x28, 0x68, 0xa3, 0x9b, 0x9f, 0x78, 0x40, 0xed, 0xce,
      0x4f, 0xef, 0x5a, 0x82, 0xbe, 0x67, 0x33, 0x5c, 0x77, 0xa6, 0x06,
      0x8e, 0x04, 0x11, 0x27, 0x54, 0xf2, 0x7c, 0xcf, 0x4e};
  const uint8_t *expected =
      v == &SHA512_VARIANT ? expected_sha512 : expected_sha256;
  uint8_t got[MAX_DIGEST_SIZE];

  if (derive(v, (const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 2,
             got, v->digest_size) != CRYPTO_OK)
    return false;
  return memcmp(got, expected, v->digest_size) == 0;
}

static int accelerated(const sha_variant_t *v, const uint8_t *password,
                       size_t password_len, const uint8_t *salt,
                       size_t salt_len, uint32_t iterations, uint8_t *key_out,
                       size_t key_len) {
  if (!password || !salt || !key_out || iterations == 0 || key_len == 0)
    return CRYPTO_ERR_INVALID_ARG;

  if (!self_check(v))
    return psa_reference(v, password, password_len, salt, salt_len, iterations,
                         key_out, key_len);

  return derive(v, password, password_len, salt, salt_len, iterations, key_out,
                key_len);
}

int pbkdf2_hw_sha256(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                     uint8_t *key_out, size_t key_len) {
  return accelerated(&SHA256_VARIANT, password, password_len, salt, salt_len,
                     iterations, key_out, key_len);
}

int pbkdf2_hw_sha512(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                     uint8_t *key_out, size_t key_len) {
  return accelerated(&SHA512_VARIANT, password, password_len, salt, salt_len,
                     iterations, key_out, key_len);
}
