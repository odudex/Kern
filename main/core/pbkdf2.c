#include "pbkdf2.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include <hal/sha_types.h>
#include <psa/crypto.h>
#include <sha/sha_core.h>
#include <stdbool.h>
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

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
  uint8_t bytes[SHA256_DIGEST_SIZE];
  uint32_t words[SHA256_DIGEST_SIZE / 4];
} sha_state_t;

typedef union {
  uint8_t bytes[SHA256_BLOCK_SIZE];
  uint32_t words[SHA256_BLOCK_SIZE / 4];
} sha_block_t;

/* ------------------------------------------------------------------ */
/*  PSA reference                                                      */
/* ------------------------------------------------------------------ */

int pbkdf2_psa_sha256(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len, uint32_t iterations,
                      uint8_t *key_out, size_t key_len) {
  if (psa_crypto_init() != PSA_SUCCESS)
    return CRYPTO_ERR_INTERNAL;

  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_status_t st =
      psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
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
static void hold_begin(void) {
  esp_sha_acquire_hardware();
  esp_sha_set_mode(SHA2_256);
}

static void hold_end(void) { esp_sha_release_hardware(); }

/*
 * Every message the iteration loop hashes is a 64-byte ipad/opad block plus a
 * 32-byte digest: 96 bytes, 768 bits. Lay the padding down once — the loop only
 * ever rewrites bytes [0..31], because esp_sha_read_digest_state writes exactly
 * eight words and leaves the tail alone.
 */
static void pad_for_96_bytes(sha_block_t *blk) {
  memset(blk->bytes, 0, SHA256_BLOCK_SIZE);
  blk->bytes[SHA256_DIGEST_SIZE] = 0x80;
  blk->bytes[SHA256_BLOCK_SIZE - 2] = 0x03; /* 768 == 0x0300 */
}

static int derive(const uint8_t *password, size_t password_len,
                  const uint8_t *salt, size_t salt_len, uint32_t iterations,
                  uint8_t *key_out, size_t key_len) {
  uint8_t k0[SHA256_BLOCK_SIZE];
  sha_state_t ipad_state, opad_state, accum;
  sha_block_t pad, inner, outer;
  psa_key_derivation_operation_t u1 = PSA_KEY_DERIVATION_OPERATION_INIT;
  int rc = CRYPTO_ERR_INTERNAL;

  /*
   * The HMAC key block. crypto_sha256() is a PSA call, so it has to happen
   * before any hardware is held: the crypto lock is not recursive and a second
   * take from this task would hang with no panic.
   */
  memset(k0, 0, sizeof(k0));
  if (password_len > SHA256_BLOCK_SIZE) {
    if (crypto_sha256(password, password_len, k0) != CRYPTO_OK)
      return CRYPTO_ERR_INTERNAL;
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
  psa_status_t st =
      psa_key_derivation_setup(&u1, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
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
   * is_first_block makes the engine start from the SHA-256 IV. */
  hold_begin();
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    pad.bytes[i] = (uint8_t)(k0[i] ^ 0x36);
  esp_sha_block(SHA2_256, pad.words, true);
  esp_sha_read_digest_state(SHA2_256, ipad_state.words);

  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    pad.bytes[i] = (uint8_t)(k0[i] ^ 0x5c);
  esp_sha_block(SHA2_256, pad.words, true);
  esp_sha_read_digest_state(SHA2_256, opad_state.words);
  hold_end();

  pad_for_96_bytes(&inner);
  pad_for_96_bytes(&outer);

  for (size_t offset = 0; offset < key_len;) {
    st = psa_key_derivation_output_bytes(&u1, accum.bytes, SHA256_DIGEST_SIZE);
    if (st != PSA_SUCCESS)
      goto out;
    memcpy(inner.bytes, accum.bytes, SHA256_DIGEST_SIZE);

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

      hold_begin();
      for (; done < chunk_end; done++) {
        esp_sha_write_digest_state(SHA2_256, ipad_state.words);
        esp_sha_block(SHA2_256, inner.words, false);
        esp_sha_read_digest_state(SHA2_256, outer.words);

        esp_sha_write_digest_state(SHA2_256, opad_state.words);
        esp_sha_block(SHA2_256, outer.words, false);
        esp_sha_read_digest_state(SHA2_256, inner.words);

        for (size_t j = 0; j < SHA256_DIGEST_SIZE / 4; j++)
          accum.words[j] ^= inner.words[j];
      }
      hold_end();
    }

    size_t take = key_len - offset;
    if (take > SHA256_DIGEST_SIZE)
      take = SHA256_DIGEST_SIZE;
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
 */
static bool self_check(void) {
  /* PBKDF2-HMAC-SHA256("password", "salt", c=2, dkLen=32) */
  static const uint8_t expected[SHA256_DIGEST_SIZE] = {
      0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf,
      0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2,
      0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43};
  uint8_t got[sizeof(expected)];

  if (derive((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 2, got,
             sizeof(got)) != CRYPTO_OK)
    return false;
  return memcmp(got, expected, sizeof(expected)) == 0;
}

int pbkdf2_hw_sha256(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                     uint8_t *key_out, size_t key_len) {
  if (!password || !salt || !key_out || iterations == 0 || key_len == 0)
    return CRYPTO_ERR_INVALID_ARG;

  if (!self_check())
    return pbkdf2_psa_sha256(password, password_len, salt, salt_len, iterations,
                             key_out, key_len);

  return derive(password, password_len, salt, salt_len, iterations, key_out,
                key_len);
}
