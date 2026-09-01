/*
 * PBKDF2 tests (core/pbkdf2.c).
 *
 * The accelerated path drives the ESP32-P4 SHA peripheral through six
 * esp_sha_* calls; here they are implemented in software (a plain SHA-256
 * compression with readable and writable state), so the algorithm around
 * them — HMAC midstate reload, XOR accumulation, multi-block output, chunk
 * boundaries and the self-check fallback — is verified against known answers
 * without hardware. The host mbedTLS has no PSA PBKDF2, so the PSA key
 * derivation pbkdf2.c uses for U_1 and for the reference path is provided
 * here too (see stubs/pbkdf2_host_hooks.h), built on mbedTLS HMAC.
 *
 * pbkdf2_selftest.c remains the proof for the real peripheral.
 */

#include "../crypto_utils.h"
#include "../pbkdf2.h"
#include "stubs/pbkdf2_host_hooks.h"
#include <mbedtls/md.h>
#include <sha/sha_core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

static size_t unhex(const char *hex, uint8_t *out) {
  size_t n = strlen(hex) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned b;
    sscanf(hex + 2 * i, "%2x", &b);
    out[i] = (uint8_t)b;
  }
  return n;
}

/* ---------- software SHA-256 engine standing in for the peripheral ----------
 */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(uint32_t s[8], const uint8_t blk[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)blk[4 * i] << 24 | (uint32_t)blk[4 * i + 1] << 16 |
           (uint32_t)blk[4 * i + 2] << 8 | blk[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6],
           h = s[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + K[i] + w[i];
    uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
  s[5] += f;
  s[6] += g;
  s[7] += h;
}

static uint32_t engine_state[8];
static esp_sha_type engine_mode;
static bool engine_held;
static int engine_acquires, engine_blocks;
static bool engine_sabotage; /* corrupt every compression: forces fallback */
static bool engine_mode_violation, engine_hold_violation;

void esp_sha_acquire_hardware(void) {
  if (engine_held)
    engine_hold_violation = true;
  engine_held = true;
  engine_acquires++;
  /* The real acquire pulses a peripheral reset that clears the mode. */
  engine_mode = SHA1;
  memset(engine_state, 0, sizeof(engine_state));
}

void esp_sha_release_hardware(void) {
  if (!engine_held)
    engine_hold_violation = true;
  engine_held = false;
}

void esp_sha_set_mode(esp_sha_type t) { engine_mode = t; }

static void engine_guard(void) {
  if (!engine_held)
    engine_hold_violation = true;
  if (engine_mode != SHA2_256)
    engine_mode_violation = true;
}

void esp_sha_block(esp_sha_type t, const void *data_block, bool is_first) {
  (void)t;
  engine_guard();
  engine_blocks++;
  if (is_first)
    memcpy(engine_state, IV, sizeof(IV));
  sha256_compress(engine_state, data_block);
  if (engine_sabotage)
    engine_state[0] ^= 1;
}

void esp_sha_read_digest_state(esp_sha_type t, void *digest_state) {
  (void)t;
  engine_guard();
  uint8_t *out = digest_state;
  for (int i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(engine_state[i] >> 24);
    out[4 * i + 1] = (uint8_t)(engine_state[i] >> 16);
    out[4 * i + 2] = (uint8_t)(engine_state[i] >> 8);
    out[4 * i + 3] = (uint8_t)engine_state[i];
  }
}

void esp_sha_write_digest_state(esp_sha_type t, void *digest_state) {
  (void)t;
  engine_guard();
  const uint8_t *in = digest_state;
  for (int i = 0; i < 8; i++)
    engine_state[i] = (uint32_t)in[4 * i] << 24 |
                      (uint32_t)in[4 * i + 1] << 16 |
                      (uint32_t)in[4 * i + 2] << 8 | in[4 * i + 3];
}

static void engine_reset(void) {
  engine_held = false;
  engine_acquires = engine_blocks = 0;
  engine_sabotage = false;
  engine_mode_violation = engine_hold_violation = false;
}

/* ---------- host PSA PBKDF2 key derivation ---------- */

static int kdf_output_calls;

/* T_i = F(P, S, c, i): U_1 = HMAC(P, S || INT(i)), U_n = HMAC(P, U_{n-1}) */
static bool pbkdf2_block(const host_kdf_t *op, uint32_t index,
                         uint8_t out[32]) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  uint8_t u[32], msg[256 + 4];
  memcpy(msg, op->salt, op->salt_len);
  msg[op->salt_len] = (uint8_t)(index >> 24);
  msg[op->salt_len + 1] = (uint8_t)(index >> 16);
  msg[op->salt_len + 2] = (uint8_t)(index >> 8);
  msg[op->salt_len + 3] = (uint8_t)index;
  if (mbedtls_md_hmac(md, op->password, op->password_len, msg, op->salt_len + 4,
                      u) != 0)
    return false;
  memcpy(out, u, 32);
  for (uint32_t n = 1; n < op->cost; n++) {
    if (mbedtls_md_hmac(md, op->password, op->password_len, u, 32, u) != 0)
      return false;
    for (int j = 0; j < 32; j++)
      out[j] ^= u[j];
  }
  return true;
}

psa_status_t host_kdf_setup(host_kdf_t *op, psa_algorithm_t alg) {
  memset(op, 0, sizeof(*op));
  op->next_block = 1;
  op->block_used = 32;
  op->alg_ok = alg == HOST_ALG_PBKDF2_HMAC_SHA256;
  return op->alg_ok ? PSA_SUCCESS : PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t host_kdf_input_integer(host_kdf_t *op, int step, uint64_t value) {
  if (step != PSA_KEY_DERIVATION_INPUT_COST || value == 0 ||
      value > 0xFFFFFFFFu)
    return PSA_ERROR_INVALID_ARGUMENT;
  op->cost = (uint32_t)value;
  return PSA_SUCCESS;
}

psa_status_t host_kdf_input_bytes(host_kdf_t *op, int step, const uint8_t *data,
                                  size_t len) {
  if (step == HOST_KDF_INPUT_SALT) {
    if (len > sizeof(op->salt))
      return PSA_ERROR_INSUFFICIENT_MEMORY;
    memcpy(op->salt, data, len);
    op->salt_len = len;
    return PSA_SUCCESS;
  }
  if (step == PSA_KEY_DERIVATION_INPUT_PASSWORD) {
    if (len > sizeof(op->password))
      return PSA_ERROR_INSUFFICIENT_MEMORY;
    memcpy(op->password, data, len);
    op->password_len = len;
    return PSA_SUCCESS;
  }
  return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t host_kdf_output_bytes(host_kdf_t *op, uint8_t *out, size_t len) {
  kdf_output_calls++;
  if (!op->alg_ok || op->cost == 0)
    return PSA_ERROR_BAD_STATE;
  while (len > 0) {
    if (op->block_used == 32) {
      if (!pbkdf2_block(op, op->next_block++, op->block))
        return PSA_ERROR_HARDWARE_FAILURE;
      op->block_used = 0;
    }
    size_t take = 32 - op->block_used;
    if (take > len)
      take = len;
    memcpy(out, op->block + op->block_used, take);
    op->block_used += take;
    out += take;
    len -= take;
  }
  return PSA_SUCCESS;
}

psa_status_t host_kdf_abort(host_kdf_t *op) {
  memset(op, 0, sizeof(*op));
  return PSA_SUCCESS;
}

/* ---------- tests ---------- */

typedef struct {
  const char *name;
  const char *password;
  const char *salt;
  uint32_t iterations;
  size_t key_len;
  const char *expected_hex;
} kat_t;

static const kat_t KATS[] = {
    {"c=1", "password", "salt", 1, 32,
     "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
    {"c=2", "password", "salt", 2, 32,
     "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
    {"c=4096", "password", "salt", 4096, 32,
     "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
    {"RFC 7914 dkLen 64", "passwd", "salt", 1, 64,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
    {"dkLen 40", "passwordPASSWORDpassword",
     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
     "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
     "c635518c7dac47e9"},
    {"KEF shape 100k", "test key", "test ID", 100000, 32,
     "e375234c207fc71d82cc430718cd0dbbf6785a05b6806399e4432d7dd1850abc"},
};

static void test_kats(void) {
  for (size_t i = 0; i < sizeof(KATS) / sizeof(KATS[0]); i++) {
    const kat_t *k = &KATS[i];
    uint8_t expected[64], got[64];
    size_t elen = unhex(k->expected_hex, expected);
    const uint8_t *pw = (const uint8_t *)k->password;
    const uint8_t *salt = (const uint8_t *)k->salt;
    char label[96];

    snprintf(label, sizeof(label), "psa %s", k->name);
    check(label,
          pbkdf2_psa_sha256(pw, strlen(k->password), salt, strlen(k->salt),
                            k->iterations, got, k->key_len) == CRYPTO_OK &&
              elen == k->key_len && memcmp(got, expected, elen) == 0);

    engine_reset();
    snprintf(label, sizeof(label), "hw %s", k->name);
    check(label,
          pbkdf2_hw_sha256(pw, strlen(k->password), salt, strlen(k->salt),
                           k->iterations, got, k->key_len) == CRYPTO_OK &&
              memcmp(got, expected, elen) == 0);
    check("  engine always held and in SHA-256 mode",
          !engine_hold_violation && !engine_mode_violation);
  }
}

static void test_hw_structure(void) {
  uint8_t out[32];
  const uint8_t *pw = (const uint8_t *)"password";
  const uint8_t *salt = (const uint8_t *)"salt";

  engine_reset();
  check("hw c=1 short-circuits to PSA without touching the engine",
        pbkdf2_hw_sha256(pw, 8, salt, 4, 1, out, 32) == CRYPTO_OK &&
            engine_blocks == 2 + 2 * 1 /* self-check only */);

  engine_reset();
  check("hw c=4096 compresses twice per iteration plus midstates",
        pbkdf2_hw_sha256(pw, 8, salt, 4, 4096, out, 32) == CRYPTO_OK &&
            engine_blocks == (2 + 2 * 1) + (2 + 2 * 4095));
  check("hw releases the peripheral between 1024-iteration chunks",
        engine_acquires == (1 + 1) + (1 + 4));

  engine_reset();
  uint8_t out40[40];
  check("hw dkLen 40 runs the loop once per output block",
        pbkdf2_hw_sha256(pw, 8, salt, 4, 10, out40, 40) == CRYPTO_OK &&
            engine_blocks == (2 + 2 * 1) + (2 + 2 * 9 * 2));
}

static bool hw_matches_psa(const uint8_t *pw, size_t pw_len,
                           const uint8_t *salt, size_t salt_len, uint32_t iters,
                           size_t key_len) {
  uint8_t a[128], b[128];
  engine_reset();
  return pbkdf2_psa_sha256(pw, pw_len, salt, salt_len, iters, a, key_len) ==
             CRYPTO_OK &&
         pbkdf2_hw_sha256(pw, pw_len, salt, salt_len, iters, b, key_len) ==
             CRYPTO_OK &&
         memcmp(a, b, key_len) == 0 && !engine_hold_violation &&
         !engine_mode_violation;
}

static void test_differential(void) {
  uint8_t pw[200], salt[255];
  for (size_t i = 0; i < sizeof(pw); i++)
    pw[i] = (uint8_t)(i * 31 + 5);
  for (size_t i = 0; i < sizeof(salt); i++)
    salt[i] = (uint8_t)(i * 17 + 3);

  const size_t pw_lens[] = {0, 1, 63, 64, 65, 200};
  bool ok = true;
  for (size_t i = 0; i < 6 && ok; i++)
    ok = hw_matches_psa(pw, pw_lens[i], salt, 16, 37, 32);
  check("differential: password lengths around the HMAC block", ok);

  const size_t salt_lens[] = {0, 1, 55, 56, 64, 255};
  ok = true;
  for (size_t i = 0; i < 6 && ok; i++)
    ok = hw_matches_psa(pw, 8, salt, salt_lens[i], 37, 32);
  check("differential: salt lengths around the SHA block", ok);

  const uint32_t iters[] = {2, 3, 1023, 1024, 1025, 2047, 2048, 2049, 3000};
  ok = true;
  for (size_t i = 0; i < 9 && ok; i++)
    ok = hw_matches_psa(pw, 8, salt, 4, iters[i], 32);
  check("differential: iteration counts around the chunk boundary", ok);

  const size_t key_lens[] = {1, 31, 32, 33, 63, 64, 65, 96, 128};
  ok = true;
  for (size_t i = 0; i < 9 && ok; i++)
    ok = hw_matches_psa(pw, 8, salt, 4, 5, key_lens[i]);
  check("differential: output lengths across block boundaries", ok);
}

static void test_fallback_and_args(void) {
  uint8_t out[32], expected[32];
  const uint8_t *pw = (const uint8_t *)"password";
  const uint8_t *salt = (const uint8_t *)"salt";
  unhex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        expected);

  engine_reset();
  engine_sabotage = true;
  kdf_output_calls = 0;
  check("faulty engine fails the self-check and falls back to PSA",
        pbkdf2_hw_sha256(pw, 8, salt, 4, 2, out, 32) == CRYPTO_OK &&
            memcmp(out, expected, 32) == 0);
  check("fallback ran the PSA reference", kdf_output_calls >= 2);
  check("fallback released the peripheral", !engine_held);

  check("hw rejects invalid args",
        pbkdf2_hw_sha256(NULL, 8, salt, 4, 2, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            pbkdf2_hw_sha256(pw, 8, NULL, 4, 2, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            pbkdf2_hw_sha256(pw, 8, salt, 4, 0, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            pbkdf2_hw_sha256(pw, 8, salt, 4, 2, out, 0) ==
                CRYPTO_ERR_INVALID_ARG &&
            pbkdf2_hw_sha256(pw, 8, salt, 4, 2, NULL, 32) ==
                CRYPTO_ERR_INVALID_ARG);
}

int main(void) {
  printf("=== pbkdf2 tests ===\n\n");
  test_kats();
  test_hw_structure();
  test_differential();
  test_fallback_and_args();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
