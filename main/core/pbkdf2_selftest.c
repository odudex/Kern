/*
 * On-device check and timing for the two PBKDF2 implementations.
 *
 * The host test suite cannot cover any of this: the simulator and
 * main/core/test both build crypto_utils.c with SIMULATOR, which routes
 * PBKDF2 through mbedTLS's pkcs5 API and never touches pbkdf2.c. The
 * accelerated path is only exercised on real silicon, so this is where it
 * gets proven.
 *
 * Three stages, in order, because timing a wrong derivation is worthless:
 *   1. known-answer vectors, both implementations
 *   2. a differential sweep of hardware against PSA across every boundary
 *      the accelerated path has
 *   3. timing at the shapes KEF and PIN actually use
 *
 * Development only; enable with CONFIG_KERN_PBKDF2_SELFTEST.
 */

#include "sdkconfig.h"

#ifdef CONFIG_KERN_PBKDF2_SELFTEST

#include "crypto_utils.h"
#include "pbkdf2.h"
#include <esp_timer.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MAX_DK 64
#define MAX_SALT 255
#define MAX_PW 200

static int checks_run;
static int checks_failed;

static void report(const char *what, bool ok) {
  checks_run++;
  if (!ok)
    checks_failed++;
  printf("PBKDF2 %-58s %s\n", what, ok ? "PASS" : "FAIL");
}

static size_t unhex(const char *hex, uint8_t *out) {
  size_t n = strlen(hex) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned byte;
    sscanf(hex + 2 * i, "%2x", &byte);
    out[i] = (uint8_t)byte;
  }
  return n;
}

/* ---------- stage 1: known-answer vectors ---------- */

typedef struct {
  const char *name;
  const char *password;
  const char *salt;
  uint32_t iterations;
  size_t key_len;
  const char *expected_hex;
} kat_t;

/*
 * The c=1/dkLen=64 case is RFC 7914 section 11; the rest are the widely
 * published PBKDF2-HMAC-SHA256 vectors. All were regenerated from Python's
 * hashlib before being pasted here.
 */
static const kat_t KATS[] = {
    {"KAT c=1", "password", "salt", 1, 32,
     "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
    {"KAT c=2", "password", "salt", 2, 32,
     "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
    {"KAT c=4096", "password", "salt", 4096, 32,
     "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
    {"KAT RFC 7914, dkLen 64", "passwd", "salt", 1, 64,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
    {"KAT dkLen 40", "passwordPASSWORDpassword",
     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
     "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
     "c635518c7dac47e9"},
    {"KAT KEF shape, 100k", "test key", "test ID", 100000, 32,
     "e375234c207fc71d82cc430718cd0dbbf6785a05b6806399e4432d7dd1850abc"},
};

static void run_kats(void) {
  for (size_t i = 0; i < sizeof(KATS) / sizeof(KATS[0]); i++) {
    const kat_t *k = &KATS[i];
    uint8_t expected[MAX_DK], got[MAX_DK];
    size_t expected_len = unhex(k->expected_hex, expected);
    char label[80];

    const uint8_t *pw = (const uint8_t *)k->password;
    const uint8_t *salt = (const uint8_t *)k->salt;
    size_t pw_len = strlen(k->password), salt_len = strlen(k->salt);

    snprintf(label, sizeof(label), "%s (psa)", k->name);
    report(label, pbkdf2_psa_sha256(pw, pw_len, salt, salt_len, k->iterations,
                                    got, k->key_len) == CRYPTO_OK &&
                      expected_len == k->key_len &&
                      memcmp(got, expected, k->key_len) == 0);

    snprintf(label, sizeof(label), "%s (hw)", k->name);
    report(label, pbkdf2_hw_sha256(pw, pw_len, salt, salt_len, k->iterations,
                                   got, k->key_len) == CRYPTO_OK &&
                      memcmp(got, expected, k->key_len) == 0);
  }
}

/* ---------- stage 2: differential sweep ---------- */

static uint8_t sweep_pw[MAX_PW];
static uint8_t sweep_salt[MAX_SALT];

static bool same_output(size_t pw_len, size_t salt_len, uint32_t iterations,
                        size_t key_len) {
  uint8_t from_psa[MAX_DK], from_hw[MAX_DK];

  if (pbkdf2_psa_sha256(sweep_pw, pw_len, sweep_salt, salt_len, iterations,
                        from_psa, key_len) != CRYPTO_OK)
    return false;
  if (pbkdf2_hw_sha256(sweep_pw, pw_len, sweep_salt, salt_len, iterations,
                       from_hw, key_len) != CRYPTO_OK)
    return false;
  return memcmp(from_psa, from_hw, key_len) == 0;
}

static void sweep_axis(const char *axis, const size_t *values, size_t count,
                       size_t pw_len, size_t salt_len, uint32_t iterations,
                       size_t key_len, int which) {
  bool ok = true;
  for (size_t i = 0; i < count; i++) {
    size_t p = pw_len, s = salt_len, k = key_len;
    uint32_t it = iterations;
    switch (which) {
    case 0:
      p = values[i];
      break;
    case 1:
      s = values[i];
      break;
    case 2:
      it = (uint32_t)values[i];
      break;
    default:
      k = values[i];
      break;
    }
    if (!same_output(p, s, it, k)) {
      printf("PBKDF2   mismatch at %s=%u\n", axis, (unsigned)values[i]);
      ok = false;
    }
  }
  report(axis, ok);
}

static void run_sweep(void) {
  for (size_t i = 0; i < sizeof(sweep_pw); i++)
    sweep_pw[i] = (uint8_t)(i * 7 + 1);
  for (size_t i = 0; i < sizeof(sweep_salt); i++)
    sweep_salt[i] = (uint8_t)(i * 13 + 5);

  /* 64 is where the HMAC key switches from zero-padded to hashed */
  static const size_t pw_lens[] = {1, 31, 63, 64, 65, 100, 200};
  /* salt || 4-byte counter crossing SHA-256 block and padding boundaries;
   * 255 is KEF_MAX_ID_LEN */
  static const size_t salt_lens[] = {1, 32, 51, 52, 55, 56, 59, 60, 64, 255};
  /* 1 short-circuits to PSA; 1024 is the default chunk length */
  static const size_t iter_counts[] = {1, 2, 3, 1023, 1024, 1025, 2049};
  /* multiple output blocks and final-block truncation */
  static const size_t key_lens[] = {1, 31, 32, 33, 64};

  sweep_axis("sweep password_len", pw_lens,
             sizeof(pw_lens) / sizeof(pw_lens[0]), 0, 16, 37, 32, 0);
  sweep_axis("sweep salt_len", salt_lens,
             sizeof(salt_lens) / sizeof(salt_lens[0]), 16, 0, 37, 32, 1);
  sweep_axis("sweep iterations", iter_counts,
             sizeof(iter_counts) / sizeof(iter_counts[0]), 16, 37, 0, 32, 2);
  sweep_axis("sweep key_len", key_lens, sizeof(key_lens) / sizeof(key_lens[0]),
             16, 37, 37, 0, 3);
}

/* ---------- stage 3: timing ---------- */

static void time_shape(const char *name, size_t pw_len, size_t salt_len,
                       uint32_t iterations) {
  uint8_t key[32];
  int64_t t0, psa_us, hw_us;

  t0 = esp_timer_get_time();
  if (pbkdf2_psa_sha256(sweep_pw, pw_len, sweep_salt, salt_len, iterations, key,
                        sizeof(key)) != CRYPTO_OK)
    return;
  psa_us = esp_timer_get_time() - t0;

  t0 = esp_timer_get_time();
  if (pbkdf2_hw_sha256(sweep_pw, pw_len, sweep_salt, salt_len, iterations, key,
                       sizeof(key)) != CRYPTO_OK)
    return;
  hw_us = esp_timer_get_time() - t0;

  printf("PBKDF2 %-20s psa %8lld us   hw %8lld us   %lld.%02llux\n", name,
         psa_us, hw_us, psa_us / hw_us, (psa_us * 100 / hw_us) % 100);
}

void pbkdf2_selftest(void) {
  printf("\n===== PBKDF2 BEGIN =====\n");
  checks_run = 0;
  checks_failed = 0;

  run_kats();
  run_sweep();

  if (checks_failed) {
    printf("PBKDF2 %d/%d checks failed -- timings withheld\n", checks_failed,
           checks_run);
  } else {
    printf("PBKDF2 %d checks passed\n", checks_run);
    time_shape("KEF (100k)", 8, 7, 100000);
    time_shape("PIN (100k)", 6, 32, 100000);
    time_shape("KEF floor (10k)", 8, 7, 10000);
  }
  printf("===== PBKDF2 END =====\n\n");
}

#endif /* CONFIG_KERN_PBKDF2_SELFTEST */
