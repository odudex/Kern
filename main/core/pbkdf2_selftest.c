/*
 * On-device check and timing for the two PBKDF2 implementations.
 *
 * The host builds cannot cover any of this: they have no SHA accelerator,
 * and the simulator derives through mbedTLS's pkcs5 API instead of pbkdf2.c.
 * The accelerated path is only exercised on real silicon, so this is where it
 * gets proven.
 *
 * Three stages, in order, because timing a wrong derivation is worthless:
 *   1. known-answer vectors, both implementations
 *   2. a differential sweep of hardware against PSA across every boundary
 *      the accelerated path has
 *   3. timing at the shapes KEF, PIN and BIP39 seeds actually use
 * Each runs for SHA-256 and SHA-512.
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

/* SHA-512: RFC 6070's inputs, and the BIP39 TREZOR vectors for a 93-byte
 * mnemonic and a 164-byte one, whose HMAC key is hashed first. Regenerated
 * from Python's hashlib. */
static const kat_t KATS_512[] = {
    {"KAT c=1", "password", "salt", 1, 64,
     "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
     "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"},
    {"KAT c=2", "password", "salt", 2, 64,
     "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
     "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"},
    {"KAT c=4096", "password", "salt", 4096, 64,
     "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
     "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"},
    {"KAT dkLen 40", "passwordPASSWORDpassword",
     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
     "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71"
     "115b59f9e60cd953"},
    {"KAT BIP39 12 words",
     "abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon about",
     "mnemonicTREZOR", 2048, 64,
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
     "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
    {"KAT BIP39 24 words",
     "letter advice cage absurd amount doctor acoustic avoid letter advice "
     "cage absurd amount doctor acoustic avoid letter advice cage absurd "
     "amount doctor acoustic bless",
     "mnemonicTREZOR", 2048, 64,
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
     "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"},
};

typedef int (*pbkdf2_fn)(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t *key_out, size_t key_len);

typedef struct {
  const char *name;
  pbkdf2_fn psa;
  pbkdf2_fn hw;
  const kat_t *kats;
  size_t num_kats;
  const size_t *pw_lens, *salt_lens, *key_lens;
  size_t num_pw_lens, num_salt_lens, num_key_lens;
} variant_t;

static void run_kats(const variant_t *v) {
  for (size_t i = 0; i < v->num_kats; i++) {
    const kat_t *k = &v->kats[i];
    uint8_t expected[MAX_DK], got[MAX_DK];
    size_t expected_len = unhex(k->expected_hex, expected);
    char label[80];

    const uint8_t *pw = (const uint8_t *)k->password;
    const uint8_t *salt = (const uint8_t *)k->salt;
    size_t pw_len = strlen(k->password), salt_len = strlen(k->salt);

    snprintf(label, sizeof(label), "%s %s (psa)", v->name, k->name);
    report(label, v->psa(pw, pw_len, salt, salt_len, k->iterations, got,
                         k->key_len) == CRYPTO_OK &&
                      expected_len == k->key_len &&
                      memcmp(got, expected, k->key_len) == 0);

    snprintf(label, sizeof(label), "%s %s (hw)", v->name, k->name);
    report(label, v->hw(pw, pw_len, salt, salt_len, k->iterations, got,
                        k->key_len) == CRYPTO_OK &&
                      memcmp(got, expected, k->key_len) == 0);
  }
}

/* ---------- stage 2: differential sweep ---------- */

static uint8_t sweep_pw[MAX_PW];
static uint8_t sweep_salt[MAX_SALT];

static bool same_output(const variant_t *v, size_t pw_len, size_t salt_len,
                        uint32_t iterations, size_t key_len) {
  uint8_t from_psa[MAX_DK], from_hw[MAX_DK];

  if (v->psa(sweep_pw, pw_len, sweep_salt, salt_len, iterations, from_psa,
             key_len) != CRYPTO_OK)
    return false;
  if (v->hw(sweep_pw, pw_len, sweep_salt, salt_len, iterations, from_hw,
            key_len) != CRYPTO_OK)
    return false;
  return memcmp(from_psa, from_hw, key_len) == 0;
}

static void sweep_axis(const variant_t *v, const char *axis,
                       const size_t *values, size_t count, size_t pw_len,
                       size_t salt_len, uint32_t iterations, size_t key_len,
                       int which) {
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
    if (!same_output(v, p, s, it, k)) {
      printf("PBKDF2   mismatch at %s=%u\n", axis, (unsigned)values[i]);
      ok = false;
    }
  }
  char label[64];
  snprintf(label, sizeof(label), "%s %s", v->name, axis);
  report(label, ok);
}

static void run_sweep(const variant_t *v) {
  for (size_t i = 0; i < sizeof(sweep_pw); i++)
    sweep_pw[i] = (uint8_t)(i * 7 + 1);
  for (size_t i = 0; i < sizeof(sweep_salt); i++)
    sweep_salt[i] = (uint8_t)(i * 13 + 5);

  /* 1 short-circuits to PSA; 1024 is the default chunk length */
  static const size_t iter_counts[] = {1, 2, 3, 1023, 1024, 1025, 2049};
  size_t key_len = v->key_lens[v->num_key_lens - 1];

  sweep_axis(v, "sweep password_len", v->pw_lens, v->num_pw_lens, 0, 16, 37,
             key_len, 0);
  sweep_axis(v, "sweep salt_len", v->salt_lens, v->num_salt_lens, 16, 0, 37,
             key_len, 1);
  sweep_axis(v, "sweep iterations", iter_counts,
             sizeof(iter_counts) / sizeof(iter_counts[0]), 16, 37, 0, key_len,
             2);
  sweep_axis(v, "sweep key_len", v->key_lens, v->num_key_lens, 16, 37, 37, 0,
             3);
}

/* SHA-256: 64 is where the HMAC key switches from zero-padded to hashed; salt
 * || 4-byte counter crosses the block and padding boundaries; 255 is
 * KEF_MAX_ID_LEN; multiple output blocks and final-block truncation. */
static const size_t PW_LENS_256[] = {1, 31, 63, 64, 65, 100, 200};
static const size_t SALT_LENS_256[] = {1, 32, 51, 52, 55, 56, 59, 60, 64, 255};
static const size_t KEY_LENS_256[] = {1, 31, 32, 33, 64};
/* SHA-512: the same boundaries for a 128-byte block with a 16-byte length. */
static const size_t PW_LENS_512[] = {1, 63, 127, 128, 129, 200};
static const size_t SALT_LENS_512[] = {1, 64, 107, 108, 111, 112, 128, 255};
static const size_t KEY_LENS_512[] = {1, 63, 64};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const variant_t SHA256 = {.name = "sha256",
                                 .psa = pbkdf2_psa_sha256,
                                 .hw = pbkdf2_hw_sha256,
                                 .kats = KATS,
                                 .num_kats = COUNT(KATS),
                                 .pw_lens = PW_LENS_256,
                                 .salt_lens = SALT_LENS_256,
                                 .key_lens = KEY_LENS_256,
                                 .num_pw_lens = COUNT(PW_LENS_256),
                                 .num_salt_lens = COUNT(SALT_LENS_256),
                                 .num_key_lens = COUNT(KEY_LENS_256)};
static const variant_t SHA512 = {.name = "sha512",
                                 .psa = pbkdf2_psa_sha512,
                                 .hw = pbkdf2_hw_sha512,
                                 .kats = KATS_512,
                                 .num_kats = COUNT(KATS_512),
                                 .pw_lens = PW_LENS_512,
                                 .salt_lens = SALT_LENS_512,
                                 .key_lens = KEY_LENS_512,
                                 .num_pw_lens = COUNT(PW_LENS_512),
                                 .num_salt_lens = COUNT(SALT_LENS_512),
                                 .num_key_lens = COUNT(KEY_LENS_512)};

/* ---------- stage 3: timing ---------- */

static void time_shape(const variant_t *v, const char *name, size_t pw_len,
                       size_t salt_len, uint32_t iterations, size_t key_len) {
  uint8_t key[MAX_DK];
  int64_t t0, psa_us, hw_us;

  t0 = esp_timer_get_time();
  if (v->psa(sweep_pw, pw_len, sweep_salt, salt_len, iterations, key,
             key_len) != CRYPTO_OK)
    return;
  psa_us = esp_timer_get_time() - t0;

  t0 = esp_timer_get_time();
  if (v->hw(sweep_pw, pw_len, sweep_salt, salt_len, iterations, key, key_len) !=
      CRYPTO_OK)
    return;
  hw_us = esp_timer_get_time() - t0;

  printf("PBKDF2 %-20s psa %8lld us   hw %8lld us   %lld.%02llux\n", name,
         psa_us, hw_us, psa_us / hw_us, (psa_us * 100 / hw_us) % 100);
}

void pbkdf2_selftest(void) {
  printf("\n===== PBKDF2 BEGIN =====\n");
  checks_run = 0;
  checks_failed = 0;

  run_kats(&SHA256);
  run_sweep(&SHA256);
  run_kats(&SHA512);
  run_sweep(&SHA512);

  if (checks_failed) {
    printf("PBKDF2 %d/%d checks failed -- timings withheld\n", checks_failed,
           checks_run);
  } else {
    printf("PBKDF2 %d checks passed\n", checks_run);
    time_shape(&SHA256, "KEF (100k)", 8, 7, 100000, 32);
    time_shape(&SHA256, "PIN (100k)", 6, 32, 100000, 32);
    time_shape(&SHA256, "KEF floor (10k)", 8, 7, 10000, 32);
    time_shape(&SHA512, "BIP39 12 words", 93, 8, 2048, 64);
    time_shape(&SHA512, "BIP39 24 words", 164, 8, 2048, 64);
  }
  printf("===== PBKDF2 END =====\n\n");
}

#endif /* CONFIG_KERN_PBKDF2_SELFTEST */
