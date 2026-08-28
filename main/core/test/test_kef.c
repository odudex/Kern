/*
 * KEF format tests.
 *
 * Two kinds of coverage:
 *
 *  1. Cross-implementation vectors.  Versions 0, 1, 5, 10, 15 and 20 are the
 *     envelopes Krux's own suite pins down (tests/test_encryption.py:
 *     TEST_KEY / TEST_MNEMONIC_ID / *_ENCRYPTED_QR).  The remaining six were
 *     produced by an independent Python reference (hashlib + cryptography +
 *     zlib) that reproduces all six Krux vectors byte-for-byte, so they
 *     exercise the same format contract rather than Kern's own output.
 *
 *  2. Round-trips and negative cases over every version, including the
 *     NUL-suffix plaintexts Krux keeps for the padding-recovery path.
 *
 * Compressed versions are decrypt-only as vectors: raw-deflate output depends
 * on the encoder's level, so only the inflate side is contract-bound.
 */

#include "../base43.h"
#include "../kef.h"
#include <mbedtls/base64.h>
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

/* ---------- helpers ---------- */

static size_t unhex(const char *hex, uint8_t *out, size_t out_size) {
  size_t n = strlen(hex) / 2;
  if (n > out_size)
    return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned byte;
    sscanf(hex + 2 * i, "%2x", &byte);
    out[i] = (uint8_t)byte;
  }
  return n;
}

#define TEST_ID ((const uint8_t *)"test ID")
#define TEST_ID_LEN 7
#define TEST_KEY ((const uint8_t *)"test key")
#define TEST_KEY_LEN 8
#define TEST_ITERATIONS 100000

/* bip39 entropy of "crush inherit small egg include title slogan mom remain
 * blouse boost bonus" — the plaintext behind most Krux vectors */
static const char ENTROPY16_HEX[] = "350e7b31a36727c5f2fc76b58304668c";
static const char CTR_ENTROPY_HEX[] =
    "ec54ea346caa1ed06cb35c96c4ef23228a26a2e0996c71d0608ec2ba49ce2316";

/* The descriptor used as the compressed-version plaintext */
static const char TEST_DESCRIPTOR[] =
    "wsh(sortedmulti(2,[73c5da0a/48h/1h/0h/2h]xpub6E64WfdQwBGz85XhbZryr9gUWUPB"
    "eTZSBQWWc3aiKZrufYWNYyRSHZjHct9zHTP1TQzpJqM7rNRoRrxFWo64rcVAzpHoq1JhGTHb7"
    "RqA/<0;1>/*,[6ba6cfd0/48h/1h/0h/2h]xpub6DwQ4gBCmJZM3TaKogz1XEzcURTDHB8Q1s"
    "HqR4dCUUcVQ3sBRt1KQqCFdBQwbLCzbLbgpTkTLDPKPU2yTFQnDXhSTPRB25V1JeXcVsbT8Sr"
    "/<0;1>/*))#dvfrxrxk";

typedef struct {
  uint8_t version;
  const char *envelope_hex;
  const char *plaintext_hex; /* NULL means "the descriptor above" */
} kef_vector_t;

static const kef_vector_t VECTORS[] = {
    /* --- Krux tests/test_encryption.py --- */
    {0,
     "07746573742049440000000a2ae19dc582c1199bb726f23f03c76ff6af9e8123462c5173"
     "e61debd159a02fcf",
     ENTROPY16_HEX},
    {1,
     "07746573742049440100000a4f52a1936c3e3271209e9d64059ed78e010360755fd7ab2f"
     "4ebc4019cc0a22c58a5e337874a4b30b4bca8a4082da7ad3",
     ENTROPY16_HEX},
    {5, "07746573742049440500000a2ae19dc582c1199bb726f23f03c76ff6523e23",
     ENTROPY16_HEX},
    {10,
     "07746573742049440a00000a4f52a1936c3e3271209e9d64059ed78e010360755fd7ab2f"
     "4ebc4019cc0a22c543fa9690",
     ENTROPY16_HEX},
    {15,
     "07746573742049440f00000a4f52a1936c3e3271209e9d64f49120c7a26d12de7b0ff026"
     "8c9691e689b02494f0af52c21c295b57b5347e9a86ee2a40",
     CTR_ENTROPY_HEX},
    {20,
     "07746573742049441400000a4f52a1936c3e3271209e9d64bfb7766f5d5d8a4f908e86e7"
     "38344c025d8fed54",
     ENTROPY16_HEX},

    /* --- independent reference, same key/ID/iterations --- */
    {6,
     "07746573742049440600000a2ae19dc582c1199bb726f23f03c76ff632c1cb8863c7d8b2"
     "7a03fdaf207fbf75",
     ENTROPY16_HEX},
    {11,
     "07746573742049440b00000a4f52a1936c3e3271209e9d64059ed78e010360755fd7ab2f"
     "4ebc4019cc0a22c5c6b2f3240a0c020bfe0ab753a88e7d12",
     ENTROPY16_HEX},
    {7,
     "07746573742049440700000a10e5fa9be714f74d3b72ac21be9b694dc2423a4dfffd86c2"
     "0441731384fd416f6d7a7045defbc4825cea8373d28e1ca3fe5c263f8fe5503e33f8f8b5"
     "5915d50f2e9a33441c87b36b49e87f42a4eb165beafa41656069737cc66e5d6085e965b7"
     "c368ac247e855802331075f7bdf77cf53b03e0c08b9d7867c92d690803e0b798ba3256f6"
     "7a0656607942d677645c59e24eade794729ddf1aeccc97e0bc5ff7cbe6fc9bfd7f3a69be"
     "b2e5514afce0a483f4716b2ff257ab91fc3889e3240752b762bcab76f5e149a26d564648"
     "d9e2f67f5ee4c5471b110a5cbc50ba03b02b4e50a895ba39317c8a9afb002996fef32b03"
     "83c6c5d80108b2b96a483b84ad5e9b7935174cd0ccd313a79b225df4d75f3646",
     NULL},
    {12,
     "07746573742049440c00000a4f52a1936c3e3271209e9d64059ed78eae1b5ca655af7602"
     "a82c6d8f299ce165526b2b7a313f45c9dcfdefa5dbab8e93518663eab899ccc7c831932b"
     "6fdc4694b532c2e77ab158d5b379714cc08e9e0b55342a0268fb040e9660e13598e3da7f"
     "cf55e5a35e49f3425ea9867f17cb8d38c4b377350ef689216dc4e5790b2d999bd4963e3e"
     "be01f99b799b8cb0076f0e784101f413626159e93c6c5d05493f5c4a511d82e7a3758a2f"
     "cde170fcb08b32ac6b0441239d8e80da38bc9d777111c795230d11dbce9a87ea0c19c06c"
     "3d5e5d2258289317eb7ec6636b6e26c9ff11e362e35d0603ada7c96b3ff83e4480c5e94a"
     "cdd7c3e4c8d056ccc0f2560c8b7875c744d4f3cfd727057f1a7cda4c508c33b9ae2b24aa"
     "ae01881285757a8a31fd3d91",
     NULL},
    {16,
     "07746573742049441000000a4f52a1936c3e3271209e9d64750b079d4cf70c0ef73b75f5"
     "5f6a9ae46120aac5c9d17351375e885effd71f11f9f94c9fc0c7e3318f09723d53c88e25"
     "9f13d02d4739e2d5386ee68190f4abc63ee004b0a96fa3cc89dd8bc025f1e1eee777a576"
     "b5183c7c2ff4a15ae75c0778586f66e76dcc0da1f13c430f256a4350248d8443b2f05b4c"
     "61e068486e9aacfdc1d1ca159393425d6e61c5d8e575f86b4729b05351a55ae786334d04"
     "8ba50abf55e134cb12964b0f3e5be6b3d50b946fc18230d4953ba51eb2079263b2bd648c"
     "b990c8a2e8b83092d50e7ca916285d1d17a8f231b15d9910a454bbd57722da8b49049dcd"
     "593071dd9ec858b5023ca3d5b9194e3cacd469b9ee8f630e65886f7683515e3a0c666820",
     NULL},
    {21,
     "07746573742049441500000a4f52a1936c3e3271209e9d64e777c0307c0aad8a82f52917"
     "ac2302aeb8dad2f210c44ca4a2f150b75d3facf5ab2a240092e2a892ee6036682b4788f0"
     "cb2cee99444f5798c27732cc660bee749aefe70f0c9d0c0db90e802aa4c6d0fbde6a104b"
     "f77f35e804bac875282b41ed1401d7ceebc28bd114dc53e992bbf8bc12471a3ae3bfd07c"
     "dd3bf2cfdfd848126ed025eddc3aa2af27ecff11c3439e76b956b26a43af8ba0a214d24f"
     "cd8c7b84297350a8b1e9967956e62c6593f40ef3c33c666e47a4b1f112cb8a29b124b0d2"
     "f30b7855f6a647b018e25f09075e98ed0dcd664c3a1d0b85f57a4dc1d3fe5309e9a735c7"
     "3063c90e58e64f1787f56d4ee94196167c8c1c128bbcb5faccfac9c2b71196290c86aba8",
     NULL},
};
#define VECTOR_COUNT (sizeof(VECTORS) / sizeof(VECTORS[0]))

static const uint8_t ALL_VERSIONS[] = {0,  1,  5,  6,  7,  10,
                                       11, 12, 15, 16, 20, 21};
#define ALL_VERSION_COUNT (sizeof(ALL_VERSIONS) / sizeof(ALL_VERSIONS[0]))

/* ---------- 1. cross-implementation vectors ---------- */

static void test_vectors_decrypt(void) {
  for (size_t i = 0; i < VECTOR_COUNT; i++) {
    const kef_vector_t *v = &VECTORS[i];
    uint8_t envelope[512];
    size_t env_len = unhex(v->envelope_hex, envelope, sizeof(envelope));

    uint8_t expected[512];
    size_t expected_len;
    if (v->plaintext_hex) {
      expected_len = unhex(v->plaintext_hex, expected, sizeof(expected));
    } else {
      expected_len = strlen(TEST_DESCRIPTOR);
      memcpy(expected, TEST_DESCRIPTOR, expected_len);
    }

    uint8_t *out = NULL;
    size_t out_len = 0;
    kef_error_t err =
        kef_decrypt(envelope, env_len, TEST_KEY, TEST_KEY_LEN, &out, &out_len);

    char name[64];
    snprintf(name, sizeof(name), "vector v%u decrypts", v->version);
    check(name, err == KEF_OK && out_len == expected_len && out &&
                    memcmp(out, expected, expected_len) == 0);
    free(out);
  }
}

static void test_vectors_header(void) {
  for (size_t i = 0; i < VECTOR_COUNT; i++) {
    const kef_vector_t *v = &VECTORS[i];
    uint8_t envelope[512];
    size_t env_len = unhex(v->envelope_hex, envelope, sizeof(envelope));

    const uint8_t *id = NULL;
    size_t id_len = 0;
    uint8_t version = 0xff;
    uint32_t iterations = 0;
    kef_error_t err = kef_parse_header(envelope, env_len, &id, &id_len,
                                       &version, &iterations);

    char name[64];
    snprintf(name, sizeof(name), "vector v%u header", v->version);
    check(name, err == KEF_OK && version == v->version &&
                    iterations == TEST_ITERATIONS && id_len == TEST_ID_LEN &&
                    memcmp(id, TEST_ID, TEST_ID_LEN) == 0 &&
                    kef_is_envelope(envelope, env_len));
  }
}

static void test_vectors_reject_wrong_key(void) {
  bool all_rejected = true;
  for (size_t i = 0; i < VECTOR_COUNT; i++) {
    uint8_t envelope[512];
    size_t env_len = unhex(VECTORS[i].envelope_hex, envelope, sizeof(envelope));
    uint8_t *out = NULL;
    size_t out_len = 0;
    kef_error_t err = kef_decrypt(envelope, env_len, (const uint8_t *)"wrong",
                                  5, &out, &out_len);
    /* GCM reports a tag failure, the SHA-256 schemes an auth failure, and a
     * bad key can also land on invalid PKCS#7 padding — never KEF_OK. */
    if (err == KEF_OK)
      all_rejected = false;
    free(out);
  }
  check("wrong key rejected for every vector", all_rejected);
}

/* ---------- 2. round-trips ---------- */

static bool roundtrip(uint8_t version, const uint8_t *plaintext, size_t len) {
  uint8_t *envelope = NULL;
  size_t env_len = 0;
  if (kef_encrypt(TEST_ID, TEST_ID_LEN, version, TEST_KEY, TEST_KEY_LEN,
                  TEST_ITERATIONS, plaintext, len, &envelope,
                  &env_len) != KEF_OK)
    return false;

  uint8_t *out = NULL;
  size_t out_len = 0;
  bool ok = kef_decrypt(envelope, env_len, TEST_KEY, TEST_KEY_LEN, &out,
                        &out_len) == KEF_OK &&
            out_len == len && out && memcmp(out, plaintext, len) == 0;
  free(envelope);
  free(out);
  return ok;
}

static void test_roundtrip_all_versions(void) {
  uint8_t entropy[32];
  size_t entropy_len = unhex(ENTROPY16_HEX, entropy, sizeof(entropy));

  for (size_t i = 0; i < ALL_VERSION_COUNT; i++) {
    uint8_t v = ALL_VERSIONS[i];
    char name[64];
    snprintf(name, sizeof(name), "v%u round-trips 16-byte entropy", v);
    check(name, roundtrip(v, entropy, entropy_len));
  }
}

static void test_roundtrip_descriptor(void) {
  const uint8_t *desc = (const uint8_t *)TEST_DESCRIPTOR;
  size_t len = strlen(TEST_DESCRIPTOR);

  for (size_t i = 0; i < ALL_VERSION_COUNT; i++) {
    uint8_t v = ALL_VERSIONS[i];
    /* v0/v1 use 16 hidden auth bytes and v5 a 3-byte exposed auth over NUL
     * padding; a text payload ending in printable bytes is fine for all of
     * them, but ECB rejects duplicate blocks, which a repetitive descriptor
     * can produce.  Skip only that documented refusal. */
    uint8_t *envelope = NULL;
    size_t env_len = 0;
    kef_error_t err =
        kef_encrypt(TEST_ID, TEST_ID_LEN, v, TEST_KEY, TEST_KEY_LEN,
                    TEST_ITERATIONS, desc, len, &envelope, &env_len);
    if (err == KEF_ERR_DUPLICATE_BLOCKS) {
      free(envelope);
      continue;
    }

    uint8_t *out = NULL;
    size_t out_len = 0;
    bool ok = err == KEF_OK &&
              kef_decrypt(envelope, env_len, TEST_KEY, TEST_KEY_LEN, &out,
                          &out_len) == KEF_OK &&
              out_len == len && out && memcmp(out, desc, len) == 0;
    free(envelope);
    free(out);

    char name[64];
    snprintf(name, sizeof(name), "v%u round-trips a descriptor", v);
    check(name, ok);
  }
}

/*
 * Plaintexts whose truncated SHA-256 auth ends in NUL bytes.  NUL-padded
 * versions strip trailing zeros on the way out, so the unpadder has to try
 * adding them back — these are exactly the cases that break a naive strip.
 * Vectors carried over from Krux's tests/test_kef.py.
 */
static const char *const NUL_SUFFIX_PLAINTEXTS[] = {
    "62234372793ce593f8f4af6a89b4e385", "036183a943c42e86903b3447fdf153f9",
    "66f3016a11ade73b9785a83863edf367", "c7505e82cd1728cd5e959cc57aa41922",
    "17efa28586fd88a281120a034d44467a", "7aa3d3a355a0b557b3610f6075c22621",
    "cf756ddf68dbb370371f7d37cccfa5da", "41e79f271771259c13129bb94315c691",
};
#define NUL_SUFFIX_COUNT                                                       \
  (sizeof(NUL_SUFFIX_PLAINTEXTS) / sizeof(NUL_SUFFIX_PLAINTEXTS[0]))

static void test_nul_suffix_recovery(void) {
  /* Only the NUL-padded versions exercise the recovery loop */
  static const uint8_t nul_versions[] = {0, 1, 5, 10};

  for (size_t v = 0; v < sizeof(nul_versions); v++) {
    bool all_ok = true;
    for (size_t i = 0; i < NUL_SUFFIX_COUNT; i++) {
      uint8_t plain[32];
      size_t plain_len = unhex(NUL_SUFFIX_PLAINTEXTS[i], plain, sizeof(plain));
      if (!roundtrip(nul_versions[v], plain, plain_len))
        all_ok = false;
    }
    char name[80];
    snprintf(name, sizeof(name), "v%u recovers NUL-suffixed auth bytes",
             nul_versions[v]);
    check(name, all_ok);
  }
}

static void test_trailing_nul_plaintext(void) {
  /* A plaintext that itself ends in NUL must survive NUL padding */
  const uint8_t plain[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x00};
  check("v10 round-trips a NUL-terminated plaintext",
        roundtrip(10, plain, sizeof(plain)));
  check("v20 round-trips a single NUL byte", roundtrip(20, plain + 4, 1));
}

/* ---------- 3. iteration bounds ---------- */

static size_t tamper_iterations(const char *envelope_hex, uint32_t stored,
                                uint8_t *out, size_t out_size) {
  size_t len = unhex(envelope_hex, out, out_size);
  size_t pos = 1 + out[0] + 1; /* len_id + id + version */
  out[pos] = (uint8_t)(stored >> 16);
  out[pos + 1] = (uint8_t)(stored >> 8);
  out[pos + 2] = (uint8_t)stored;
  return len;
}

static void test_iteration_bounds(void) {
  const char *hex = VECTORS[5].envelope_hex; /* v20 */
  uint8_t env[512];

  /* stored 0 decodes to 0 effective iterations */
  size_t len = tamper_iterations(hex, 0, env, sizeof(env));
  const uint8_t *id;
  size_t id_len;
  check("zero iterations rejected by kef_parse_header",
        kef_parse_header(env, len, &id, &id_len, NULL, NULL) ==
            KEF_ERR_INVALID_ITERATIONS);
  check("zero iterations not an envelope", !kef_is_envelope(env, len));

  uint8_t *out = NULL;
  size_t out_len = 0;
  check("zero iterations rejected by kef_decrypt",
        kef_decrypt(env, len, TEST_KEY, TEST_KEY_LEN, &out, &out_len) ==
            KEF_ERR_INVALID_ITERATIONS);
  free(out);

  /* stored 0xffffff decodes to 16,777,215 — above the ceiling */
  len = tamper_iterations(hex, 0xffffff, env, sizeof(env));
  check("oversized iterations rejected",
        kef_parse_header(env, len, &id, &id_len, NULL, NULL) ==
            KEF_ERR_INVALID_ITERATIONS);

  /* stored 1 decodes to exactly KEF_MIN_ITERATIONS */
  len = tamper_iterations(hex, 1, env, sizeof(env));
  uint32_t iterations = 0;
  check("minimum iterations accepted",
        kef_parse_header(env, len, &id, &id_len, NULL, &iterations) == KEF_OK &&
            iterations == KEF_MIN_ITERATIONS);

  /* stored 1000 decodes to exactly KEF_MAX_ITERATIONS */
  len = tamper_iterations(hex, 1000, env, sizeof(env));
  check("maximum iterations accepted",
        kef_parse_header(env, len, &id, &id_len, NULL, &iterations) == KEF_OK &&
            iterations == KEF_MAX_ITERATIONS);

  /* stored 1001 decodes to 10,010,000 — just over the ceiling */
  len = tamper_iterations(hex, 1001, env, sizeof(env));
  check("just-over-maximum iterations rejected",
        kef_parse_header(env, len, &id, &id_len, NULL, NULL) ==
            KEF_ERR_INVALID_ITERATIONS);
}

static void test_iteration_encoding(void) {
  static const uint32_t values[] = {10000, 100000, 500000, 10000000, 12345};
  bool ok = true;
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    uint8_t stored[3];
    kef_encode_iterations(values[i], stored);
    if (kef_decode_iterations(stored) != values[i])
      ok = false;
  }
  check("iteration encode/decode round-trips", ok);
}

/* ---------- 4. envelope detection and armor ---------- */

static void test_envelope_from_bytes_armors(void) {
  uint8_t raw[512];
  size_t raw_len = unhex(VECTORS[5].envelope_hex, raw, sizeof(raw)); /* v20 */

  size_t got_len = 0;
  uint8_t *got = kef_envelope_from_bytes(raw, raw_len, &got_len);
  check("raw envelope detected",
        got && got_len == raw_len && memcmp(got, raw, raw_len) == 0);
  free(got);

  /* base64, as stored on SD */
  unsigned char b64[1024];
  size_t b64_len = 0;
  mbedtls_base64_encode(b64, sizeof(b64), &b64_len, raw, raw_len);
  got = kef_envelope_from_bytes(b64, b64_len, &got_len);
  check("base64-armored envelope detected",
        got && got_len == raw_len && memcmp(got, raw, raw_len) == 0);
  free(got);

  /* base43, as encoded into a QR */
  char *b43 = NULL;
  size_t b43_len = 0;
  bool encoded = base43_encode(raw, raw_len, &b43, &b43_len);
  got = encoded
            ? kef_envelope_from_bytes((const uint8_t *)b43, b43_len, &got_len)
            : NULL;
  check("base43-armored envelope detected",
        got && got_len == raw_len && memcmp(got, raw, raw_len) == 0);
  free(got);

  /* trailing whitespace an editor may have appended */
  if (encoded) {
    char padded[1024];
    snprintf(padded, sizeof(padded), "%s\r\n", b43);
    got = kef_envelope_from_bytes((const uint8_t *)padded, strlen(padded),
                                  &got_len);
    check("base43 armor tolerates trailing whitespace",
          got && got_len == raw_len);
    free(got);
  }
  free(b43);
}

static void test_envelope_from_bytes_rejects(void) {
  static const char *const not_envelopes[] = {
      TEST_DESCRIPTOR,
      "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+///"
      "/",
      "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
      "crush inherit small egg include title slogan mom remain blouse boost "
      "bonus",
      "",
  };
  bool all_rejected = true;
  for (size_t i = 0; i < sizeof(not_envelopes) / sizeof(not_envelopes[0]);
       i++) {
    size_t len = 0;
    uint8_t *got = kef_envelope_from_bytes((const uint8_t *)not_envelopes[i],
                                           strlen(not_envelopes[i]), &len);
    if (got)
      all_rejected = false;
    free(got);
  }
  check("plaintext payloads are not mistaken for envelopes", all_rejected);
}

/* ---------- 5. malformed envelopes ---------- */

static void test_truncated_envelopes(void) {
  uint8_t full[512];
  size_t full_len = unhex(VECTORS[1].envelope_hex, full, sizeof(full)); /* v1 */

  bool all_handled = true;
  for (size_t len = 0; len < full_len; len++) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    kef_error_t err =
        kef_decrypt(full, len, TEST_KEY, TEST_KEY_LEN, &out, &out_len);
    if (err == KEF_OK)
      all_handled = false;
    free(out);
  }
  check("every truncation of a valid envelope is rejected", all_handled);
}

static void test_unknown_version(void) {
  uint8_t env[512];
  size_t len = unhex(VECTORS[5].envelope_hex, env, sizeof(env));
  size_t version_pos = 1 + env[0];

  bool all_rejected = true;
  static const uint8_t unknown[] = {2, 3, 4, 8, 9, 13, 14, 17, 18, 19, 22, 255};
  for (size_t i = 0; i < sizeof(unknown); i++) {
    env[version_pos] = unknown[i];
    if (kef_is_envelope(env, len))
      all_rejected = false;
    uint8_t *out = NULL;
    size_t out_len = 0;
    if (kef_decrypt(env, len, TEST_KEY, TEST_KEY_LEN, &out, &out_len) == KEF_OK)
      all_rejected = false;
    free(out);
  }
  check("unknown versions rejected", all_rejected);
}

static void test_zero_length_id_rejected(void) {
  uint8_t env[512];
  size_t len = unhex(VECTORS[5].envelope_hex, env, sizeof(env));
  env[0] = 0;
  const uint8_t *id;
  size_t id_len;
  check("zero-length ID rejected",
        kef_parse_header(env, len, &id, &id_len, NULL, NULL) != KEF_OK &&
            !kef_is_envelope(env, len));
}

static void test_binary_id_rejected(void) {
  /* kef_is_envelope requires a printable ID so raw binary payloads that
   * happen to parse as a header are not offered to the key prompt */
  uint8_t env[512];
  size_t len = unhex(VECTORS[5].envelope_hex, env, sizeof(env));
  env[1] = 0x01;
  check("non-printable ID is not an envelope", !kef_is_envelope(env, len));
}

/* ---------- 6. argument validation ---------- */

static void test_encrypt_rejects_bad_args(void) {
  uint8_t *out = NULL;
  size_t out_len = 0;
  const uint8_t data[] = {1, 2, 3};

  bool ok =
      kef_encrypt(NULL, 0, 20, TEST_KEY, TEST_KEY_LEN, TEST_ITERATIONS, data,
                  sizeof(data), &out, &out_len) == KEF_ERR_INVALID_ARG &&
      kef_encrypt(TEST_ID, TEST_ID_LEN, 20, TEST_KEY, TEST_KEY_LEN,
                  TEST_ITERATIONS, data, 0, &out,
                  &out_len) == KEF_ERR_INVALID_ARG &&
      kef_encrypt(TEST_ID, TEST_ID_LEN, 99, TEST_KEY, TEST_KEY_LEN,
                  TEST_ITERATIONS, data, sizeof(data), &out,
                  &out_len) == KEF_ERR_UNSUPPORTED_VERSION;
  check("kef_encrypt rejects invalid arguments", ok);

  /* An envelope must never be written with a work factor the reader refuses */
  bool bounded =
      kef_encrypt(TEST_ID, TEST_ID_LEN, 20, TEST_KEY, TEST_KEY_LEN, 0, data,
                  sizeof(data), &out, &out_len) == KEF_ERR_INVALID_ITERATIONS &&
      kef_encrypt(TEST_ID, TEST_ID_LEN, 20, TEST_KEY, TEST_KEY_LEN,
                  KEF_MIN_ITERATIONS - 1, data, sizeof(data), &out,
                  &out_len) == KEF_ERR_INVALID_ITERATIONS &&
      kef_encrypt(TEST_ID, TEST_ID_LEN, 20, TEST_KEY, TEST_KEY_LEN,
                  KEF_MAX_ITERATIONS + 1, data, sizeof(data), &out,
                  &out_len) == KEF_ERR_INVALID_ITERATIONS;
  check("kef_encrypt enforces the same iteration window as the reader",
        bounded);
}

static void test_error_strings(void) {
  static const kef_error_t errors[] = {KEF_OK,
                                       KEF_ERR_INVALID_ARG,
                                       KEF_ERR_UNSUPPORTED_VERSION,
                                       KEF_ERR_ALLOC,
                                       KEF_ERR_CRYPTO,
                                       KEF_ERR_AUTH,
                                       KEF_ERR_COMPRESS,
                                       KEF_ERR_DECOMPRESS,
                                       KEF_ERR_ENVELOPE_TOO_SHORT,
                                       KEF_ERR_DUPLICATE_BLOCKS,
                                       KEF_ERR_INVALID_ITERATIONS};
  bool ok = true;
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    const char *s = kef_error_str(errors[i]);
    if (!s || s[0] == '\0')
      ok = false;
  }
  check("every error code has a message", ok);
}

int main(void) {
  test_vectors_header();
  test_vectors_decrypt();
  test_vectors_reject_wrong_key();

  test_roundtrip_all_versions();
  test_roundtrip_descriptor();
  test_nul_suffix_recovery();
  test_trailing_nul_plaintext();

  test_iteration_bounds();
  test_iteration_encoding();

  test_envelope_from_bytes_armors();
  test_envelope_from_bytes_rejects();

  test_truncated_envelopes();
  test_unknown_version();
  test_zero_length_id_rejected();
  test_binary_id_rejected();

  test_encrypt_rejects_bad_args();
  test_error_strings();

  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed ? 1 : 0;
}
