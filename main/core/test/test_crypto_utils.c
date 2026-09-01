/*
 * Crypto primitive tests (core/crypto_utils.c) against published vectors:
 * FIPS 197 (AES-256 ECB), NIST SP 800-38A (CBC), NIST GCM test cases 13/14,
 * FIPS 180 (SHA-256) and the standard PBKDF2-HMAC-SHA256 vectors. CTR is
 * checked against a keystream built from the ECB primitive.
 */

#include "../crypto_utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IGNORE(call)                                                           \
  do {                                                                         \
    if ((call) != 0) {                                                         \
    }                                                                          \
  } while (0)

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

static bool hex_eq(const uint8_t *got, const char *hex, size_t len) {
  uint8_t exp[128];
  return unhex(hex, exp) == len && memcmp(got, exp, len) == 0;
}

static const char *KEY_FIPS =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char *KEY_38A =
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

static void test_sha256(void) {
  uint8_t h[32];
  check("sha256 abc",
        crypto_sha256((const uint8_t *)"abc", 3, h) == CRYPTO_OK &&
            hex_eq(h,
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f"
                   "20015ad",
                   32));
  check("sha256 empty",
        crypto_sha256((const uint8_t *)"", 0, h) == CRYPTO_OK &&
            hex_eq(h,
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7"
                   "852b855",
                   32));
  uint8_t million[1000];
  memset(million, 'a', sizeof(million));
  uint8_t big[1000 * 1000];
  for (int i = 0; i < 1000; i++)
    memcpy(big + i * 1000, million, 1000);
  check("sha256 one million a",
        crypto_sha256(big, sizeof(big), h) == CRYPTO_OK &&
            hex_eq(h,
                   "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc"
                   "7112cd0",
                   32));
  check("sha256 NULL args",
        crypto_sha256(NULL, 1, h) == CRYPTO_ERR_INVALID_ARG &&
            crypto_sha256(h, 1, NULL) == CRYPTO_ERR_INVALID_ARG);
}

static void test_ecb(void) {
  uint8_t key[32], pt[16], ct[16], back[16];
  unhex(KEY_FIPS, key);
  unhex("00112233445566778899aabbccddeeff", pt);
  check("ecb FIPS-197 C.3 encrypt",
        crypto_aes_ecb_encrypt(key, pt, 16, ct) == CRYPTO_OK &&
            hex_eq(ct, "8ea2b7ca516745bfeafc49904b496089", 16));
  check("ecb decrypt round trip",
        crypto_aes_ecb_decrypt(key, ct, 16, back) == CRYPTO_OK &&
            memcmp(back, pt, 16) == 0);
  uint8_t two[32], two_ct[32];
  memcpy(two, pt, 16);
  memcpy(two + 16, pt, 16);
  check("ecb equal blocks encrypt identically",
        crypto_aes_ecb_encrypt(key, two, 32, two_ct) == CRYPTO_OK &&
            memcmp(two_ct, ct, 16) == 0 && memcmp(two_ct + 16, ct, 16) == 0);
  check("ecb rejects partial blocks and empty input",
        crypto_aes_ecb_encrypt(key, pt, 15, ct) == CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_ecb_encrypt(key, pt, 0, ct) == CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_ecb_decrypt(key, pt, 17, ct) == CRYPTO_ERR_INVALID_ARG);
  check(
      "ecb rejects NULL args",
      crypto_aes_ecb_encrypt(NULL, pt, 16, ct) == CRYPTO_ERR_INVALID_ARG &&
          crypto_aes_ecb_encrypt(key, NULL, 16, ct) == CRYPTO_ERR_INVALID_ARG &&
          crypto_aes_ecb_encrypt(key, pt, 16, NULL) == CRYPTO_ERR_INVALID_ARG);
}

static void test_cbc(void) {
  uint8_t key[32], iv[16], pt[32], ct[32], back[32];
  unhex(KEY_38A, key);
  unhex("000102030405060708090a0b0c0d0e0f", iv);
  unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt);
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  check("cbc SP800-38A F.2.5 encrypt",
        crypto_aes_cbc_encrypt(key, iv, pt, 32, ct) == CRYPTO_OK &&
            hex_eq(ct,
                   "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc67"
                   "02c7d",
                   32));
  check("cbc leaves the iv untouched", memcmp(iv, iv_copy, 16) == 0);
  check("cbc decrypt round trip",
        crypto_aes_cbc_decrypt(key, iv, ct, 32, back) == CRYPTO_OK &&
            memcmp(back, pt, 32) == 0);
  uint8_t other_iv[16] = {1};
  check("cbc wrong iv corrupts only the first block",
        crypto_aes_cbc_decrypt(key, other_iv, ct, 32, back) == CRYPTO_OK &&
            memcmp(back, pt, 16) != 0 && memcmp(back + 16, pt + 16, 16) == 0);
  check("cbc rejects partial blocks and NULL iv",
        crypto_aes_cbc_encrypt(key, iv, pt, 20, ct) == CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_cbc_encrypt(key, NULL, pt, 16, ct) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_cbc_decrypt(key, iv, pt, 0, ct) ==
                CRYPTO_ERR_INVALID_ARG);
}

static void test_ctr(void) {
  uint8_t key[32], nonce[12], pt[53], ct[53], back[53];
  unhex(KEY_38A, key);
  for (int i = 0; i < 12; i++)
    nonce[i] = (uint8_t)(0xA0 + i);
  for (int i = 0; i < 53; i++)
    pt[i] = (uint8_t)(i * 7);
  check("ctr encrypt",
        crypto_aes_ctr(key, nonce, pt, sizeof(pt), ct) == CRYPTO_OK);
  check("ctr is symmetric",
        crypto_aes_ctr(key, nonce, ct, sizeof(ct), back) == CRYPTO_OK &&
            memcmp(back, pt, sizeof(pt)) == 0);

  /* keystream block i = AES(key, nonce || BE32(i)), counter starting at 0 */
  uint8_t blocks[4][16], stream[64];
  for (uint32_t i = 0; i < 4; i++) {
    memcpy(blocks[i], nonce, 12);
    blocks[i][12] = (uint8_t)(i >> 24);
    blocks[i][13] = (uint8_t)(i >> 16);
    blocks[i][14] = (uint8_t)(i >> 8);
    blocks[i][15] = (uint8_t)i;
  }
  bool ok =
      crypto_aes_ecb_encrypt(key, (uint8_t *)blocks, 64, stream) == CRYPTO_OK;
  for (size_t i = 0; ok && i < sizeof(pt); i++)
    ok = ct[i] == (pt[i] ^ stream[i]);
  check("ctr keystream is ECB of nonce||counter from zero", ok);

  check("ctr accepts a single byte",
        crypto_aes_ctr(key, nonce, pt, 1, ct) == CRYPTO_OK &&
            ct[0] == (pt[0] ^ stream[0]));
  check("ctr rejects empty and NULL",
        crypto_aes_ctr(key, nonce, pt, 0, ct) == CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_ctr(key, NULL, pt, 1, ct) == CRYPTO_ERR_INVALID_ARG);
}

static void test_gcm(void) {
  uint8_t key[32] = {0}, nonce[12] = {0}, pt[16] = {0}, ct[16], tag[16],
          back[16];
  check("gcm NIST test case 13 (empty plaintext)",
        crypto_aes_gcm_encrypt(key, nonce, 12, pt, 0, ct, tag, 16) ==
                CRYPTO_OK &&
            hex_eq(tag, "530f8afbc74536b9a963b4f1c4cb738b", 16));
  check("gcm NIST test case 14",
        crypto_aes_gcm_encrypt(key, nonce, 12, pt, 16, ct, tag, 16) ==
                CRYPTO_OK &&
            hex_eq(ct, "cea7403d4d606b6e074ec5d3baf39d18", 16) &&
            hex_eq(tag, "d0d1c8a799996bf0265b98b5d48ab919", 16));
  check("gcm decrypt round trip",
        crypto_aes_gcm_decrypt(key, nonce, 12, ct, 16, back, tag, 16) ==
                CRYPTO_OK &&
            memcmp(back, pt, 16) == 0);

  uint8_t bad_tag[16];
  memcpy(bad_tag, tag, 16);
  bad_tag[15] ^= 1;
  check("gcm tampered tag fails auth",
        crypto_aes_gcm_decrypt(key, nonce, 12, ct, 16, back, bad_tag, 16) ==
            CRYPTO_ERR_AUTH_FAILED);
  uint8_t bad_ct[16];
  memcpy(bad_ct, ct, 16);
  bad_ct[0] ^= 1;
  check("gcm tampered ciphertext fails auth",
        crypto_aes_gcm_decrypt(key, nonce, 12, bad_ct, 16, back, tag, 16) ==
            CRYPTO_ERR_AUTH_FAILED);
  uint8_t other_nonce[12] = {1};
  check("gcm wrong nonce fails auth",
        crypto_aes_gcm_decrypt(key, other_nonce, 12, ct, 16, back, tag, 16) ==
            CRYPTO_ERR_AUTH_FAILED);
  uint8_t other_key[32] = {1};
  check("gcm wrong key fails auth",
        crypto_aes_gcm_decrypt(other_key, nonce, 12, ct, 16, back, tag, 16) ==
            CRYPTO_ERR_AUTH_FAILED);

  uint8_t msg[37], mct[37], mtag[16], mback[37];
  for (int i = 0; i < 37; i++)
    msg[i] = (uint8_t)(i * 13);
  bool ok = true;
  for (size_t tl = 4; tl <= 16 && ok; tl++) {
    ok = crypto_aes_gcm_encrypt(key, nonce, 12, msg, 37, mct, mtag, tl) ==
             CRYPTO_OK &&
         crypto_aes_gcm_decrypt(key, nonce, 12, mct, 37, mback, mtag, tl) ==
             CRYPTO_OK &&
         memcmp(mback, msg, 37) == 0;
    if (ok) {
      mtag[tl - 1] ^= 0x80;
      ok = crypto_aes_gcm_decrypt(key, nonce, 12, mct, 37, mback, mtag, tl) ==
           CRYPTO_ERR_AUTH_FAILED;
    }
  }
  check("gcm tag lengths 4..16 round trip and detect tampering", ok);
  check("gcm tag prefix property",
        crypto_aes_gcm_encrypt(key, nonce, 12, msg, 37, mct, mtag, 16) ==
                CRYPTO_OK &&
            ({
              uint8_t t8[8];
              crypto_aes_gcm_encrypt(key, nonce, 12, msg, 37, mct, t8, 8) ==
                  CRYPTO_OK &&memcmp(t8, mtag, 8) == 0;
            }));
  check("gcm rejects bad tag lengths and NULL args",
        crypto_aes_gcm_encrypt(key, nonce, 12, pt, 16, ct, tag, 0) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_gcm_encrypt(key, nonce, 12, pt, 16, ct, tag, 17) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_gcm_encrypt(key, nonce, 0, pt, 16, ct, tag, 16) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_aes_gcm_decrypt(key, nonce, 12, ct, 16, back, NULL, 16) ==
                CRYPTO_ERR_INVALID_ARG);
  check("gcm accepts a non-12-byte nonce",
        crypto_aes_gcm_encrypt(key, msg, 20, pt, 16, ct, tag, 16) ==
                CRYPTO_OK &&
            crypto_aes_gcm_decrypt(key, msg, 20, ct, 16, back, tag, 16) ==
                CRYPTO_OK);
}

static void test_pbkdf2(void) {
  uint8_t out[64];
  const uint8_t *pw = (const uint8_t *)"password";
  const uint8_t *salt = (const uint8_t *)"salt";
  check("pbkdf2 c=1",
        crypto_pbkdf2_sha256(pw, 8, salt, 4, 1, out, 32) == CRYPTO_OK &&
            hex_eq(out,
                   "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70"
                   "be17b",
                   32));
  check("pbkdf2 c=2",
        crypto_pbkdf2_sha256(pw, 8, salt, 4, 2, out, 32) == CRYPTO_OK &&
            hex_eq(out,
                   "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a954"
                   "74c43",
                   32));
  check("pbkdf2 c=4096",
        crypto_pbkdf2_sha256(pw, 8, salt, 4, 4096, out, 32) == CRYPTO_OK &&
            hex_eq(out,
                   "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa9"
                   "8134a",
                   32));
  check("pbkdf2 RFC 7914 dkLen 64",
        crypto_pbkdf2_sha256((const uint8_t *)"passwd", 6, salt, 4, 1, out,
                             64) == CRYPTO_OK &&
            hex_eq(out,
                   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20"
                   "dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd5091120"
                   "41d3a19783",
                   64));
  check("pbkdf2 dkLen 40 spans blocks",
        crypto_pbkdf2_sha256((const uint8_t *)"passwordPASSWORDpassword", 24,
                             (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALT"
                                              "salt",
                             36, 4096, out, 40) == CRYPTO_OK &&
            hex_eq(out,
                   "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8d"
                   "d53e1c635518c7dac47e9",
                   40));
  check("pbkdf2 rejects zero iterations, zero length and NULL",
        crypto_pbkdf2_sha256(pw, 8, salt, 4, 0, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_pbkdf2_sha256(pw, 8, salt, 4, 1, out, 0) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_pbkdf2_sha256(NULL, 8, salt, 4, 1, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_pbkdf2_sha256(pw, 8, NULL, 4, 1, out, 32) ==
                CRYPTO_ERR_INVALID_ARG &&
            crypto_pbkdf2_sha256(pw, 8, salt, 4, 1, NULL, 32) ==
                CRYPTO_ERR_INVALID_ARG);
}

static void test_padding(void) {
  uint8_t in[16], out[32];
  for (int i = 0; i < 16; i++)
    in[i] = (uint8_t)i;

  check("pad 5 bytes to 16", crypto_pkcs7_pad(in, 5, out, 32) == 16 &&
                                 memcmp(out, in, 5) == 0 && out[5] == 11 &&
                                 out[15] == 11);
  check("pad full block adds a whole block",
        crypto_pkcs7_pad(in, 16, out, 32) == 32 && out[16] == 16 &&
            out[31] == 16);
  check("pad empty input", crypto_pkcs7_pad(in, 0, out, 16) == 16 &&
                               out[0] == 16 && out[15] == 16);
  check("pad refuses a short output buffer",
        crypto_pkcs7_pad(in, 5, out, 15) == 0 &&
            crypto_pkcs7_pad(in, 16, out, 16) == 0);
  check("pad NULL args", crypto_pkcs7_pad(NULL, 5, out, 32) == 0 &&
                             crypto_pkcs7_pad(in, 5, NULL, 32) == 0);

  IGNORE(crypto_pkcs7_pad(in, 5, out, 32));
  check("unpad restores the length", crypto_pkcs7_unpad(out, 16) == 5);
  IGNORE(crypto_pkcs7_pad(in, 16, out, 32));
  check("unpad a full padding block", crypto_pkcs7_unpad(out, 32) == 16);
  check("unpad rejects non-block lengths",
        crypto_pkcs7_unpad(out, 15) == 0 && crypto_pkcs7_unpad(out, 0) == 0);
  uint8_t bad[16];
  memset(bad, 4, 16);
  bad[15] = 0;
  check("unpad rejects zero pad byte", crypto_pkcs7_unpad(bad, 16) == 0);
  bad[15] = 17;
  check("unpad rejects pad byte over block size",
        crypto_pkcs7_unpad(bad, 16) == 0);
  memset(bad, 4, 16);
  bad[13] = 3;
  check("unpad rejects inconsistent padding", crypto_pkcs7_unpad(bad, 16) == 0);
  memset(bad, 16, 16);
  check("unpad of an all-padding block is empty",
        crypto_pkcs7_unpad(bad, 16) == 0);
  check("unpad NULL", crypto_pkcs7_unpad(NULL, 16) == 0);
}

static void test_random(void) {
  uint8_t buf[64] = {0}, buf2[64] = {0};
  check("random rejects NULL and zero",
        crypto_random_bytes(NULL, 8) == CRYPTO_ERR_INVALID_ARG &&
            crypto_random_bytes(buf, 0) == CRYPTO_ERR_INVALID_ARG);
  check("random fills the buffer",
        crypto_random_bytes(buf, sizeof(buf)) == CRYPTO_OK &&
            crypto_random_bytes(buf2, sizeof(buf2)) == CRYPTO_OK &&
            memcmp(buf, buf2, sizeof(buf)) != 0);
  uint8_t acc = 0;
  for (size_t i = 0; i < sizeof(buf); i++)
    acc |= buf[i];
  check("random output is not all zero", acc != 0);
  check("random short draw accepted", crypto_random_bytes(buf, 1) == CRYPTO_OK);
}

int main(void) {
  printf("=== crypto_utils tests ===\n\n");
  test_sha256();
  test_ecb();
  test_cbc();
  test_ctr();
  test_gcm();
  test_pbkdf2();
  test_padding();
  test_random();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
