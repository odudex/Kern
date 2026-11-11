#include "sbv2.h"
#include <psa/crypto.h>
#include <string.h>

/* ets_secure_boot_sig_block_t, RSA scheme (esp_rom secure_boot.h) */
#define BLOCK_SIZE 1216
#define NUM_BLOCKS 3
#define MAGIC 0xE7
#define VERSION_RSA 0x02
#define RSA_LEN 384
#define OFF_IMAGE_DIGEST 4
#define OFF_KEY 36 /* ets_rsa_pubkey_t: n[384], e, rinv[384], mdash */
#define KEY_LEN 776
#define OFF_E (OFF_KEY + RSA_LEN)
#define OFF_SIGNATURE (OFF_KEY + KEY_LEN)
#define OFF_CRC (OFF_SIGNATURE + RSA_LEN)

/* CRC-32 as zlib computes it (espsecure) and esp_rom_crc32_le(0, ...) checks */
static uint32_t crc32_le(const uint8_t *p, size_t n) {
  uint32_t crc = 0xFFFFFFFF;
  while (n--) {
    crc ^= *p++;
    for (int k = 0; k < 8; k++)
      crc = (crc >> 1) ^ (0xEDB88320 & (0 - (crc & 1)));
  }
  return ~crc;
}

static uint32_t read_le32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}

static size_t der_len(uint8_t *out, size_t len) {
  if (len < 0x80) {
    out[0] = (uint8_t)len;
    return 1;
  }
  if (len < 0x100) {
    out[0] = 0x81;
    out[1] = (uint8_t)len;
    return 2;
  }
  out[0] = 0x82;
  out[1] = (uint8_t)(len >> 8);
  out[2] = (uint8_t)len;
  return 3;
}

/* Big-endian unsigned integer as a DER INTEGER */
static size_t der_uint(uint8_t *out, const uint8_t *be, size_t len) {
  while (len > 1 && be[0] == 0) {
    be++;
    len--;
  }
  bool pad = be[0] & 0x80;
  size_t n = 0;
  out[n++] = 0x02;
  n += der_len(out + n, len + pad);
  if (pad)
    out[n++] = 0;
  memcpy(out + n, be, len);
  return n + len;
}

/* PKCS#1 RSAPublicKey from the block's little-endian modulus and exponent */
static size_t rsa_public_key_der(const uint8_t *block, uint8_t *out) {
  uint8_t n_be[RSA_LEN];
  for (size_t i = 0; i < RSA_LEN; i++)
    n_be[i] = block[OFF_KEY + RSA_LEN - 1 - i];
  uint32_t e = read_le32(block + OFF_E);
  uint8_t e_be[4] = {(uint8_t)(e >> 24), (uint8_t)(e >> 16), (uint8_t)(e >> 8),
                     (uint8_t)e};

  uint8_t body[RSA_LEN + 16];
  size_t body_len = der_uint(body, n_be, RSA_LEN);
  body_len += der_uint(body + body_len, e_be, sizeof(e_be));

  size_t n = 0;
  out[n++] = 0x30;
  n += der_len(out + n, body_len);
  memcpy(out + n, body, body_len);
  return n + body_len;
}

static bool rsa_pss_verify(const uint8_t *block,
                           const uint8_t image_digest[SBV2_DIGEST_LEN]) {
  uint8_t der[RSA_LEN + 32];
  size_t der_size = rsa_public_key_der(block, der);

  uint8_t sig_be[RSA_LEN];
  for (size_t i = 0; i < RSA_LEN; i++)
    sig_be[i] = block[OFF_SIGNATURE + RSA_LEN - 1 - i];

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
  psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
  psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

  psa_key_id_t key = 0;
  bool ok = psa_import_key(&attr, der, der_size, &key) == PSA_SUCCESS &&
            psa_verify_hash(key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), image_digest,
                            SBV2_DIGEST_LEN, sig_be, RSA_LEN) == PSA_SUCCESS;
  if (key)
    psa_destroy_key(key);
  psa_reset_key_attributes(&attr);
  return ok;
}

size_t sbv2_sector_offset(size_t image_len) {
  return (image_len + SBV2_SECTOR_SIZE - 1) & ~(size_t)(SBV2_SECTOR_SIZE - 1);
}

bool sbv2_signed_by(const uint8_t sector[SBV2_SECTOR_SIZE],
                    const uint8_t image_digest[SBV2_DIGEST_LEN],
                    const uint8_t key_digest[SBV2_DIGEST_LEN]) {
  if (psa_crypto_init() != PSA_SUCCESS)
    return false;

  for (size_t i = 0; i < NUM_BLOCKS; i++) {
    const uint8_t *block = sector + i * BLOCK_SIZE;
    if (block[0] != MAGIC || block[1] != VERSION_RSA ||
        read_le32(block + OFF_CRC) != crc32_le(block, OFF_CRC) ||
        memcmp(block + OFF_IMAGE_DIGEST, image_digest, SBV2_DIGEST_LEN) != 0)
      continue;

    uint8_t digest[SBV2_DIGEST_LEN];
    size_t digest_len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, block + OFF_KEY, KEY_LEN, digest,
                         sizeof(digest), &digest_len) != PSA_SUCCESS ||
        memcmp(digest, key_digest, SBV2_DIGEST_LEN) != 0)
      continue;

    if (rsa_pss_verify(block, image_digest))
      return true;
  }
  return false;
}
