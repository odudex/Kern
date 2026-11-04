/*
 * PBKDF2 for the simulator and the host tests, in place of core/pbkdf2.c.
 *
 * The host mbedTLS predates PSA PBKDF2 (added in 3.5), so the PSA reference
 * derives through the legacy pkcs5 API, which mbedtls_compat.h wraps for 2.x.
 * There is no SHA accelerator, so pbkdf2_hw_*() are not provided.
 */

#include "core/crypto_utils.h"
#include "core/pbkdf2.h"
#include "mbedtls_compat.h"

static int legacy_pbkdf2(mbedtls_md_type_t md, const uint8_t *password,
                         size_t password_len, const uint8_t *salt,
                         size_t salt_len, uint32_t iterations, uint8_t *key_out,
                         size_t key_len) {
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
      md, password, password_len, salt, salt_len, iterations, key_len, key_out);
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

int pbkdf2_psa_sha256(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len, uint32_t iterations,
                      uint8_t *key_out, size_t key_len) {
  return legacy_pbkdf2(MBEDTLS_MD_SHA256, password, password_len, salt,
                       salt_len, iterations, key_out, key_len);
}

int pbkdf2_psa_sha512(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len, uint32_t iterations,
                      uint8_t *key_out, size_t key_len) {
  return legacy_pbkdf2(MBEDTLS_MD_SHA512, password, password_len, salt,
                       salt_len, iterations, key_out, key_len);
}
