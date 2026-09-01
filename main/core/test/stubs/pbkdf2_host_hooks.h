/*
 * Force-included when compiling core/pbkdf2.c for the host tests. The host
 * mbedTLS (2.28) has no PSA PBKDF2 key derivation, so the PSA calls pbkdf2.c
 * makes are routed to a small reference implementation in test_pbkdf2.c.
 * psa/crypto.h is included first so only pbkdf2.c's own uses are renamed.
 */
#pragma once
#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  int alg_ok;
  uint32_t cost;
  uint8_t salt[256];
  size_t salt_len;
  uint8_t password[256];
  size_t password_len;
  uint32_t next_block; /* PBKDF2 block index of the next output byte */
  size_t block_used;   /* bytes of the current block already emitted */
  uint8_t block[32];
} host_kdf_t;

#define HOST_KDF_INIT                                                          \
  {                                                                            \
    0, 0, {0}, 0, {0}, 0, 1, 32, { 0 }                                         \
  }

psa_status_t host_kdf_setup(host_kdf_t *op, psa_algorithm_t alg);
psa_status_t host_kdf_input_integer(host_kdf_t *op, int step, uint64_t value);
psa_status_t host_kdf_input_bytes(host_kdf_t *op, int step, const uint8_t *data,
                                  size_t len);
psa_status_t host_kdf_output_bytes(host_kdf_t *op, uint8_t *out, size_t len);
psa_status_t host_kdf_abort(host_kdf_t *op);

#define HOST_ALG_PBKDF2_HMAC_SHA256 0x08800109u
#define PSA_ALG_PBKDF2_HMAC(hash) HOST_ALG_PBKDF2_HMAC_SHA256
#define PSA_KEY_DERIVATION_INPUT_COST 0x0301
#define PSA_KEY_DERIVATION_INPUT_PASSWORD 0x0302
#define HOST_KDF_INPUT_SALT 0x0303
#undef PSA_KEY_DERIVATION_INPUT_SALT
#define PSA_KEY_DERIVATION_INPUT_SALT HOST_KDF_INPUT_SALT

#define psa_key_derivation_operation_t host_kdf_t
#undef PSA_KEY_DERIVATION_OPERATION_INIT
#define PSA_KEY_DERIVATION_OPERATION_INIT HOST_KDF_INIT
#define psa_key_derivation_setup host_kdf_setup
#define psa_key_derivation_input_integer host_kdf_input_integer
#define psa_key_derivation_input_bytes host_kdf_input_bytes
#define psa_key_derivation_output_bytes host_kdf_output_bytes
#define psa_key_derivation_abort host_kdf_abort
