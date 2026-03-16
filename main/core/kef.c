/*
 * KEF — Key Encryption Format implementation
 *
 * Table-driven versioned encryption with AES-256, PBKDF2-HMAC-SHA256 key
 * derivation, optional raw-deflate compression, and hidden/exposed
 * authentication.  All code paths use goto-cleanup to guarantee
 * secure_memzero of key material and intermediates.
 */

#include "kef.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"

/* Raw deflate compress / decompress (wbits = 10) */
#include "../../components/bbqr/src/miniz.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Internal types                                                     */
/* ------------------------------------------------------------------ */

typedef enum { MODE_ECB, MODE_CBC, MODE_CTR, MODE_GCM } kef_mode_t;
typedef enum { PAD_NUL, PAD_PKCS7, PAD_NONE } kef_pad_t;
typedef enum { AUTH_HIDDEN, AUTH_EXPOSED, AUTH_GCM } kef_auth_t;

typedef struct {
  uint8_t version;
  kef_mode_t mode;
  uint8_t iv_size;
  kef_pad_t padding;
  bool compress;
  kef_auth_t auth_type;
  uint8_t auth_size;
} kef_version_info_t;

/* ------------------------------------------------------------------ */
/*  Version table                                                      */
/* ------------------------------------------------------------------ */

static const kef_version_info_t k_versions[] = {
    /* ver  mode      iv  padding   zlib   auth          abytes */
    {0, MODE_ECB, 0, PAD_NUL, false, AUTH_HIDDEN, 16},
    {1, MODE_CBC, 16, PAD_NUL, false, AUTH_HIDDEN, 16},
    {5, MODE_ECB, 0, PAD_NUL, false, AUTH_EXPOSED, 3},
    {6, MODE_ECB, 0, PAD_PKCS7, false, AUTH_HIDDEN, 4},
    {7, MODE_ECB, 0, PAD_PKCS7, true, AUTH_HIDDEN, 4},
    {10, MODE_CBC, 16, PAD_NUL, false, AUTH_EXPOSED, 4},
    {11, MODE_CBC, 16, PAD_PKCS7, false, AUTH_HIDDEN, 4},
    {12, MODE_CBC, 16, PAD_PKCS7, true, AUTH_HIDDEN, 4},
    {15, MODE_CTR, 12, PAD_NONE, false, AUTH_HIDDEN, 4},
    {16, MODE_CTR, 12, PAD_NONE, true, AUTH_HIDDEN, 4},
    {20, MODE_GCM, 12, PAD_NONE, false, AUTH_GCM, 4},
    {21, MODE_GCM, 12, PAD_NONE, true, AUTH_GCM, 4},
};

#define VERSION_COUNT (sizeof(k_versions) / sizeof(k_versions[0]))

static const kef_version_info_t *find_version(uint8_t ver) {
  for (size_t i = 0; i < VERSION_COUNT; i++) {
    if (k_versions[i].version == ver)
      return &k_versions[i];
  }
  return NULL;
}

/* ------------------------------------------------------------------ */
/*  Iteration encoding                                                 */
/* ------------------------------------------------------------------ */

void kef_encode_iterations(uint32_t effective, uint8_t out[3]) {
  uint32_t stored = effective;
  if (effective >= KEF_ITER_THRESHOLD && effective % KEF_ITER_THRESHOLD == 0 &&
      effective / KEF_ITER_THRESHOLD <= KEF_ITER_THRESHOLD) {
    stored = effective / KEF_ITER_THRESHOLD;
  }
  out[0] = (uint8_t)(stored >> 16);
  out[1] = (uint8_t)(stored >> 8);
  out[2] = (uint8_t)(stored);
}

uint32_t kef_decode_iterations(const uint8_t stored[3]) {
  uint32_t val =
      ((uint32_t)stored[0] << 16) | ((uint32_t)stored[1] << 8) | stored[2];
  return (val <= KEF_ITER_THRESHOLD) ? val * KEF_ITER_THRESHOLD : val;
}

/* ------------------------------------------------------------------ */
/*  Auth helpers                                                       */
/* ------------------------------------------------------------------ */

/* SHA256(data) truncated to auth_size bytes. */
static int compute_hidden_auth(const uint8_t *data, size_t data_len,
                               uint8_t *out, size_t auth_size) {
  uint8_t hash[CRYPTO_SHA256_SIZE];
  int rc = crypto_sha256(data, data_len, hash);
  if (rc == CRYPTO_OK)
    memcpy(out, hash, auth_size);
  secure_memzero(hash, sizeof(hash));
  return rc;
}

/* SHA256(version || iv || data || key) truncated to auth_size bytes. */
static kef_error_t compute_exposed_auth(uint8_t version, const uint8_t *iv,
                                        size_t iv_size, const uint8_t *data,
                                        size_t data_len, const uint8_t *key,
                                        uint8_t *out, size_t auth_size) {
  size_t total = 1 + iv_size + data_len + CRYPTO_AES_KEY_SIZE;
  uint8_t *buf = malloc(total);
  if (!buf)
    return KEF_ERR_ALLOC;

  size_t pos = 0;
  buf[pos++] = version;
  if (iv_size > 0) {
    memcpy(buf + pos, iv, iv_size);
    pos += iv_size;
  }
  memcpy(buf + pos, data, data_len);
  pos += data_len;
  memcpy(buf + pos, key, CRYPTO_AES_KEY_SIZE);

  uint8_t hash[CRYPTO_SHA256_SIZE];
  int rc = crypto_sha256(buf, total, hash);
  secure_memzero(buf, total);
  free(buf);

  if (rc != CRYPTO_OK) {
    secure_memzero(hash, sizeof(hash));
    return KEF_ERR_CRYPTO;
  }
  memcpy(out, hash, auth_size);
  secure_memzero(hash, sizeof(hash));
  return KEF_OK;
}

/* ------------------------------------------------------------------ */
/*  Safety checks                                                      */
/* ------------------------------------------------------------------ */

/* True if any two 16-byte blocks in data are identical (ECB weakness). */
static bool has_duplicate_blocks(const uint8_t *data, size_t len) {
  size_t nblocks = len / CRYPTO_AES_BLOCK_SIZE;
  for (size_t i = 0; i < nblocks; i++) {
    for (size_t j = i + 1; j < nblocks; j++) {
      if (memcmp(data + i * CRYPTO_AES_BLOCK_SIZE,
                 data + j * CRYPTO_AES_BLOCK_SIZE, CRYPTO_AES_BLOCK_SIZE) == 0)
        return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/*  Cipher dispatch (ECB / CBC / CTR — GCM handled inline)             */
/* ------------------------------------------------------------------ */

static int cipher_encrypt(const kef_version_info_t *vi, const uint8_t *key,
                          const uint8_t *iv, const uint8_t *in, size_t in_len,
                          uint8_t *out) {
  switch (vi->mode) {
  case MODE_ECB:
    return crypto_aes_ecb_encrypt(key, in, in_len, out);
  case MODE_CBC:
    return crypto_aes_cbc_encrypt(key, iv, in, in_len, out);
  case MODE_CTR:
    return crypto_aes_ctr(key, iv, in, in_len, out);
  default:
    return CRYPTO_ERR_INVALID_ARG;
  }
}

static int cipher_decrypt(const kef_version_info_t *vi, const uint8_t *key,
                          const uint8_t *iv, const uint8_t *in, size_t in_len,
                          uint8_t *out) {
  switch (vi->mode) {
  case MODE_ECB:
    return crypto_aes_ecb_decrypt(key, in, in_len, out);
  case MODE_CBC:
    return crypto_aes_cbc_decrypt(key, iv, in, in_len, out);
  case MODE_CTR:
    return crypto_aes_ctr(key, iv, in, in_len, out);
  default:
    return CRYPTO_ERR_INVALID_ARG;
  }
}

/* ------------------------------------------------------------------ */
/*  Padding                                                            */
/* ------------------------------------------------------------------ */

/*
 * Build the buffer that goes into the cipher.
 *
 * For HIDDEN auth the caller has already appended the auth bytes to `in`.
 * For EXPOSED / GCM no auth bytes are in `in`.
 *
 * Returns heap-allocated padded buffer via *out / *out_len.
 * Caller must free with secure_memzero + free.
 */
static kef_error_t apply_padding(kef_pad_t pad, const uint8_t *in,
                                 size_t in_len, uint8_t **out,
                                 size_t *out_len) {
  switch (pad) {
  case PAD_NUL: {
    size_t padded =
        ((in_len + CRYPTO_AES_BLOCK_SIZE - 1) / CRYPTO_AES_BLOCK_SIZE) *
        CRYPTO_AES_BLOCK_SIZE;
    if (padded == 0)
      padded = CRYPTO_AES_BLOCK_SIZE;
    uint8_t *buf = calloc(padded, 1); /* zeros = NUL padding */
    if (!buf)
      return KEF_ERR_ALLOC;
    memcpy(buf, in, in_len);
    *out = buf;
    *out_len = padded;
    return KEF_OK;
  }
  case PAD_PKCS7: {
    size_t max_len = in_len + CRYPTO_AES_BLOCK_SIZE;
    uint8_t *buf = malloc(max_len);
    if (!buf)
      return KEF_ERR_ALLOC;
    size_t padded = crypto_pkcs7_pad(in, in_len, buf, max_len);
    if (padded == 0) {
      free(buf);
      return KEF_ERR_CRYPTO;
    }
    *out = buf;
    *out_len = padded;
    return KEF_OK;
  }
  case PAD_NONE: {
    uint8_t *buf = malloc(in_len);
    if (!buf)
      return KEF_ERR_ALLOC;
    memcpy(buf, in, in_len);
    *out = buf;
    *out_len = in_len;
    return KEF_OK;
  }
  }
  return KEF_ERR_INVALID_ARG;
}

/* ------------------------------------------------------------------ */
/*  NUL-pad recovery + auth verification (decrypt side)                */
/* ------------------------------------------------------------------ */

/*
 * NUL-padded data with hidden auth.  The decrypted buffer contains:
 *   [plaintext] [auth_bytes] [NUL padding]
 *
 * Strip trailing NULs, then try matching the hidden auth while adding
 * back 0..auth_size NUL bytes (handles plaintext/auth ending with 0x00).
 */
static kef_error_t nul_unpad_verify_hidden(const uint8_t *dec, size_t dec_len,
                                           size_t auth_size,
                                           size_t *data_len_out) {
  /* Find length after stripping trailing NULs */
  size_t stripped = dec_len;
  while (stripped > 0 && dec[stripped - 1] == 0)
    stripped--;

  for (size_t nuls = 0; nuls <= auth_size; nuls++) {
    size_t candidate = stripped + nuls;
    if (candidate < auth_size)
      continue;
    if (candidate > dec_len)
      break;

    size_t dlen = candidate - auth_size;
    uint8_t hash[CRYPTO_SHA256_SIZE];
    if (crypto_sha256(dec, dlen, hash) != CRYPTO_OK) {
      secure_memzero(hash, sizeof(hash));
      return KEF_ERR_CRYPTO;
    }
    if (secure_memcmp(hash, dec + dlen, auth_size) == 0) {
      secure_memzero(hash, sizeof(hash));
      *data_len_out = dlen;
      return KEF_OK;
    }
    secure_memzero(hash, sizeof(hash));
  }
  return KEF_ERR_AUTH;
}

/*
 * NUL-padded data with exposed auth (versions 5, 10).
 * Same NUL-strip + recovery, but verification uses the exposed auth formula.
 */
static kef_error_t nul_unpad_verify_exposed(const uint8_t *dec, size_t dec_len,
                                            uint8_t version, const uint8_t *iv,
                                            size_t iv_size, const uint8_t *key,
                                            const uint8_t *expected_auth,
                                            size_t auth_size,
                                            size_t *data_len_out) {
  size_t stripped = dec_len;
  while (stripped > 0 && dec[stripped - 1] == 0)
    stripped--;

  for (size_t nuls = 0; nuls <= auth_size; nuls++) {
    size_t candidate = stripped + nuls;
    if (candidate > dec_len)
      break;

    uint8_t auth[CRYPTO_SHA256_SIZE];
    kef_error_t err = compute_exposed_auth(version, iv, iv_size, dec, candidate,
                                           key, auth, auth_size);
    if (err != KEF_OK) {
      secure_memzero(auth, sizeof(auth));
      return err;
    }
    if (secure_memcmp(auth, expected_auth, auth_size) == 0) {
      secure_memzero(auth, sizeof(auth));
      *data_len_out = candidate;
      return KEF_OK;
    }
    secure_memzero(auth, sizeof(auth));
  }
  return KEF_ERR_AUTH;
}

/* ------------------------------------------------------------------ */
/*  Header helpers                                                     */
/* ------------------------------------------------------------------ */

/* Minimum header: len_id(1) + id(1) + version(1) + iterations(3) = 6 */
#define KEF_MIN_HEADER 6

kef_error_t kef_parse_header(const uint8_t *envelope, size_t env_len,
                             const uint8_t **id_out, size_t *id_len_out,
                             uint8_t *version_out, uint32_t *iterations_out) {
  if (!envelope || env_len < KEF_MIN_HEADER || !id_out || !id_len_out)
    return KEF_ERR_INVALID_ARG;

  size_t id_len = envelope[0];
  if (id_len == 0 || id_len > KEF_MAX_ID_LEN)
    return KEF_ERR_INVALID_ARG;

  size_t header_size = 1 + id_len + 1 + 3; /* len_id + id + ver + iters */
  if (env_len < header_size)
    return KEF_ERR_ENVELOPE_TOO_SHORT;

  *id_out = envelope + 1;
  *id_len_out = id_len;
  if (version_out)
    *version_out = envelope[1 + id_len];
  if (iterations_out)
    *iterations_out = kef_decode_iterations(envelope + 1 + id_len + 1);
  return KEF_OK;
}

/* ------------------------------------------------------------------ */
/*  Encrypt                                                            */
/* ------------------------------------------------------------------ */

kef_error_t kef_encrypt(const uint8_t *id, size_t id_len, uint8_t version,
                        const uint8_t *password, size_t pw_len,
                        uint32_t iterations, const uint8_t *plaintext,
                        size_t pt_len, uint8_t **out, size_t *out_len) {
  kef_error_t err = KEF_ERR_CRYPTO;
  uint8_t key[CRYPTO_AES_KEY_SIZE];
  uint8_t iv[CRYPTO_AES_IV_SIZE]; /* large enough for CBC(16) and CTR/GCM(12) */
  uint8_t auth_buf[CRYPTO_SHA256_SIZE];
  uint8_t *compressed = NULL;
  size_t compressed_len = 0;
  uint8_t *pre_pad = NULL; /* data + hidden auth before padding */
  size_t pre_pad_len = 0;
  uint8_t *padded = NULL; /* after padding, ready for cipher */
  size_t padded_len = 0;
  uint8_t *envelope = NULL;
  int rc;

  /* --- Validate -------------------------------------------------- */
  if (!id || id_len == 0 || id_len > KEF_MAX_ID_LEN || !password ||
      pw_len == 0 || !plaintext || pt_len == 0 || !out || !out_len ||
      iterations == 0)
    return KEF_ERR_INVALID_ARG;

  const kef_version_info_t *vi = find_version(version);
  if (!vi)
    return KEF_ERR_UNSUPPORTED_VERSION;

  /* --- Derive key ------------------------------------------------ */
  rc = crypto_pbkdf2_sha256(password, pw_len, id, id_len, iterations, key,
                            CRYPTO_AES_KEY_SIZE);
  if (rc != CRYPTO_OK) {
    err = KEF_ERR_CRYPTO;
    goto cleanup;
  }

  /* --- Generate IV ----------------------------------------------- */
  memset(iv, 0, sizeof(iv));
  if (vi->iv_size > 0)
    crypto_random_bytes(iv, vi->iv_size);

  /* --- Compress -------------------------------------------------- */
  const uint8_t *work = plaintext;
  size_t work_len = pt_len;

  if (vi->compress) {
    compressed =
        mz_deflate_raw_alloc_wbits(plaintext, pt_len, &compressed_len, 10);
    if (!compressed) {
      err = KEF_ERR_COMPRESS;
      goto cleanup;
    }
    work = compressed;
    work_len = compressed_len;
  }

  /* --- Build pre-pad buffer (work + hidden auth if applicable) --- */
  if (vi->auth_type == AUTH_HIDDEN) {
    rc = compute_hidden_auth(work, work_len, auth_buf, vi->auth_size);
    if (rc != CRYPTO_OK) {
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
    pre_pad_len = work_len + vi->auth_size;
    pre_pad = malloc(pre_pad_len);
    if (!pre_pad) {
      err = KEF_ERR_ALLOC;
      goto cleanup;
    }
    memcpy(pre_pad, work, work_len);
    memcpy(pre_pad + work_len, auth_buf, vi->auth_size);
  } else {
    /* Exposed / GCM — no hidden auth appended */
    pre_pad_len = work_len;
    pre_pad = malloc(pre_pad_len);
    if (!pre_pad) {
      err = KEF_ERR_ALLOC;
      goto cleanup;
    }
    memcpy(pre_pad, work, work_len);
  }

  /* --- Pad ------------------------------------------------------- */
  err = apply_padding(vi->padding, pre_pad, pre_pad_len, &padded, &padded_len);
  if (err != KEF_OK)
    goto cleanup;

  /* --- ECB duplicate-block check --------------------------------- */
  if (vi->mode == MODE_ECB && has_duplicate_blocks(padded, padded_len)) {
    err = KEF_ERR_DUPLICATE_BLOCKS;
    goto cleanup;
  }

  /* --- Allocate envelope ----------------------------------------- */
  size_t header_size = 1 + id_len + 1 + 3;
  size_t cipher_len = padded_len;
  bool exposed = (vi->auth_type == AUTH_EXPOSED || vi->auth_type == AUTH_GCM);
  size_t env_size =
      header_size + vi->iv_size + cipher_len + (exposed ? vi->auth_size : 0);
  envelope = malloc(env_size);
  if (!envelope) {
    err = KEF_ERR_ALLOC;
    goto cleanup;
  }

  /* --- Write header ---------------------------------------------- */
  size_t pos = 0;
  envelope[pos++] = (uint8_t)id_len;
  memcpy(envelope + pos, id, id_len);
  pos += id_len;
  envelope[pos++] = version;
  kef_encode_iterations(iterations, envelope + pos);
  pos += 3;

  /* --- Write IV -------------------------------------------------- */
  if (vi->iv_size > 0) {
    memcpy(envelope + pos, iv, vi->iv_size);
    pos += vi->iv_size;
  }

  /* --- Encrypt --------------------------------------------------- */
  uint8_t *cipher_dest = envelope + pos;

  if (vi->mode == MODE_GCM) {
    uint8_t tag[CRYPTO_AES_BLOCK_SIZE];
    rc = crypto_aes_gcm_encrypt(key, iv, vi->iv_size, padded, padded_len,
                                cipher_dest, tag, vi->auth_size);
    if (rc != CRYPTO_OK) {
      secure_memzero(tag, sizeof(tag));
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
    pos += cipher_len;
    memcpy(envelope + pos, tag, vi->auth_size);
    secure_memzero(tag, sizeof(tag));
  } else {
    rc = cipher_encrypt(vi, key, iv, padded, padded_len, cipher_dest);
    if (rc != CRYPTO_OK) {
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
    pos += cipher_len;

    /* Exposed auth (versions 5, 10) */
    if (vi->auth_type == AUTH_EXPOSED) {
      err = compute_exposed_auth(version, iv, vi->iv_size, work, work_len, key,
                                 envelope + pos, vi->auth_size);
      if (err != KEF_OK)
        goto cleanup;
    }
  }

  /* --- Success --------------------------------------------------- */
  *out = envelope;
  *out_len = env_size;
  envelope = NULL; /* prevent cleanup from freeing */
  err = KEF_OK;

cleanup:
  secure_memzero(key, sizeof(key));
  secure_memzero(iv, sizeof(iv));
  secure_memzero(auth_buf, sizeof(auth_buf));
  if (compressed) {
    secure_memzero(compressed, compressed_len);
    free(compressed);
  }
  if (pre_pad) {
    secure_memzero(pre_pad, pre_pad_len);
    free(pre_pad);
  }
  if (padded) {
    secure_memzero(padded, padded_len);
    free(padded);
  }
  free(envelope);
  return err;
}

/* ------------------------------------------------------------------ */
/*  Decrypt                                                            */
/* ------------------------------------------------------------------ */

kef_error_t kef_decrypt(const uint8_t *envelope, size_t env_len,
                        const uint8_t *password, size_t pw_len, uint8_t **out,
                        size_t *out_len) {
  kef_error_t err = KEF_ERR_CRYPTO;
  uint8_t key[CRYPTO_AES_KEY_SIZE];
  uint8_t *decrypted = NULL;
  size_t cipher_len = 0;
  int rc;

  /* --- Validate -------------------------------------------------- */
  if (!envelope || env_len == 0 || !password || pw_len == 0 || !out || !out_len)
    return KEF_ERR_INVALID_ARG;

  /* --- Parse header ---------------------------------------------- */
  const uint8_t *id;
  size_t id_len;
  uint8_t version;
  uint32_t iterations;
  err =
      kef_parse_header(envelope, env_len, &id, &id_len, &version, &iterations);
  if (err != KEF_OK)
    return err;

  const kef_version_info_t *vi = find_version(version);
  if (!vi)
    return KEF_ERR_UNSUPPORTED_VERSION;

  /* --- Locate payload parts -------------------------------------- */
  size_t header_size = 1 + id_len + 1 + 3;
  size_t iv_start = header_size;

  if (iv_start + vi->iv_size > env_len)
    return KEF_ERR_ENVELOPE_TOO_SHORT;

  const uint8_t *iv = (vi->iv_size > 0) ? envelope + iv_start : NULL;
  size_t data_start = iv_start + vi->iv_size;
  size_t data_end = env_len;

  /* Extract exposed auth from end of envelope */
  const uint8_t *exposed_auth = NULL;
  bool has_exposed =
      (vi->auth_type == AUTH_EXPOSED || vi->auth_type == AUTH_GCM);
  if (has_exposed) {
    if (data_end < data_start + vi->auth_size)
      return KEF_ERR_ENVELOPE_TOO_SHORT;
    data_end -= vi->auth_size;
    exposed_auth = envelope + data_end;
  }

  const uint8_t *ciphertext = envelope + data_start;
  cipher_len = data_end - data_start;

  if (cipher_len == 0)
    return KEF_ERR_ENVELOPE_TOO_SHORT;

  /* Block ciphers need aligned input */
  if ((vi->mode == MODE_ECB || vi->mode == MODE_CBC) &&
      cipher_len % CRYPTO_AES_BLOCK_SIZE != 0)
    return KEF_ERR_ENVELOPE_TOO_SHORT;

  /* --- Derive key ------------------------------------------------ */
  rc = crypto_pbkdf2_sha256(password, pw_len, id, id_len, iterations, key,
                            CRYPTO_AES_KEY_SIZE);
  if (rc != CRYPTO_OK) {
    err = KEF_ERR_CRYPTO;
    goto cleanup;
  }

  /* --- Decrypt --------------------------------------------------- */
  decrypted = malloc(cipher_len);
  if (!decrypted) {
    err = KEF_ERR_ALLOC;
    goto cleanup;
  }

  if (vi->mode == MODE_GCM) {
    rc = crypto_aes_gcm_decrypt(key, iv, vi->iv_size, ciphertext, cipher_len,
                                decrypted, exposed_auth, vi->auth_size);
    if (rc == CRYPTO_ERR_AUTH_FAILED) {
      err = KEF_ERR_AUTH;
      goto cleanup;
    }
    if (rc != CRYPTO_OK) {
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
  } else {
    rc = cipher_decrypt(vi, key, iv, ciphertext, cipher_len, decrypted);
    if (rc != CRYPTO_OK) {
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
  }

  /* --- Unpad + verify auth --------------------------------------- */
  size_t plain_len = 0;

  if (vi->auth_type == AUTH_GCM) {
    /* GCM tag already verified above */
    plain_len = cipher_len;

  } else if (vi->padding == PAD_NUL) {
    if (vi->auth_type == AUTH_HIDDEN) {
      err = nul_unpad_verify_hidden(decrypted, cipher_len, vi->auth_size,
                                    &plain_len);
    } else {
      err = nul_unpad_verify_exposed(decrypted, cipher_len, version, iv,
                                     vi->iv_size, key, exposed_auth,
                                     vi->auth_size, &plain_len);
    }
    if (err != KEF_OK)
      goto cleanup;

  } else if (vi->padding == PAD_PKCS7) {
    size_t unpadded = crypto_pkcs7_unpad(decrypted, cipher_len);
    if (unpadded == 0 || unpadded < vi->auth_size) {
      err = KEF_ERR_AUTH;
      goto cleanup;
    }
    plain_len = unpadded - vi->auth_size;

    /* Verify hidden auth */
    uint8_t hash[CRYPTO_SHA256_SIZE];
    rc = crypto_sha256(decrypted, plain_len, hash);
    if (rc != CRYPTO_OK) {
      secure_memzero(hash, sizeof(hash));
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
    if (secure_memcmp(hash, decrypted + plain_len, vi->auth_size) != 0) {
      secure_memzero(hash, sizeof(hash));
      err = KEF_ERR_AUTH;
      goto cleanup;
    }
    secure_memzero(hash, sizeof(hash));

  } else {
    /* PAD_NONE with hidden auth (CTR modes) */
    if (cipher_len < vi->auth_size) {
      err = KEF_ERR_AUTH;
      goto cleanup;
    }
    plain_len = cipher_len - vi->auth_size;

    uint8_t hash[CRYPTO_SHA256_SIZE];
    rc = crypto_sha256(decrypted, plain_len, hash);
    if (rc != CRYPTO_OK) {
      secure_memzero(hash, sizeof(hash));
      err = KEF_ERR_CRYPTO;
      goto cleanup;
    }
    if (secure_memcmp(hash, decrypted + plain_len, vi->auth_size) != 0) {
      secure_memzero(hash, sizeof(hash));
      err = KEF_ERR_AUTH;
      goto cleanup;
    }
    secure_memzero(hash, sizeof(hash));
  }

  /* --- Decompress ------------------------------------------------ */
  if (vi->compress) {
    size_t dec_len = 0;
    uint8_t *decompressed =
        mz_inflate_raw_alloc(decrypted, plain_len, &dec_len);
    if (!decompressed) {
      err = KEF_ERR_DECOMPRESS;
      goto cleanup;
    }
    *out = decompressed;
    *out_len = dec_len;
  } else {
    uint8_t *result = malloc(plain_len);
    if (!result) {
      err = KEF_ERR_ALLOC;
      goto cleanup;
    }
    memcpy(result, decrypted, plain_len);
    *out = result;
    *out_len = plain_len;
  }
  err = KEF_OK;

cleanup:
  secure_memzero(key, sizeof(key));
  if (decrypted) {
    secure_memzero(decrypted, cipher_len);
    free(decrypted);
  }
  return err;
}

/* ------------------------------------------------------------------ */
/*  Envelope detection                                                 */
/* ------------------------------------------------------------------ */

bool kef_is_envelope(const uint8_t *data, size_t len) {
  if (!data || len < KEF_MIN_HEADER)
    return false;

  const uint8_t *id;
  size_t id_len;
  uint8_t version;
  uint32_t iterations;
  if (kef_parse_header(data, len, &id, &id_len, &version, &iterations) !=
      KEF_OK)
    return false;

  const kef_version_info_t *vi = find_version(version);
  if (!vi)
    return false;

  /* Minimum payload: header + IV + minimum ciphertext + exposed auth */
  size_t header_size = 1 + id_len + 1 + 3;
  size_t min_cipher = (vi->mode == MODE_ECB || vi->mode == MODE_CBC)
                          ? CRYPTO_AES_BLOCK_SIZE
                          : 1;
  bool has_exposed =
      (vi->auth_type == AUTH_EXPOSED || vi->auth_type == AUTH_GCM);
  size_t min_total = header_size + vi->iv_size + min_cipher +
                     (has_exposed ? vi->auth_size : 0);

  return len >= min_total;
}

/* ------------------------------------------------------------------ */
/*  Error strings                                                      */
/* ------------------------------------------------------------------ */

const char *kef_error_str(kef_error_t err) {
  switch (err) {
  case KEF_OK:
    return "OK";
  case KEF_ERR_INVALID_ARG:
    return "invalid argument";
  case KEF_ERR_UNSUPPORTED_VERSION:
    return "unsupported KEF version";
  case KEF_ERR_ALLOC:
    return "memory allocation failed";
  case KEF_ERR_CRYPTO:
    return "cryptographic operation failed";
  case KEF_ERR_AUTH:
    return "authentication failed";
  case KEF_ERR_COMPRESS:
    return "compression failed";
  case KEF_ERR_DECOMPRESS:
    return "decompression failed";
  case KEF_ERR_ENVELOPE_TOO_SHORT:
    return "envelope too short";
  case KEF_ERR_DUPLICATE_BLOCKS:
    return "duplicate ECB blocks detected";
  }
  return "unknown error";
}
