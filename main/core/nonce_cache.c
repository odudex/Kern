#include "nonce_cache.h"

#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include "key.h"
#include <esp_log.h>
#include <nvs.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

static const char *TAG = "nonce_cache";

#define NVS_NAMESPACE "noncecache"
#define NVS_KEY_SESSIONS "sessions"
#define SEQUENCE_LEN 8
/* A stored session: its ID, creation order (little endian) and secret. */
#define STORED_SESSION_LEN (BNC_SESSION_ID_LEN + SEQUENCE_LEN + BNC_SECRET_LEN)

typedef struct {
  uint8_t session_id[BNC_SESSION_ID_LEN];
  bnc_record record;
} stored_session_t;

/* The NVS blob, loaded for one store callback and wiped when it returns, so a
 * session secret is in RAM only while the binding uses it. */
typedef struct {
  stored_session_t sessions[NONCE_CACHE_MAX_SESSIONS];
  size_t len;
} session_table_t;

static nvs_handle_t sessions_nvs;
static bool sessions_nvs_open;
static bnc_signer *signer;

/* SHA-256 cannot fail on a valid context, and the binding's backend has no
 * way to report it: a failure here is a broken device, never a hash to use. */
static void sha256_cb(void *ctx, const bnc_bytes *parts, size_t parts_len,
                      uint8_t *out) {
  (void)ctx;
  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  size_t out_len = 0;
  bool ok = psa_crypto_init() == PSA_SUCCESS &&
            psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS;
  for (size_t i = 0; ok && i < parts_len; i++)
    ok = psa_hash_update(&op, parts[i].ptr, parts[i].len) == PSA_SUCCESS;
  ok = ok && psa_hash_finish(&op, out, 32, &out_len) == PSA_SUCCESS &&
       out_len == 32;
  psa_hash_abort(&op);
  if (!ok) {
    ESP_LOGE(TAG, "SHA-256 failed");
    abort();
  }
}

static int32_t nonce_gen_cb(void *ctx, const uint8_t *rand,
                            const uint8_t *secret_key,
                            const uint8_t *public_key, void **secnonce_out,
                            uint8_t *pubnonce_out) {
  (void)ctx;
  struct wally_musig_secnonce *secnonce = NULL;
  struct wally_musig_pubnonce *pubnonce = NULL;
  int ret = wally_musig_nonce_gen(
      rand, BNC_HASH_LEN, secret_key, BNC_SECRET_KEY_LEN, public_key,
      BNC_PUBLIC_KEY_LEN, NULL, NULL, 0, NULL, 0, &secnonce, &pubnonce);
  if (ret == WALLY_OK)
    ret = wally_musig_pubnonce_serialize(pubnonce, pubnonce_out,
                                         BNC_PUBNONCE_LEN);
  wally_musig_pubnonce_free(pubnonce);
  if (ret != WALLY_OK) {
    wally_musig_secnonce_free(secnonce);
    return -1;
  }
  *secnonce_out = secnonce;
  return 0;
}

static int32_t partial_sign_cb(void *ctx, void *secnonce,
                               const uint8_t *secret_key, const void *context,
                               uint8_t *partial_sig_out) {
  (void)ctx;
  const nonce_cache_sign_context_t *sign_context = context;
  struct wally_musig_partial_sig *partial_sig = NULL;
  int ret = wally_musig_partial_sign(secnonce, secret_key, BNC_SECRET_KEY_LEN,
                                     sign_context->keyagg_cache,
                                     sign_context->session, &partial_sig);
  if (ret == WALLY_OK)
    ret = wally_musig_partial_sig_serialize(partial_sig, partial_sig_out,
                                            BNC_PARTIAL_SIG_LEN);
  wally_musig_partial_sig_free(partial_sig);
  return ret == WALLY_OK ? 0 : -1;
}

static void secnonce_free_cb(void *ctx, void *secnonce) {
  (void)ctx;
  wally_musig_secnonce_free(secnonce);
}

static void table_wipe(session_table_t *table) {
  secure_memzero(table, sizeof(*table));
}

static bool table_load(session_table_t *table) {
  uint8_t blob[NONCE_CACHE_MAX_SESSIONS * STORED_SESSION_LEN];
  size_t blob_len = sizeof(blob);
  memset(table, 0, sizeof(*table));
  esp_err_t err = nvs_get_blob(sessions_nvs, NVS_KEY_SESSIONS, blob, &blob_len);
  if (err == ESP_ERR_NVS_NOT_FOUND)
    return true;
  if (err != ESP_OK || blob_len % STORED_SESSION_LEN != 0) {
    ESP_LOGE(TAG, "Session store unreadable (%d)", err);
    secure_memzero(blob, sizeof(blob));
    return false;
  }
  table->len = blob_len / STORED_SESSION_LEN;
  for (size_t i = 0; i < table->len; i++) {
    const uint8_t *stored = blob + i * STORED_SESSION_LEN;
    stored_session_t *session = &table->sessions[i];
    memcpy(session->session_id, stored, BNC_SESSION_ID_LEN);
    for (size_t b = 0; b < SEQUENCE_LEN; b++)
      session->record.sequence |= (uint64_t)stored[BNC_SESSION_ID_LEN + b]
                                  << (8 * b);
    memcpy(session->record.secret, stored + BNC_SESSION_ID_LEN + SEQUENCE_LEN,
           BNC_SECRET_LEN);
  }
  secure_memzero(blob, sizeof(blob));
  return true;
}

/* Written, not committed: the binding's flush commits. */
static bool table_save(const session_table_t *table) {
  if (table->len == 0) {
    esp_err_t err = nvs_erase_key(sessions_nvs, NVS_KEY_SESSIONS);
    return err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND;
  }
  uint8_t blob[NONCE_CACHE_MAX_SESSIONS * STORED_SESSION_LEN];
  for (size_t i = 0; i < table->len; i++) {
    uint8_t *stored = blob + i * STORED_SESSION_LEN;
    const stored_session_t *session = &table->sessions[i];
    memcpy(stored, session->session_id, BNC_SESSION_ID_LEN);
    for (size_t b = 0; b < SEQUENCE_LEN; b++)
      stored[BNC_SESSION_ID_LEN + b] =
          (uint8_t)(session->record.sequence >> (8 * b));
    memcpy(stored + BNC_SESSION_ID_LEN + SEQUENCE_LEN, session->record.secret,
           BNC_SECRET_LEN);
  }
  esp_err_t err = nvs_set_blob(sessions_nvs, NVS_KEY_SESSIONS, blob,
                               table->len * STORED_SESSION_LEN);
  secure_memzero(blob, sizeof(blob));
  return err == ESP_OK;
}

/* The position of the session held under `session_id`, or table->len. */
static size_t table_find(const session_table_t *table,
                         const uint8_t *session_id) {
  for (size_t i = 0; i < table->len; i++) {
    if (memcmp(table->sessions[i].session_id, session_id, BNC_SESSION_ID_LEN) ==
        0)
      return i;
  }
  return table->len;
}

static int32_t store_get(void *ctx, const uint8_t *session_id,
                         bnc_record *record_out, bool *found_out) {
  (void)ctx;
  session_table_t table;
  if (!table_load(&table))
    return -1;
  size_t i = table_find(&table, session_id);
  *found_out = i < table.len;
  if (*found_out)
    *record_out = table.sessions[i].record;
  table_wipe(&table);
  return 0;
}

static int32_t store_put(void *ctx, const uint8_t *session_id,
                         const bnc_record *record) {
  (void)ctx;
  session_table_t table;
  if (!table_load(&table))
    return -1;
  size_t i = table_find(&table, session_id);
  bool ok = i < NONCE_CACHE_MAX_SESSIONS;
  if (ok) {
    memcpy(table.sessions[i].session_id, session_id, BNC_SESSION_ID_LEN);
    table.sessions[i].record = *record;
    if (i == table.len)
      table.len++;
    ok = table_save(&table);
  }
  table_wipe(&table);
  return ok ? 0 : -1;
}

static int32_t store_remove(void *ctx, const uint8_t *session_id) {
  (void)ctx;
  session_table_t table;
  if (!table_load(&table))
    return -1;
  size_t i = table_find(&table, session_id);
  bool ok = true;
  if (i < table.len) {
    memmove(&table.sessions[i], &table.sessions[i + 1],
            (table.len - i - 1) * sizeof(table.sessions[0]));
    table.len--;
    ok = table_save(&table);
  }
  table_wipe(&table);
  return ok ? 0 : -1;
}

static int32_t store_len(void *ctx, size_t *len_out) {
  (void)ctx;
  session_table_t table;
  if (!table_load(&table))
    return -1;
  *len_out = table.len;
  table_wipe(&table);
  return 0;
}

static int32_t store_at(void *ctx, size_t index, uint8_t *session_id_out,
                        bnc_record *record_out) {
  (void)ctx;
  session_table_t table;
  if (!table_load(&table))
    return -1;
  bool ok = index < table.len;
  if (ok) {
    memcpy(session_id_out, table.sessions[index].session_id,
           BNC_SESSION_ID_LEN);
    *record_out = table.sessions[index].record;
  }
  table_wipe(&table);
  return ok ? 0 : -1;
}

static int32_t store_flush(void *ctx) {
  (void)ctx;
  return nvs_commit(sessions_nvs) == ESP_OK ? 0 : -1;
}

/* One handle for the signer and the erase, so both see the same store. */
static bool open_sessions_nvs(void) {
  if (!sessions_nvs_open)
    sessions_nvs_open =
        nvs_open(NVS_NAMESPACE, NVS_READWRITE, &sessions_nvs) == ESP_OK;
  if (!sessions_nvs_open)
    ESP_LOGE(TAG, "Failed to open the session store");
  return sessions_nvs_open;
}

bnc_signer *nonce_cache_signer(void) {
  if (signer)
    return signer;
  if (!open_sessions_nvs())
    return NULL;
  const bnc_crypto crypto = {
      .ctx = NULL,
      .sha256 = sha256_cb,
      .nonce_gen = nonce_gen_cb,
      .partial_sign = partial_sign_cb,
      .secnonce_free = secnonce_free_cb,
  };
  const bnc_store store = {
      .ctx = NULL,
      .capacity = NONCE_CACHE_MAX_SESSIONS,
      .get = store_get,
      .put = store_put,
      .remove = store_remove,
      .len = store_len,
      .at = store_at,
      .flush = store_flush,
  };
  if (bnc_signer_new(&crypto, &store, &signer) != BNC_OK)
    signer = NULL;
  return signer;
}

bool nonce_cache_erase(void) {
  return open_sessions_nvs() && nvs_erase_all(sessions_nvs) == ESP_OK &&
         nvs_commit(sessions_nvs) == ESP_OK;
}

bool nonce_cache_fresh_secret(uint8_t *secret_out) {
  return crypto_random_bytes(secret_out, BNC_SECRET_LEN) == CRYPTO_OK;
}

/* A drawn session ID must name a new session, so its reference is answered. */
#define SESSION_ID_DRAWS 8

static bool draw_session_id(bnc_signer *signer, uint8_t *session_id) {
  for (int i = 0; i < SESSION_ID_DRAWS; i++) {
    bnc_secret *held = NULL;
    if (crypto_random_bytes(session_id, BNC_SESSION_ID_LEN) != CRYPTO_OK)
      return false;
    int32_t status = bnc_held_session(signer, session_id, NULL, &held);
    bnc_secret_free(held);
    if (status == BNC_ERR_UNKNOWN_SESSION)
      return true;
    if (status != BNC_OK)
      return false;
  }
  return false;
}

static nonce_cache_result_t issue_result(int32_t status) {
  switch (status) {
  case BNC_OK:
    return NONCE_CACHE_OK;
  case BNC_ERR_UNKNOWN_SESSION:
  case BNC_ERR_SESSION_REF_MISMATCH:
    return NONCE_CACHE_ERR_SESSION;
  case BNC_ERR_INVALID_BOOL:
  case BNC_ERR_BUFFER_LENGTH:
  case BNC_ERR_NO_INPUTS:
  case BNC_ERR_INVALID_RANGE:
    return NONCE_CACHE_ERR_INVALID;
  default:
    return NONCE_CACHE_ERR_INTERNAL;
  }
}

nonce_cache_result_t nonce_cache_issue(bnc_issuance *request, bool draw_session,
                                       const uint32_t *path, size_t path_len,
                                       uint8_t *nonces_out, size_t nonces_len,
                                       nonce_cache_issued_t *issued_out) {
  bnc_signer *signer = nonce_cache_signer();
  if (!signer ||
      (draw_session && !draw_session_id(signer, request->session_id)))
    return NONCE_CACHE_ERR_INTERNAL;
  struct ext_key *key = NULL;
  if (!path || path_len == 0 ||
      !key_get_derived_key_components(path, path_len, &key))
    return NONCE_CACHE_ERR_INVALID;
  uint8_t fresh[BNC_SECRET_LEN];
  int32_t status = BNC_ERR_CRYPTO;
  if (nonce_cache_fresh_secret(fresh))
    status = bnc_issue(signer, request, fresh, key->priv_key + 1, key->pub_key,
                       issued_out->session_ref, &issued_out->new_session,
                       nonces_out, nonces_len);
  secure_memzero(fresh, sizeof(fresh));
  bip32_key_free(key);
  memcpy(issued_out->session_id, request->session_id, BNC_SESSION_ID_LEN);
  return issue_result(status);
}
