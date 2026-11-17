/*
 * Nonce cache tests (core/nonce_cache.c).
 *
 * The bip_nonces_cache signer on Kern's backend: libwally's MuSig2,
 * mbedTLS SHA-256 and sessions in the simulator's NVS, under a fresh temp
 * directory, as MuSig2 signing keeps them between its two rounds. The values
 * are the nonce cache BIP draft's test vectors (bip_nonces_cache/test_vectors).
 */

#include "core/nonce_cache.h"
#include "sim_nvs.h"
#include <nvs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_musig.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* nonce.json and musig2_signing.json */
#define SECRET_A                                                               \
  "6b85ef3dff7bb6fea77cd2b8662cb19b7a6895139e8e86e307e1875e456dab7e"
#define SECRET_B                                                               \
  "5485cb5d03981cc3bd989290a6be33ca392c013279a5c3c3fd10a1cae57e1460"
#define SK_A "ba36730b8ca1fb220a1b35736c0091cc9bd0ecfa9d87c52ed3750f4cffa7445b"
#define PK_A                                                                   \
  "021936c5746965205425e26e6e19e3c2eeb91378843363de0267caf2f968991a12"
#define SK_B "54adb8575a8947c289dd1223d5777429765b0317f5f4dc0df0e7ba8f449d2603"
#define PK_B                                                                   \
  "028b43c3be504aee9a0001905774a3d0e8f8392b668223336a50cd227ca7f91904"
#define NONCE_A_0_0                                                            \
  "0344b9a89f4636ec139b31380d614afbcde1f1469095b3cc603e9558e3ae6e0613"         \
  "03e4c43e42b40fc9b046d88e7b2412606c592935287e92a5ec8847a3fe3c8bdcab"
#define NONCE_A_1_0                                                            \
  "0276cfe291bc50c29859f8738b8c761472131ecf35ed7b92ee051ec64db16c56f4"         \
  "02168db564eb109e1d0145df593947c74e07ff2ddd5fafddb17639206542795551"
#define NONCE_A_0_1                                                            \
  "02f8a183a65d7be47916663dbfa45349c589afef5bacd8f64b1d5c47e472091a43"         \
  "0365e690f58195af734871374fc970616f3d2f264ce31684441bcf9a7476c17a4d"
#define NONCE_B_0_0                                                            \
  "037f5d7ac2b57b2ec40a2b000ac080a084cfb273e7f604629cdb6a14589658b4b4"         \
  "027bb594d43cd6330351fc0f0dcacd4e94cff69b877b9e606b4296a8de67545e53"
#define AGGNONCE                                                               \
  "02729b58c1772d16a5a8521dd115efc7da7034bf7ad5e55f6dbd460e8c551942af"         \
  "02609aac6b5d08912d07ab60f915745b7bfb998962c9dc7833497e96ac08efccc8"
#define MSG "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d"
#define PSIG_A                                                                 \
  "6490a1dbc816a01db4340a05e9e51a14cc6cbe5abcbd23a50b0723ca3acb628c"
#define PSIG_B                                                                 \
  "3696113d4bf29a72098c7ab6c8ea0ef428f9b554da718ee01d13ba8e7f135ac7"
#define AGGPK "edc088407bc106814307f3002afce9bd44f672c833bdc64bea1520bf243c6833"
#define SIG                                                                    \
  "c69f9a646539fec456fb5f7c4372eb3d0ff4e143a9c2421d71a61bc873c4a06d"           \
  "9b26b31914093a8fbdc084bcb2cf2908f56673af972eb285281ade58b9debd53"

#define STORED_SESSION_LEN 44

static void hex(const char *text, unsigned char *out, size_t len) {
  size_t written = 0;
  if (wally_hex_to_bytes(text, out, len, &written) != WALLY_OK ||
      written != len) {
    printf("bad test hex %s\n", text);
    exit(1);
  }
}

static bool equals_hex(const unsigned char *bytes, size_t len,
                       const char *expected) {
  unsigned char decoded[BNC_PUBNONCE_LEN];
  hex(expected, decoded, len);
  return memcmp(bytes, decoded, len) == 0;
}

static void session_id(uint8_t id, uint8_t *out) {
  memset(out, id, BNC_SESSION_ID_LEN);
}

/* Round 1 under the session ID of bytes `id`, `fresh` the new secret. */
static int32_t round_one(uint8_t id, const char *fresh, bnc_secret **secret) {
  uint8_t sid[BNC_SESSION_ID_LEN];
  unsigned char fresh_bytes[BNC_SECRET_LEN];
  session_id(id, sid);
  hex(fresh, fresh_bytes, sizeof(fresh_bytes));
  return bnc_begin_round_one(nonce_cache_signer(), sid, fresh_bytes, secret);
}

static int32_t held_session(uint8_t id, bnc_secret **secret) {
  uint8_t sid[BNC_SESSION_ID_LEN];
  session_id(id, sid);
  return bnc_held_session(nonce_cache_signer(), sid, NULL, secret);
}

static int32_t round_two(uint8_t id, bnc_secret **secret) {
  uint8_t sid[BNC_SESSION_ID_LEN];
  session_id(id, sid);
  return bnc_begin_round_two(nonce_cache_signer(), sid, secret);
}

/* The session's nonce of input `input`, key expression `key_expression` and
 * the key sk/pk is `expected`. */
static bool nonce_is(const bnc_secret *secret, uint32_t input,
                     uint32_t key_expression, const char *sk, const char *pk,
                     const char *expected) {
  unsigned char sk_bytes[BNC_SECRET_KEY_LEN], pk_bytes[BNC_PUBLIC_KEY_LEN];
  unsigned char nonce[BNC_PUBNONCE_LEN];
  hex(sk, sk_bytes, sizeof(sk_bytes));
  hex(pk, pk_bytes, sizeof(pk_bytes));
  return bnc_cached_nonce(nonce_cache_signer(), secret, input, key_expression,
                          sk_bytes, pk_bytes, nonce) == BNC_OK &&
         equals_hex(nonce, sizeof(nonce), expected);
}

static size_t stored_sessions(void) {
  nvs_handle_t handle;
  uint8_t blob[NONCE_CACHE_MAX_SESSIONS * STORED_SESSION_LEN];
  size_t len = sizeof(blob);
  if (nvs_open("noncecache", NVS_READONLY, &handle) != 0)
    return SIZE_MAX;
  esp_err_t err = nvs_get_blob(handle, "sessions", blob, &len);
  nvs_close(handle);
  if (err == ESP_ERR_NVS_NOT_FOUND)
    return 0;
  return err == ESP_OK ? len / STORED_SESSION_LEN : SIZE_MAX;
}

static void test_draft_vectors(void) {
  bnc_secret *secret = NULL;
  check("round 1 stores a new session",
        round_one(0xa1, SECRET_A, &secret) == BNC_OK);
  check("nonce of input 0, key expression 0",
        nonce_is(secret, 0, 0, SK_A, PK_A, NONCE_A_0_0));
  check("nonce of input 1, key expression 0",
        nonce_is(secret, 1, 0, SK_A, PK_A, NONCE_A_1_0));
  check("nonce of input 0, key expression 1",
        nonce_is(secret, 0, 1, SK_A, PK_A, NONCE_A_0_1));
  check("another key at the same position gets another nonce",
        nonce_is(secret, 0, 0, SK_B, PK_B, NONCE_B_0_0));
  bnc_secret_free(secret);
  check("the session is stored", stored_sessions() == 1);
}

static void test_held_session(void) {
  bnc_secret *secret = NULL;
  check("a held session is read without being taken",
        held_session(0xa1, &secret) == BNC_OK &&
            nonce_is(secret, 0, 0, SK_A, PK_A, NONCE_A_0_0) &&
            stored_sessions() == 1);
  bnc_secret_free(secret);
  secret = NULL;
  check("round 1 again replaces the session with a new secret",
        round_one(0xa1, SECRET_B, &secret) == BNC_OK &&
            !nonce_is(secret, 0, 0, SK_A, PK_A, NONCE_A_0_0) &&
            stored_sessions() == 1);
  bnc_secret_free(secret);
  check("a session never stored is not held",
        held_session(0xb0, &(bnc_secret *){NULL}) == BNC_ERR_UNKNOWN_SESSION);
}

/* musig2_signing.json: A signs in round 2 with its round 1 nonce, no
 * tweaks. */
static void test_musig2_signing(void) {
  bnc_secret *secret = NULL;
  check("signer A's round 1 nonce",
        round_one(0xc1, SECRET_A, &secret) == BNC_OK &&
            nonce_is(secret, 0, 0, SK_A, PK_A, NONCE_A_0_0));
  bnc_secret_free(secret);
  secret = NULL;

  unsigned char pubkeys[2 * BNC_PUBLIC_KEY_LEN], xonly[32], msg[32];
  unsigned char aggnonce_bytes[BNC_PUBNONCE_LEN];
  struct wally_musig_keyagg_cache *cache = NULL;
  struct wally_musig_aggnonce *aggnonce = NULL;
  struct wally_musig_session *session = NULL;
  hex(PK_A, pubkeys, BNC_PUBLIC_KEY_LEN);
  hex(PK_B, pubkeys + BNC_PUBLIC_KEY_LEN, BNC_PUBLIC_KEY_LEN);
  hex(AGGNONCE, aggnonce_bytes, sizeof(aggnonce_bytes));
  hex(MSG, msg, sizeof(msg));
  bool context_ok =
      wally_musig_pubkey_agg(pubkeys, sizeof(pubkeys), xonly, sizeof(xonly),
                             &cache) == WALLY_OK &&
      equals_hex(xonly, sizeof(xonly), AGGPK) &&
      wally_musig_aggnonce_parse(aggnonce_bytes, sizeof(aggnonce_bytes),
                                 &aggnonce) == WALLY_OK &&
      wally_musig_nonce_process(aggnonce, msg, sizeof(msg), cache, NULL, 0,
                                &session) == WALLY_OK;
  check("session context of the vector", context_ok);

  check("round 2 takes the session", round_two(0xc1, &secret) == BNC_OK);
  check("a taken session is deleted",
        round_two(0xc1, &(bnc_secret *){NULL}) == BNC_ERR_UNKNOWN_SESSION);

  nonce_cache_sign_context_t context = {.keyagg_cache = cache,
                                        .session = session};
  bnc_musig_slot slot = {.input_index = 0, .key_expression_index = 0};
  unsigned char sk[BNC_SECRET_KEY_LEN], partial_sig[BNC_PARTIAL_SIG_LEN];
  hex(PK_A, slot.participant, sizeof(slot.participant));
  hex(NONCE_A_1_0, slot.pubnonce, sizeof(slot.pubnonce));
  hex(SK_A, sk, sizeof(sk));
  check("a nonce of another position is refused",
        bnc_sign_musig(nonce_cache_signer(), secret, &slot, sk, &context,
                       partial_sig) == BNC_ERR_PUBNONCE_MISMATCH);
  hex(NONCE_A_0_0, slot.pubnonce, sizeof(slot.pubnonce));
  check("partial signature of signer A",
        bnc_sign_musig(nonce_cache_signer(), secret, &slot, sk, &context,
                       partial_sig) == BNC_OK &&
            equals_hex(partial_sig, sizeof(partial_sig), PSIG_A));
  bnc_secret_free(secret);

  unsigned char partial_sigs[2 * BNC_PARTIAL_SIG_LEN], sig[64];
  memcpy(partial_sigs, partial_sig, BNC_PARTIAL_SIG_LEN);
  hex(PSIG_B, partial_sigs + BNC_PARTIAL_SIG_LEN, BNC_PARTIAL_SIG_LEN);
  check("both partial signatures aggregate to the vector's signature",
        wally_musig_partial_sig_agg(partial_sigs, sizeof(partial_sigs), 2,
                                    session, sig, sizeof(sig)) == WALLY_OK &&
            equals_hex(sig, sizeof(sig), SIG));
  wally_musig_session_free(session);
  wally_musig_aggnonce_free(aggnonce);
  wally_musig_keyagg_cache_free(cache);
}

static void test_eviction(void) {
  size_t held = stored_sessions();
  check("sessions held before filling the store",
        held > 0 && held < NONCE_CACHE_MAX_SESSIONS);
  bool stored = true;
  for (uint8_t id = 0xe0; id < 0xe0 + NONCE_CACHE_MAX_SESSIONS; id++) {
    bnc_secret *secret = NULL;
    stored = round_one(id, SECRET_A, &secret) == BNC_OK && stored;
    bnc_secret_free(secret);
  }
  check("the store keeps at most its capacity",
        stored && stored_sessions() == NONCE_CACHE_MAX_SESSIONS);
  bnc_secret *secret = NULL;
  check("the oldest session is evicted",
        held_session(0xa1, &secret) == BNC_ERR_UNKNOWN_SESSION);
  check("the newest session is held", held_session(0xef, &secret) == BNC_OK);
  bnc_secret_free(secret);
}

static void test_erase(void) {
  check("erasing deletes every session",
        nonce_cache_erase() && stored_sessions() == 0);
  bnc_secret *secret = NULL;
  check("an erased session is no longer held",
        held_session(0xef, &secret) == BNC_ERR_UNKNOWN_SESSION);
}

int main(void) {
  char dir[] = "/tmp/kern_nonce_cache_XXXXXX";
  if (!mkdtemp(dir)) {
    perror("mkdtemp");
    return 1;
  }
  sim_nvs_set_data_dir(dir);
  printf("=== nonce_cache tests ===\n\n");
  check("signer sets up", nonce_cache_signer() != NULL);
  test_draft_vectors();
  test_held_session();
  test_musig2_signing();
  test_eviction();
  test_erase();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
