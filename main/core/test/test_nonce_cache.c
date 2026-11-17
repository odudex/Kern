/*
 * Nonce cache tests (core/nonce_cache.c).
 *
 * The bip_nonces_cache signer on Kern's backend: libwally's MuSig2,
 * mbedTLS SHA-256 and sessions in the simulator's NVS, under a fresh temp
 * directory. The values are the nonce cache BIP draft's test vectors
 * (bip_nonces_cache/test_vectors).
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

/* nonce.json, session_ref.json and musig2_signing.json */
#define SECRET_A                                                               \
  "6b85ef3dff7bb6fea77cd2b8662cb19b7a6895139e8e86e307e1875e456dab7e"
#define SECRET_B                                                               \
  "5485cb5d03981cc3bd989290a6be33ca392c013279a5c3c3fd10a1cae57e1460"
#define REF_A "c29ef5ec"
#define REF_B "9981509f"
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

typedef struct {
  int32_t status;
  uint8_t session_ref[BNC_SESSION_REF_LEN];
  bool new_session;
  uint8_t nonces[4 * BNC_PUBNONCE_LEN];
} issued_t;

/* Issues `inputs` inputs and the key expressions start..=end, for the key
 * sk/pk; `fresh` is the secret a new session gets. */
static issued_t issue(uint8_t id, const char *ref, uint32_t inputs,
                      uint32_t start, uint32_t end, const char *fresh,
                      const char *sk, const char *pk) {
  issued_t issued = {0};
  bnc_issuance request = {.inputs = inputs, .start = start, .end = end};
  unsigned char fresh_bytes[BNC_SECRET_LEN], sk_bytes[BNC_SECRET_KEY_LEN],
      pk_bytes[BNC_PUBLIC_KEY_LEN];
  memset(request.session_id, id, sizeof(request.session_id));
  if (ref) {
    request.has_session_ref = 1;
    hex(ref, request.session_ref, sizeof(request.session_ref));
  }
  hex(fresh, fresh_bytes, sizeof(fresh_bytes));
  hex(sk, sk_bytes, sizeof(sk_bytes));
  hex(pk, pk_bytes, sizeof(pk_bytes));
  issued.status =
      bnc_issue(nonce_cache_signer(), &request, fresh_bytes, sk_bytes, pk_bytes,
                issued.session_ref, &issued.new_session, issued.nonces,
                (size_t)(end - start + 1) * inputs * BNC_PUBNONCE_LEN);
  return issued;
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
  issued_t issued = issue(0xa1, NULL, 2, 0, 1, SECRET_A, SK_A, PK_A);
  check("a new session issues", issued.status == BNC_OK && issued.new_session);
  check("session reference of the secret",
        equals_hex(issued.session_ref, BNC_SESSION_REF_LEN, REF_A));
  check("nonce of input 0, key expression 0",
        equals_hex(issued.nonces, BNC_PUBNONCE_LEN, NONCE_A_0_0));
  check("nonce of input 1, key expression 0",
        equals_hex(issued.nonces + BNC_PUBNONCE_LEN, BNC_PUBNONCE_LEN,
                   NONCE_A_1_0));
  check("nonce of input 0, key expression 1",
        equals_hex(issued.nonces + 2 * BNC_PUBNONCE_LEN, BNC_PUBNONCE_LEN,
                   NONCE_A_0_1));
  check("the session is stored", stored_sessions() == 1);

  issued = issue(0xa2, NULL, 1, 0, 0, SECRET_A, SK_B, PK_B);
  check("another key at the same position gets another nonce",
        issued.status == BNC_OK &&
            equals_hex(issued.nonces, BNC_PUBNONCE_LEN, NONCE_B_0_0));

  issued = issue(0xa3, NULL, 1, 0, 0, SECRET_B, SK_A, PK_A);
  check("session reference of another secret",
        issued.status == BNC_OK &&
            equals_hex(issued.session_ref, BNC_SESSION_REF_LEN, REF_B));
}

static void test_held_session(void) {
  issued_t again = issue(0xa1, NULL, 2, 0, 1, SECRET_B, SK_A, PK_A);
  check("a held session answers again with its nonces, not a new secret",
        again.status == BNC_OK && !again.new_session &&
            equals_hex(again.nonces, BNC_PUBNONCE_LEN, NONCE_A_0_0) &&
            equals_hex(again.session_ref, BNC_SESSION_REF_LEN, REF_A));

  issued_t extended = issue(0xa1, REF_A, 2, 1, 1, SECRET_B, SK_A, PK_A);
  check("extending with the reference gives key expression 1 first",
        extended.status == BNC_OK && !extended.new_session &&
            equals_hex(extended.nonces, BNC_PUBNONCE_LEN, NONCE_A_0_1));

  check("a reference of another session is refused",
        issue(0xa1, REF_B, 2, 0, 1, SECRET_B, SK_A, PK_A).status ==
            BNC_ERR_SESSION_REF_MISMATCH);
  check("a reference without a held session is refused",
        issue(0xb0, REF_A, 2, 0, 1, SECRET_A, SK_A, PK_A).status ==
            BNC_ERR_UNKNOWN_SESSION);
  check("a refused reference creates no session", stored_sessions() == 3);
}

/* musig2_signing.json: A signs with its cached nonce, no tweaks. */
static void test_musig2_signing(void) {
  issued_t issued = issue(0xc1, NULL, 1, 0, 0, SECRET_A, SK_A, PK_A);
  check("signer A's cached nonce",
        issued.status == BNC_OK &&
            equals_hex(issued.nonces, BNC_PUBNONCE_LEN, NONCE_A_0_0));

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

  bnc_secret *secret = NULL;
  check("the named session is taken",
        bnc_begin_signing(nonce_cache_signer(),
                          (const uint8_t[]){0xc1, 0xc1, 0xc1, 0xc1},
                          issued.session_ref, &secret) == BNC_OK);
  check("a taken session is deleted",
        bnc_begin_signing(nonce_cache_signer(),
                          (const uint8_t[]){0xc1, 0xc1, 0xc1, 0xc1},
                          issued.session_ref,
                          &(bnc_secret *){NULL}) == BNC_ERR_UNKNOWN_SESSION);

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
  memcpy(slot.pubnonce, issued.nonces, sizeof(slot.pubnonce));
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

  issued_t reissued = issue(0xc1, NULL, 1, 0, 0, SECRET_B, SK_A, PK_A);
  check("the session ID issued again gets a new secret and nonce",
        reissued.status == BNC_OK && reissued.new_session &&
            !equals_hex(reissued.nonces, BNC_PUBNONCE_LEN, NONCE_A_0_0));
}

static void test_eviction(void) {
  size_t held = stored_sessions();
  check("sessions held before filling the store",
        held > 0 && held < NONCE_CACHE_MAX_SESSIONS);
  for (uint8_t id = 0xe0; id < 0xe0 + NONCE_CACHE_MAX_SESSIONS; id++)
    issue(id, NULL, 1, 0, 0, SECRET_A, SK_A, PK_A);
  check("the store keeps at most its capacity",
        stored_sessions() == NONCE_CACHE_MAX_SESSIONS);
  bnc_secret *secret = NULL;
  check("the oldest session is evicted",
        bnc_held_session(nonce_cache_signer(),
                         (const uint8_t[]){0xa1, 0xa1, 0xa1, 0xa1}, NULL,
                         &secret) == BNC_ERR_UNKNOWN_SESSION);
  check("the newest session is held",
        bnc_held_session(nonce_cache_signer(),
                         (const uint8_t[]){0xef, 0xef, 0xef, 0xef}, NULL,
                         &secret) == BNC_OK);
  bnc_secret_free(secret);
}

static void test_erase(void) {
  check("erasing deletes every session",
        nonce_cache_erase() && stored_sessions() == 0);
  bnc_secret *secret = NULL;
  check("an erased session is no longer held",
        bnc_held_session(nonce_cache_signer(),
                         (const uint8_t[]){0xef, 0xef, 0xef, 0xef}, NULL,
                         &secret) == BNC_ERR_UNKNOWN_SESSION);
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
