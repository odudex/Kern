#ifndef NONCE_CACHE_H
#define NONCE_CACHE_H

#include "../utils/attributes.h"
#include <bip_nonces_cache.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_musig.h>

/* Sessions of the nonce cache BIP draft (bip_nonces_cache, BIP-DRAFT.md): the
 * signer of the bip_nonces_cache C binding on libwally's MuSig2 and
 * mbedTLS SHA-256, with its sessions in NVS.
 *
 * A session is a random secret: storing one more than NONCE_CACHE_MAX_SESSIONS
 * evicts the oldest. Secret nonces are never stored: the binding recomputes
 * them from the session secret when it signs. */
#define NONCE_CACHE_MAX_SESSIONS 16

/* The BIP-327 session context of one MuSig2 signature, handed as is to
 * bnc_sign_musig: the key aggregation with its tweaks, and the session of the
 * aggregate nonce and message. */
typedef struct {
  const struct wally_musig_keyagg_cache *keyagg_cache;
  const struct wally_musig_session *session;
} nonce_cache_sign_context_t;

/* The process-wide signer, set up on first use. NULL when NVS cannot be
 * opened. */
KERN_WARN_UNUSED_RESULT bnc_signer *nonce_cache_signer(void);

/* A new session secret from the RNG, never derived from the seed. */
KERN_WARN_UNUSED_RESULT bool nonce_cache_fresh_secret(uint8_t *secret_out);

/* Deletes every session, durably: a device wipe leaves none behind. */
KERN_WARN_UNUSED_RESULT bool nonce_cache_erase(void);

typedef enum {
  NONCE_CACHE_OK,
  /* the reference names no session held under the ID, or another one */
  NONCE_CACHE_ERR_SESSION,
  NONCE_CACHE_ERR_INVALID,
  NONCE_CACHE_ERR_INTERNAL,
} nonce_cache_result_t;

typedef struct {
  uint8_t session_id[BNC_SESSION_ID_LEN];
  uint8_t session_ref[BNC_SESSION_REF_LEN];
  /* the session was created for this request */
  bool new_session;
} nonce_cache_issued_t;

/* Issuance (Nonce Preparation): the public nonces of the key at `path` from
 * the session `request` names, created when it holds none and carries no
 * reference, durable before this returns. With `draw_session`, the session
 * ID is drawn from the RNG among the IDs no session holds. `nonces_out` takes
 * (end - start + 1) * inputs nonces, by key expression index then input. */
KERN_WARN_UNUSED_RESULT nonce_cache_result_t
nonce_cache_issue(bnc_issuance *request, bool draw_session,
                  const uint32_t *path, size_t path_len, uint8_t *nonces_out,
                  size_t nonces_len, nonce_cache_issued_t *issued_out);

#endif // NONCE_CACHE_H
