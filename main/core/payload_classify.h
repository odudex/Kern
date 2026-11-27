#ifndef PAYLOAD_CLASSIFY_H
#define PAYLOAD_CLASSIFY_H

#include "../utils/attributes.h"
#include "message_sign.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_psbt.h>

typedef enum {
  PAYLOAD_ADDRESS_NONE = 0,
  PAYLOAD_ADDRESS_MAINNET,
  PAYLOAD_ADDRESS_TESTNET,
} payload_address_network_t;

typedef enum {
  PAYLOAD_KIND_UNKNOWN = 0,
  PAYLOAD_KIND_MESSAGE_SIGN,
  PAYLOAD_KIND_INVALID_MESSAGE_SIGN,
  PAYLOAD_KIND_PSBT,
  PAYLOAD_KIND_DESCRIPTOR,
  PAYLOAD_KIND_ADDRESS,
  PAYLOAD_KIND_MNEMONIC,
  PAYLOAD_KIND_KEF,
} payload_kind_t;

typedef struct {
  payload_kind_t kind;
  /* PAYLOAD_KIND_MESSAGE_SIGN: owned parsed message. */
  parsed_sign_message_t message;
  /* PAYLOAD_KIND_PSBT: owned parsed PSBT. */
  struct wally_psbt *psbt;
  bool psbt_is_base64;
  /* PAYLOAD_KIND_ADDRESS: detected Bitcoin network. */
  payload_address_network_t address_network;
  /* PAYLOAD_KIND_KEF: owned raw KEF envelope bytes. */
  uint8_t *kef_envelope;
  size_t kef_envelope_len;
} payload_classification_t;

/* True when `data` looks like a Coldcard/BlueWallet multisig setup payload. */
bool payload_is_bluewallet_descriptor(const char *data);

/* Fast prefix check for binary ("psbt\xff") or base64 ("cHNidP") PSBT data.
 * Used in keyless flows to recognize PSBTs without full parsing. */
bool payload_looks_like_psbt(const uint8_t *data, size_t len);

/* Detect whether `data` is a Bitcoin address (optionally prefixed with
 * "bitcoin:" and followed by a BIP21 "?..." query) and return its network. */
payload_address_network_t payload_detect_address_network(const char *data);

/* Classify a NUL-terminated QR or normalized file payload (which may contain
 * binary bytes up to `len`, such as Compact SeedQR or raw KEF) by trying
 * Kern's decoders in priority order:
 *   1. Message signing ("signmessage ...")
 *   2. Base64 PSBT
 *   3. Descriptor prefix or BlueWallet setup text
 *   4. Bitcoin address (raw or BIP21 URI)
 *   5. Mnemonic (plaintext, SeedQR, Compact SeedQR)
 *   6. KEF encrypted envelope (raw or base64-armored)
 *
 * Caller must release owned fields with payload_classify_free(). */
void payload_classify_text(const char *data, size_t len,
                           payload_classification_t *out);

void payload_classify_free(payload_classification_t *c);

#endif // PAYLOAD_CLASSIFY_H
