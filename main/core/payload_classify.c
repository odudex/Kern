/*
 * Payload classification for scanned QR codes and loaded files (UI-free).
 */

#include "payload_classify.h"
#include "../qr/seedqr.h"
#include "../utils/secure_mem.h"
#include "../utils/text_file.h"
#include "kef.h"
#include "kern_wally.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_address.h>
#include <wally_core.h>

bool payload_is_bluewallet_descriptor(const char *data) {
  return data != NULL && strstr(data, "Policy:") != NULL;
}

bool payload_looks_like_psbt(const uint8_t *data, size_t len) {
  if (!data)
    return false;
  if (len >= 6 && memcmp(data, "cHNidP", 6) == 0)
    return true;
  if (len >= 5 && memcmp(data, "psbt\xff", 5) == 0)
    return true;
  return false;
}

payload_address_network_t payload_detect_address_network(const char *data) {
  if (!data || data[0] == '\0')
    return PAYLOAD_ADDRESS_NONE;

  const char *addr = data;
  char *stripped = NULL;

  /* Strip optional BIP21 prefix and query parameters. */
  if (strncasecmp(data, "bitcoin:", 8) == 0) {
    const char *start = data + 8;
    const char *query = strchr(start, '?');
    size_t addr_len = query ? (size_t)(query - start) : strlen(start);
    stripped = strndup(start, addr_len);
    if (!stripped)
      return PAYLOAD_ADDRESS_NONE;
    addr = stripped;
  }

  unsigned char script[128];
  size_t written = 0;
  payload_address_network_t result = PAYLOAD_ADDRESS_NONE;

  if (wally_addr_segwit_to_bytes(addr, "bc", 0, script, sizeof(script),
                                 &written) == WALLY_OK ||
      wally_address_to_scriptpubkey(addr, WALLY_NETWORK_BITCOIN_MAINNET, script,
                                    sizeof(script), &written) == WALLY_OK) {
    result = PAYLOAD_ADDRESS_MAINNET;
  } else if (wally_addr_segwit_to_bytes(addr, "tb", 0, script, sizeof(script),
                                        &written) == WALLY_OK ||
             wally_address_to_scriptpubkey(addr, WALLY_NETWORK_BITCOIN_TESTNET,
                                           script, sizeof(script),
                                           &written) == WALLY_OK) {
    result = PAYLOAD_ADDRESS_TESTNET;
  }

  free(stripped);
  return result;
}

void payload_classify_free(payload_classification_t *c) {
  if (!c)
    return;
  message_sign_free_parsed(&c->message);
  if (c->psbt) {
    wally_psbt_free(c->psbt);
    c->psbt = NULL;
  }
  free(c->kef_envelope);
  memset(c, 0, sizeof(*c));
}

void payload_classify_text(const char *data, size_t len,
                           payload_classification_t *out) {
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!data || len == 0)
    return;

  /* Embedded NUL bytes mean binary content (Compact SeedQR or raw KEF); skip
   * C-string-only text heuristics so binary prefixes cannot misclassify. */
  bool is_text = (memchr(data, '\0', len) == NULL);

  if (is_text) {
    /* 1. Message signing */
    if (message_sign_parse(data, &out->message)) {
      out->kind = PAYLOAD_KIND_MESSAGE_SIGN;
      return;
    }
    if (strncmp(data, "signmessage ", 12) == 0) {
      out->kind = PAYLOAD_KIND_INVALID_MESSAGE_SIGN;
      return;
    }

    /* 2. PSBT (base64) */
    if (kern_psbt_from_base64(data, 0, &out->psbt) == WALLY_OK) {
      out->kind = PAYLOAD_KIND_PSBT;
      out->psbt_is_base64 = true;
      return;
    }

    /* 3. Descriptor */
    if (text_is_descriptor_prefix(data) ||
        payload_is_bluewallet_descriptor(data)) {
      out->kind = PAYLOAD_KIND_DESCRIPTOR;
      return;
    }

    /* 4. Bitcoin address (raw or BIP21 URI) */
    payload_address_network_t addr_net = payload_detect_address_network(data);
    if (addr_net != PAYLOAD_ADDRESS_NONE) {
      out->kind = PAYLOAD_KIND_ADDRESS;
      out->address_network = addr_net;
      return;
    }
  }

  /* 5. Mnemonic (plaintext, SeedQR, or binary Compact SeedQR) */
  char *mnemonic = mnemonic_qr_to_mnemonic(data, len, NULL);
  if (mnemonic) {
    SECURE_FREE_STRING(mnemonic);
    out->kind = PAYLOAD_KIND_MNEMONIC;
    return;
  }

  /* 6. Encrypted (KEF) envelope (raw binary or base64-armored). Tried last so
   * a base64 PSBT is recognized as a PSBT first. */
  size_t env_len = 0;
  uint8_t *envelope =
      kef_envelope_from_bytes((const uint8_t *)data, len, &env_len);
  if (envelope) {
    out->kind = PAYLOAD_KIND_KEF;
    out->kef_envelope = envelope;
    out->kef_envelope_len = env_len;
    return;
  }
}
