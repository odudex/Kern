#include "message_sign.h"
#include "../utils/secure_mem.h"
#include "key.h"
#include "message_validation.h"
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>

static const char *TAG = "message_sign";

bool message_sign_parse(const char *content, parsed_sign_message_t *result) {
  if (!content || !result) {
    return false;
  }

  memset(result, 0, sizeof(*result));

  if (strncmp(content, "signmessage ", 12) != 0) {
    return false;
  }

  const char *path_start = content + 12;

  // Find end of path (next space)
  const char *path_end = strchr(path_start, ' ');
  if (!path_end || path_end == path_start) {
    return false;
  }

  size_t path_len = path_end - path_start;

  // Copy path, replacing 'h' after digits with '\'' (key.c only accepts '\'')
  char *converted_path = malloc(path_len + 1);
  if (!converted_path) {
    return false;
  }

  size_t out_idx = 0;
  for (size_t i = 0; i < path_len; i++) {
    if (path_start[i] == 'h' && i > 0 && path_start[i - 1] >= '0' &&
        path_start[i - 1] <= '9') {
      converted_path[out_idx++] = '\'';
    } else {
      converted_path[out_idx++] = path_start[i];
    }
  }
  converted_path[out_idx] = '\0';

  // After space, expect "ascii:" prefix
  const char *msg_start = path_end + 1;
  if (strncmp(msg_start, "ascii:", 6) != 0) {
    free(converted_path);
    return false;
  }
  msg_start += 6;
  if (!message_text_is_displayable((const unsigned char *)msg_start,
                                   strlen(msg_start))) {
    free(converted_path);
    return false;
  }

  result->derivation_path = converted_path;
  result->message = strdup(msg_start);
  if (!result->message) {
    free(converted_path);
    result->derivation_path = NULL;
    return false;
  }

  return true;
}

void message_sign_free_parsed(parsed_sign_message_t *parsed) {
  if (!parsed) {
    return;
  }
  free(parsed->derivation_path);
  parsed->derivation_path = NULL;
  free(parsed->message);
  parsed->message = NULL;
}

bool message_sign_sign(const char *derivation_path, const char *message,
                       char **signature_b64_out) {
  if (!derivation_path || !message || !signature_b64_out) {
    return false;
  }

  struct ext_key *derived_key = NULL;
  if (!key_get_derived_key(derivation_path, &derived_key)) {
    ESP_LOGE(TAG, "Failed to derive key at %s", derivation_path);
    return false;
  }

  unsigned char hash[SHA256_LEN];
  size_t written;

  int ret = wally_format_bitcoin_message(
      (const unsigned char *)message, strlen(message),
      BITCOIN_MESSAGE_FLAG_HASH, hash, sizeof(hash), &written);
  if (ret != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to format bitcoin message: %d", ret);
    bip32_key_free(derived_key);
    return false;
  }

  // Create recoverable ECDSA signature (65 bytes)
  // NOTE: This uses ECDSA recoverable signatures, suitable for legacy and
  // segwit addresses. Taproot (BIP86, path 86h) would require BIP340 Schnorr
  // signing (EC_FLAG_SCHNORR) — to be implemented when taproot support is
  // added.
  unsigned char sig[EC_SIGNATURE_RECOVERABLE_LEN];
  ret = wally_ec_sig_from_bytes(
      derived_key->priv_key + 1, EC_PRIVATE_KEY_LEN, hash, EC_MESSAGE_HASH_LEN,
      EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, sig, sizeof(sig));

  // Securely clear private key material
  secure_memzero(hash, sizeof(hash));
  bip32_key_free(derived_key);

  if (ret != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to sign message: %d", ret);
    secure_memzero(sig, sizeof(sig));
    return false;
  }

  // Encode signature to base64
  char *b64_output = NULL;
  ret = wally_base64_from_bytes(sig, sizeof(sig), 0, &b64_output);
  secure_memzero(sig, sizeof(sig));

  if (ret != WALLY_OK || !b64_output) {
    ESP_LOGE(TAG, "Failed to base64 encode signature: %d", ret);
    return false;
  }

  *signature_b64_out = b64_output;
  return true;
}

bool message_sign_get_address(const char *derivation_path, bool is_testnet,
                              char **address_out) {
  if (!derivation_path || !address_out) {
    return false;
  }

  struct ext_key *derived_key = NULL;
  if (!key_get_derived_key(derivation_path, &derived_key)) {
    ESP_LOGE(TAG, "Failed to derive key at %s", derivation_path);
    return false;
  }

  unsigned char script[WALLY_WITNESSSCRIPT_MAX_LEN];
  size_t script_len;

  int ret = wally_witness_program_from_bytes(
      derived_key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, script,
      sizeof(script), &script_len);
  bip32_key_free(derived_key);

  if (ret != WALLY_OK) {
    return false;
  }

  const char *hrp = is_testnet ? "tb" : "bc";
  ret = wally_addr_segwit_from_bytes(script, script_len, hrp, 0, address_out);
  return (ret == WALLY_OK);
}
