#include "bip322.h"
#include "psbt.h"
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>

static const char *TAG = "bip322";

#define PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE 0x09

static const unsigned char MESSAGE_KEY[] = {PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE};

static bool get_message_field(const struct wally_psbt *psbt,
                              const unsigned char **msg, size_t *msg_len) {
  size_t index = 0;
  if (wally_map_find(&psbt->unknowns, MESSAGE_KEY, sizeof(MESSAGE_KEY),
                     &index) != WALLY_OK ||
      index == 0)
    return false;
  const struct wally_map_item *item = &psbt->unknowns.items[index - 1];
  *msg = item->value;
  *msg_len = item->value_len;
  return true;
}

bool bip322_detect(const struct wally_psbt *psbt) {
  const unsigned char *msg;
  size_t msg_len;
  return psbt && get_message_field(psbt, &msg, &msg_len);
}

/* BIP322 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message) */
static bool message_tagged_hash(const unsigned char *msg, size_t msg_len,
                                unsigned char hash_out[SHA256_LEN]) {
  static const char tag[] = "BIP0322-signed-message";
  unsigned char tag_hash[SHA256_LEN];
  if (wally_sha256((const unsigned char *)tag, sizeof(tag) - 1, tag_hash,
                   sizeof(tag_hash)) != WALLY_OK)
    return false;

  size_t buf_len = 2 * SHA256_LEN + msg_len;
  unsigned char *buf = malloc(buf_len);
  if (!buf)
    return false;
  memcpy(buf, tag_hash, SHA256_LEN);
  memcpy(buf + SHA256_LEN, tag_hash, SHA256_LEN);
  if (msg_len)
    memcpy(buf + 2 * SHA256_LEN, msg, msg_len);

  int ret = wally_sha256(buf, buf_len, hash_out, SHA256_LEN);
  free(buf);
  return ret == WALLY_OK;
}

/* Rebuild the virtual to_spend transaction for the message + proven script
 * and return its txid. */
static bool to_spend_txid(const unsigned char *msg, size_t msg_len,
                          const unsigned char *spk, size_t spk_len,
                          unsigned char txid_out[WALLY_TXHASH_LEN]) {
  unsigned char msg_hash[SHA256_LEN];
  if (!message_tagged_hash(msg, msg_len, msg_hash))
    return false;

  /* scriptSig: OP_0 <32-byte message hash> */
  unsigned char scriptsig[2 + SHA256_LEN];
  scriptsig[0] = OP_0;
  scriptsig[1] = SHA256_LEN;
  memcpy(scriptsig + 2, msg_hash, SHA256_LEN);

  static const unsigned char null_txhash[WALLY_TXHASH_LEN] = {0};

  struct wally_tx *tx = NULL;
  bool ok = wally_tx_init_alloc(0, 0, 1, 1, &tx) == WALLY_OK &&
            wally_tx_add_raw_input(tx, null_txhash, sizeof(null_txhash),
                                   0xffffffff, 0, scriptsig, sizeof(scriptsig),
                                   NULL, 0) == WALLY_OK &&
            wally_tx_add_raw_output(tx, 0, spk, spk_len, 0) == WALLY_OK &&
            wally_tx_get_txid(tx, txid_out, WALLY_TXHASH_LEN) == WALLY_OK;
  wally_tx_free(tx);
  return ok;
}

bool bip322_parse(const struct wally_psbt *psbt, bool is_testnet,
                  bip322_request_t *out) {
  if (!psbt || !out)
    return false;

  memset(out, 0, sizeof(*out));

  const unsigned char *msg = NULL;
  size_t msg_len = 0;
  if (!get_message_field(psbt, &msg, &msg_len))
    return false;
  if (msg_len == 0) {
    ESP_LOGW(TAG, "empty message");
    return false;
  }

  /* to_sign structure per BIP322 */
  const struct wally_tx *tx = psbt->tx;
  if (!tx || tx->version != 0 || tx->locktime != 0 || tx->num_inputs != 1 ||
      tx->num_outputs != 1) {
    ESP_LOGW(TAG, "to_sign transaction structure mismatch");
    return false;
  }
  if (tx->inputs[0].index != 0 || tx->inputs[0].sequence != 0) {
    ESP_LOGW(TAG, "to_sign input must spend to_spend:0 with sequence 0");
    return false;
  }
  if (tx->outputs[0].satoshi != 0 || tx->outputs[0].script_len != 1 ||
      tx->outputs[0].script[0] != OP_RETURN) {
    ESP_LOGW(TAG, "to_sign output must be 0-value OP_RETURN");
    return false;
  }

  const struct wally_tx_output *utxo = psbt->inputs[0].witness_utxo;
  if (!utxo || utxo->satoshi != 0 || !utxo->script || utxo->script_len == 0 ||
      utxo->script_len > 0xfc) {
    ESP_LOGW(TAG, "missing or invalid witness_utxo");
    return false;
  }

  /* The input must spend the to_spend tx committing to this exact message
   * and scriptPubKey. */
  unsigned char txid[WALLY_TXHASH_LEN];
  if (!to_spend_txid(msg, msg_len, utxo->script, utxo->script_len, txid))
    return false;
  if (memcmp(txid, tx->inputs[0].txhash, WALLY_TXHASH_LEN) != 0) {
    ESP_LOGW(TAG, "to_spend commitment mismatch");
    return false;
  }

  out->message = malloc(msg_len + 1);
  if (!out->message)
    return false;
  if (msg_len)
    memcpy(out->message, msg, msg_len);
  out->message[msg_len] = '\0';

  out->address =
      psbt_scriptpubkey_to_address(utxo->script, utxo->script_len, is_testnet);
  if (!out->address) {
    bip322_request_free(out);
    return false;
  }

  return true;
}

void bip322_request_free(bip322_request_t *req) {
  if (!req)
    return;
  free(req->message);
  req->message = NULL;
  free(req->address);
  req->address = NULL;
}
