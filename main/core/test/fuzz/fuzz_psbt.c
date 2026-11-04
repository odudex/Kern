/* PSBT payloads, as a QR or SD file delivers them: parse, then everything
 * the review and signing flow does with an untrusted PSBT. */
#include "core/bip322.h"
#include "core/key.h"
#include "core/psbt.h"
#include "core/registry.h"
#include "core/wallet.h"
#include "fuzz.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
#define NUMS "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

/* Results are thrown away; this keeps them from being optimised out. */
static volatile uint64_t sink;

void fuzz_load_test_key(void) {
  static bool done;
  if (done)
    return;
  done = true;
  if (wally_init(0) != WALLY_OK ||
      !key_load_from_mnemonic("abandon abandon abandon abandon abandon "
                              "abandon abandon abandon abandon abandon "
                              "abandon about",
                              "", false))
    abort();
  /* Registered wallets, so registry claims run too. */
  char *k48 = NULL, *k86 = NULL;
  char desc[1024];
  if (!key_get_xpub("m/48'/0'/0'/2'", &k48) ||
      !key_get_xpub("m/86'/0'/0'", &k86))
    abort();
  snprintf(desc, sizeof(desc),
           "wsh(sortedmulti(2,[73c5da0a/48'/0'/0'/2']%s/<0;1>/*,"
           "[deadbeef/48'/0'/0'/2']" XPUB_86 "/<0;1>/*))",
           k48);
  bool ok = registry_add_from_string("ms", desc, STORAGE_FLASH, false);
  snprintf(desc, sizeof(desc),
           "tr(" NUMS ",{pk([73c5da0a/86'/0'/0']%s/<0;1>/*),"
           "and_v(v:pk([73c5da0a/48'/0'/0'/2']%s/<2;3>/*),older(144))})",
           k86, k48);
  ok = ok && registry_add_from_string("tr", desc, STORAGE_FLASH, false);
  wally_free_string(k48);
  wally_free_string(k86);
  if (!ok)
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_load_test_key();
  struct wally_psbt *psbt = NULL;
  if (!psbt_parse_payload(data, size, &psbt))
    return 0;

  size_t num_inputs = 0, num_outputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK)
    num_inputs = 0;
  if (wally_psbt_get_num_outputs(psbt, &num_outputs) != WALLY_OK)
    num_outputs = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    sink += psbt_classify_input(psbt, i, false).ownership;
    sink += psbt_input_is_taproot(psbt, i);
  }
  for (size_t i = 0; i < num_outputs; i++)
    sink += psbt_classify_output(psbt, i, false).ownership;

  psbt_amount_audit_t audit;
  psbt_sighash_audit_t sighash;
  uint64_t total = 0;
  psbt_audit_input_amounts(psbt, &audit);
  psbt_audit_sighash(psbt, &sighash);
  sink += psbt_total_output_value(psbt, &total) + total;
  sink += psbt_detect_network(psbt);

  struct wally_tx *tx = psbt_tx_alloc(psbt);
  for (size_t i = 0; tx && i < tx->num_outputs; i++) {
    psbt_destination_kind_t kind;
    char *dest = psbt_output_destination(
        tx->outputs[i].script, tx->outputs[i].script_len, false, &kind);
    wally_free_string(dest);
    sink += psbt_output_dust_threshold(tx->outputs[i].script,
                                       tx->outputs[i].script_len);
  }
  wally_tx_free(tx);

  bip322_request_t req;
  if (bip322_parse(psbt, false, &req))
    bip322_request_free(&req);

  psbt_sign_policy_t policy = {.allow_unsafe = true,
                               .allow_expected_owned = true};
  psbt_sign_result_t result;
  sink += psbt_sign(psbt, false, policy, &result);
  wally_psbt_free(psbt_trim(psbt));
  wally_psbt_free(psbt);
  return 0;
}
