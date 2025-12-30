#include "psbt.h"
#include "../key/key.h"
#include "../wallet/wallet.h"
#include <esp_log.h>
#include <stdio.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_map.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

static const char *TAG = "PSBT";

uint64_t psbt_get_input_value(const struct wally_psbt *psbt, size_t index) {
  struct wally_tx_output *utxo = NULL;
  uint64_t value = 0;

  if (wally_psbt_get_input_best_utxo_alloc(psbt, index, &utxo) == WALLY_OK &&
      utxo) {
    value = utxo->satoshi;
    wally_tx_output_free(utxo);
  }

  return value;
}

static bool check_keypath_network(const unsigned char *keypath,
                                  size_t keypath_len, bool *is_testnet) {
  if (keypath_len < 12) {
    return false;
  }

  uint32_t coin_type;
  memcpy(&coin_type, keypath + 8, sizeof(uint32_t));
  uint32_t coin_value = coin_type & 0x7FFFFFFF;

  if (coin_value == 0 || coin_value == 1) {
    *is_testnet = (coin_value == 1);
    return true;
  }

  return false;
}

bool psbt_detect_network(const struct wally_psbt *psbt) {
  if (!psbt) {
    return false;
  }

  unsigned char keypath[100];
  size_t keypath_len, keypaths_size;
  bool is_testnet;

  // Check outputs first
  size_t num_outputs = 0;
  wally_psbt_get_num_outputs(psbt, &num_outputs);

  for (size_t i = 0; i < num_outputs; i++) {
    if (wally_psbt_get_output_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_output_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                      &keypath_len) == WALLY_OK &&
        check_keypath_network(keypath, keypath_len, &is_testnet)) {
      return is_testnet;
    }
  }

  // Check inputs as fallback
  size_t num_inputs = 0;
  wally_psbt_get_num_inputs(psbt, &num_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    if (wally_psbt_get_input_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_input_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                     &keypath_len) == WALLY_OK &&
        check_keypath_network(keypath, keypath_len, &is_testnet)) {
      return is_testnet;
    }
  }

  return false; // Default to mainnet
}

char *psbt_scriptpubkey_to_address(const unsigned char *script,
                                   size_t script_len, bool is_testnet) {
  if (!script || script_len == 0) {
    return NULL;
  }

  size_t script_type = 0;
  if (wally_scriptpubkey_get_type(script, script_len, &script_type) !=
      WALLY_OK) {
    return NULL;
  }

  char *address = NULL;
  const char *hrp = is_testnet ? "tb" : "bc";
  uint32_t network = is_testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                : WALLY_NETWORK_BITCOIN_MAINNET;

  if (script_type == WALLY_SCRIPT_TYPE_P2WPKH ||
      script_type == WALLY_SCRIPT_TYPE_P2WSH ||
      script_type == WALLY_SCRIPT_TYPE_P2TR) {
    if (wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &address) !=
        WALLY_OK) {
      return NULL;
    }
  } else if (script_type == WALLY_SCRIPT_TYPE_P2PKH ||
             script_type == WALLY_SCRIPT_TYPE_P2SH) {
    if (wally_scriptpubkey_to_address(script, script_len, network, &address) !=
        WALLY_OK) {
      return NULL;
    }
  } else if (script_type == WALLY_SCRIPT_TYPE_OP_RETURN) {
    address = strdup("OP_RETURN");
  }

  return address;
}

bool psbt_get_output_derivation(const struct wally_psbt *psbt,
                                size_t output_index, bool is_testnet,
                                bool *is_change, uint32_t *address_index) {
  if (!psbt || !is_change || !address_index) {
    return false;
  }

  size_t keypaths_size = 0;
  if (wally_psbt_get_output_keypaths_size(psbt, output_index, &keypaths_size) !=
          WALLY_OK ||
      keypaths_size == 0) {
    return false;
  }

  unsigned char our_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(our_fingerprint)) {
    return false;
  }

  for (size_t i = 0; i < keypaths_size; i++) {
    unsigned char keypath[100];
    size_t keypath_len = 0;

    if (wally_psbt_get_output_keypath(psbt, output_index, i, keypath,
                                      sizeof(keypath),
                                      &keypath_len) != WALLY_OK ||
        keypath_len < 24) {
      continue;
    }

    if (memcmp(keypath, our_fingerprint, BIP32_KEY_FINGERPRINT_LEN) != 0) {
      continue;
    }

    uint32_t purpose, coin_type, account, change_val, index_val;
    memcpy(&purpose, keypath + 4, sizeof(uint32_t));
    memcpy(&coin_type, keypath + 8, sizeof(uint32_t));
    memcpy(&account, keypath + 12, sizeof(uint32_t));
    memcpy(&change_val, keypath + 16, sizeof(uint32_t));
    memcpy(&index_val, keypath + 20, sizeof(uint32_t));

    uint32_t expected_coin = is_testnet ? (0x80000000 | 1) : (0x80000000 | 0);

    if (purpose == (0x80000000 | 84) && coin_type == expected_coin &&
        account == 0x80000000 && !(change_val & 0x80000000) &&
        !(index_val & 0x80000000)) {
      *is_change = (change_val == 1);
      *address_index = index_val;
      return true;
    }
  }

  return false;
}

size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet) {
  if (!psbt) {
    ESP_LOGE(TAG, "Invalid PSBT");
    return 0;
  }

  // Get our fingerprint
  unsigned char our_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(our_fingerprint)) {
    ESP_LOGE(TAG, "Failed to get key fingerprint");
    return 0;
  }

  // Get wallet network to check for mismatches
  wallet_network_t wallet_network = wallet_get_network();
  bool wallet_is_testnet = (wallet_network == WALLET_NETWORK_TESTNET);

  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to get number of inputs");
    return 0;
  }

  size_t signatures_added = 0;

  for (size_t i = 0; i < num_inputs; i++) {
    size_t keypaths_size = 0;
    if (wally_psbt_get_input_keypaths_size(psbt, i, &keypaths_size) !=
            WALLY_OK ||
        keypaths_size == 0) {
      continue;
    }

    for (size_t j = 0; j < keypaths_size; j++) {
      unsigned char keypath[100];
      size_t keypath_len = 0;

      if (wally_psbt_get_input_keypath(psbt, i, j, keypath, sizeof(keypath),
                                       &keypath_len) != WALLY_OK ||
          keypath_len < 24) {
        continue;
      }

      if (memcmp(keypath, our_fingerprint, BIP32_KEY_FINGERPRINT_LEN) != 0) {
        continue;
      }

      uint32_t purpose, coin_type, account, change_val, index_val;
      memcpy(&purpose, keypath + 4, sizeof(uint32_t));
      memcpy(&coin_type, keypath + 8, sizeof(uint32_t));
      memcpy(&account, keypath + 12, sizeof(uint32_t));
      memcpy(&change_val, keypath + 16, sizeof(uint32_t));
      memcpy(&index_val, keypath + 20, sizeof(uint32_t));

      if (purpose != (0x80000000 | 84) || account != 0x80000000) {
        continue;
      }

      uint32_t coin_value = coin_type & 0x7FFFFFFF;
      bool input_is_testnet = (coin_value == 1);

      if (wallet_is_testnet != input_is_testnet) {
        ESP_LOGW(TAG, "Network mismatch: input is %s but wallet is %s",
                 input_is_testnet ? "testnet" : "mainnet",
                 wallet_is_testnet ? "testnet" : "mainnet");
      }

      char path_str[64];
      snprintf(path_str, sizeof(path_str), "m/84'/%u'/0'/%u/%u", coin_value,
               change_val, index_val);

      struct ext_key *derived_key = NULL;
      if (!key_get_derived_key(path_str, &derived_key)) {
        ESP_LOGE(TAG, "Failed to derive key for path: %s", path_str);
        continue;
      }

      int ret = wally_psbt_sign(psbt, derived_key->priv_key + 1,
                                EC_PRIVATE_KEY_LEN, EC_FLAG_GRIND_R);

      bip32_key_free(derived_key);

      if (ret == WALLY_OK) {
        signatures_added++;
        break;
      } else {
        ESP_LOGE(TAG, "Failed to sign input %zu: %d", i, ret);
      }
    }
  }

  return signatures_added;
}

struct wally_psbt *psbt_trim(const struct wally_psbt *psbt) {
  if (!psbt) {
    return NULL;
  }

  struct wally_tx *global_tx = NULL;
  if (wally_psbt_get_global_tx_alloc(psbt, &global_tx) != WALLY_OK ||
      !global_tx) {
    return NULL;
  }

  struct wally_psbt *trimmed = NULL;
  if (wally_psbt_from_tx(global_tx, 0, 0, &trimmed) != WALLY_OK) {
    wally_tx_free(global_tx);
    return NULL;
  }
  wally_tx_free(global_tx);

  size_t num_inputs = 0;
  wally_psbt_get_num_inputs(psbt, &num_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    // Copy partial signatures using direct map access
    size_t sigs_size = 0;
    if (wally_psbt_get_input_signatures_size(psbt, i, &sigs_size) == WALLY_OK &&
        sigs_size > 0) {
      // Access the signatures map directly from the source PSBT input
      const struct wally_map *sig_map = &psbt->inputs[i].signatures;
      for (size_t j = 0; j < sig_map->num_items; j++) {
        const struct wally_map_item *item = &sig_map->items[j];
        if (item->key && item->key_len > 0 && item->value &&
            item->value_len > 0) {
          wally_psbt_add_input_signature(trimmed, i, item->key, item->key_len,
                                         item->value, item->value_len);
        }
      }
    }

    // Copy final witness if present
    struct wally_tx_witness_stack *witness = NULL;
    if (wally_psbt_get_input_final_witness_alloc(psbt, i, &witness) ==
            WALLY_OK &&
        witness) {
      wally_psbt_set_input_final_witness(trimmed, i, witness);
      wally_tx_witness_stack_free(witness);
    }

    // Copy final scriptsig if present
    size_t scriptsig_len = 0;
    if (wally_psbt_get_input_final_scriptsig_len(psbt, i, &scriptsig_len) ==
            WALLY_OK &&
        scriptsig_len > 0) {
      unsigned char *scriptsig = malloc(scriptsig_len);
      if (scriptsig) {
        size_t written = 0;
        if (wally_psbt_get_input_final_scriptsig(
                psbt, i, scriptsig, scriptsig_len, &written) == WALLY_OK) {
          wally_psbt_set_input_final_scriptsig(trimmed, i, scriptsig, written);
        }
        free(scriptsig);
      }
    }

    // Copy witness UTXO if present
    struct wally_tx_output *witness_utxo = NULL;
    if (wally_psbt_get_input_witness_utxo_alloc(psbt, i, &witness_utxo) ==
            WALLY_OK &&
        witness_utxo) {
      wally_psbt_set_input_witness_utxo(trimmed, i, witness_utxo);
      wally_tx_output_free(witness_utxo);
    }

    // Copy non-witness UTXO if present (for legacy inputs)
    struct wally_tx *utxo = NULL;
    if (wally_psbt_get_input_utxo_alloc(psbt, i, &utxo) == WALLY_OK && utxo) {
      wally_psbt_set_input_utxo(trimmed, i, utxo);
      wally_tx_free(utxo);
    }

    // Copy redeem script if present (P2SH)
    size_t redeem_len = 0;
    if (wally_psbt_get_input_redeem_script_len(psbt, i, &redeem_len) ==
            WALLY_OK &&
        redeem_len > 0) {
      unsigned char *redeem = malloc(redeem_len);
      if (redeem) {
        size_t written = 0;
        if (wally_psbt_get_input_redeem_script(psbt, i, redeem, redeem_len,
                                               &written) == WALLY_OK) {
          wally_psbt_set_input_redeem_script(trimmed, i, redeem, written);
        }
        free(redeem);
      }
    }

    // Copy witness script if present (P2WSH)
    size_t witness_script_len = 0;
    if (wally_psbt_get_input_witness_script_len(psbt, i, &witness_script_len) ==
            WALLY_OK &&
        witness_script_len > 0) {
      unsigned char *witness_script = malloc(witness_script_len);
      if (witness_script) {
        size_t written = 0;
        if (wally_psbt_get_input_witness_script(psbt, i, witness_script,
                                                witness_script_len,
                                                &written) == WALLY_OK) {
          wally_psbt_set_input_witness_script(trimmed, i, witness_script,
                                              written);
        }
        free(witness_script);
      }
    }

    // Copy taproot key signature if present
    size_t tap_sig_len = 0;
    if (wally_psbt_get_input_taproot_signature_len(psbt, i, &tap_sig_len) ==
            WALLY_OK &&
        tap_sig_len > 0) {
      unsigned char tap_sig[65];
      size_t written = 0;
      if (wally_psbt_get_input_taproot_signature(
              psbt, i, tap_sig, sizeof(tap_sig), &written) == WALLY_OK) {
        wally_psbt_set_input_taproot_signature(trimmed, i, tap_sig, written);
      }
    }
  }

  return trimmed;
}
