#include "descriptor_validator.h"
#include "key.h"
#include "wallet.h"
#include <esp_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

static const char *TAG = "descriptor_validator";

typedef struct {
  char *descriptor_str;
  validation_complete_cb callback;
  validation_confirm_cb confirm_cb;
  void *user_data;
  wallet_network_t target_network;
  wallet_policy_t target_policy;
  uint32_t target_account;
  bool needs_network_change;
  bool needs_policy_change;
  bool needs_account_change;
} validation_context_t;

static validation_context_t *current_ctx = NULL;

static void cleanup_context(void) {
  if (current_ctx) {
    if (current_ctx->descriptor_str) {
      free(current_ctx->descriptor_str);
    }
    free(current_ctx);
    current_ctx = NULL;
  }
}

static void complete_validation(descriptor_validation_result_t result) {
  if (current_ctx && current_ctx->callback) {
    validation_complete_cb cb = current_ctx->callback;
    void *user_data = current_ctx->user_data;
    cleanup_context();
    cb(result, user_data);
  } else {
    cleanup_context();
  }
}

// Find key index in descriptor that matches our fingerprint
// Returns -1 if not found
static int find_matching_key_index(struct wally_descriptor *descriptor) {
  unsigned char wallet_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(wallet_fp)) {
    return -1;
  }

  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(descriptor, &num_keys) != WALLY_OK) {
    return -1;
  }

  for (uint32_t i = 0; i < num_keys; i++) {
    unsigned char key_fp[BIP32_KEY_FINGERPRINT_LEN];
    int ret = wally_descriptor_get_key_origin_fingerprint(
        descriptor, i, key_fp, BIP32_KEY_FINGERPRINT_LEN);

    if (ret == WALLY_OK &&
        memcmp(wallet_fp, key_fp, BIP32_KEY_FINGERPRINT_LEN) == 0) {
      return (int)i;
    }
  }

  return -1;
}

// Parse origin path like "48'/0'/0'/2'" into network, policy, account
static bool parse_origin_path(const char *path, wallet_network_t *network_out,
                              wallet_policy_t *policy_out,
                              uint32_t *account_out) {
  if (!path || !network_out || !policy_out || !account_out) {
    return false;
  }

  // Path format: "purpose'/coin'/account'[/script']"
  // BIP84 (singlesig): 84'/coin'/account'
  // BIP48 (multisig): 48'/coin'/account'/script'
  uint32_t purpose = 0, coin = 0, account = 0;
  const char *p = path;
  const char *start;

  // Parse purpose
  start = p;
  while (*p >= '0' && *p <= '9') {
    purpose = purpose * 10 + (*p - '0');
    p++;
  }
  if (p == start)
    return false;
  if (*p == '\'' || *p == 'h')
    p++;
  if (*p == '/')
    p++;

  // Parse coin type
  start = p;
  while (*p >= '0' && *p <= '9') {
    coin = coin * 10 + (*p - '0');
    p++;
  }
  if (p == start)
    return false;
  if (*p == '\'' || *p == 'h')
    p++;
  if (*p == '/')
    p++;

  // Parse account
  start = p;
  while (*p >= '0' && *p <= '9') {
    account = account * 10 + (*p - '0');
    p++;
  }
  if (p == start)
    return false;

  // Determine network from coin type
  *network_out = (coin == 0) ? WALLET_NETWORK_MAINNET : WALLET_NETWORK_TESTNET;

  // Determine policy from purpose
  if (purpose == 48) {
    *policy_out = WALLET_POLICY_MULTISIG;
  } else {
    *policy_out = WALLET_POLICY_SINGLESIG;
  }

  *account_out = account;

  return true;
}

// Extract xpub from key string
// Key format: "[fingerprint/path]xpub..." or just "xpub..."
static char *extract_xpub_from_key(const char *key_str) {
  if (!key_str) {
    return NULL;
  }

  // Find start of xpub (skip origin info if present)
  const char *xpub_start = key_str;
  if (key_str[0] == '[') {
    const char *close = strchr(key_str, ']');
    if (close) {
      xpub_start = close + 1;
    }
  }

  // Find xpub prefix (xpub or tpub)
  const char *prefix = strstr(xpub_start, "pub");
  if (!prefix || prefix == xpub_start) {
    return NULL;
  }
  prefix--; // Back up to 'x' or 't'

  // Find end of xpub (stop at / or end of string)
  const char *end = prefix;
  while (*end && *end != '/' && *end != ')' && *end != ',' && *end != '<') {
    end++;
  }

  size_t len = end - prefix;
  char *xpub = malloc(len + 1);
  if (!xpub) {
    return NULL;
  }

  memcpy(xpub, prefix, len);
  xpub[len] = '\0';

  return xpub;
}

// Re-parse descriptor, verify xpub matches wallet, and load descriptor.
static descriptor_validation_result_t verify_xpub_and_load(void) {
  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;

  struct wally_descriptor *descriptor = NULL;
  if (wally_descriptor_parse(current_ctx->descriptor_str, NULL, wally_network,
                             0, &descriptor) != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to parse descriptor for xpub verification");
    return VALIDATION_PARSE_ERROR;
  }

  int key_index = find_matching_key_index(descriptor);
  if (key_index < 0) {
    wally_descriptor_free(descriptor);
    return VALIDATION_FINGERPRINT_NOT_FOUND;
  }

  char *key_str = NULL;
  if (wally_descriptor_get_key(descriptor, key_index, &key_str) != WALLY_OK) {
    wally_descriptor_free(descriptor);
    return VALIDATION_INTERNAL_ERROR;
  }

  char *descriptor_xpub = extract_xpub_from_key(key_str);
  wally_free_string(key_str);
  wally_descriptor_free(descriptor);

  if (!descriptor_xpub) {
    return VALIDATION_PARSE_ERROR;
  }

  char *wallet_xpub = NULL;
  if (!wallet_get_account_xpub(&wallet_xpub)) {
    free(descriptor_xpub);
    return VALIDATION_INTERNAL_ERROR;
  }

  bool xpub_match = (strcmp(descriptor_xpub, wallet_xpub) == 0);
  free(descriptor_xpub);
  wally_free_string(wallet_xpub);

  if (!xpub_match) {
    ESP_LOGE(TAG, "XPub mismatch");
    return VALIDATION_XPUB_MISMATCH;
  }

  if (!wallet_load_descriptor(current_ctx->descriptor_str)) {
    ESP_LOGE(TAG, "Failed to load descriptor");
    return VALIDATION_INTERNAL_ERROR;
  }

  return VALIDATION_SUCCESS;
}

// Apply settings changes and verify xpub
static void apply_changes_and_verify(void) {
  if (!current_ctx) {
    return;
  }

  // Get current mnemonic for reinit
  char *mnemonic = NULL;
  if (!key_get_mnemonic(&mnemonic)) {
    ESP_LOGE(TAG, "Failed to get mnemonic");
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  bool is_testnet = (current_ctx->target_network == WALLET_NETWORK_TESTNET);

  // Perform wallet reinit with new settings
  wallet_cleanup();
  wallet_set_account(current_ctx->target_account);
  wallet_set_policy(current_ctx->target_policy);

  // Reload key - passphrase is already applied in current key
  if (!key_load_from_mnemonic(mnemonic, NULL, is_testnet)) {
    ESP_LOGE(TAG, "Failed to reload key");
    free(mnemonic);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }
  free(mnemonic);

  if (!wallet_init(current_ctx->target_network)) {
    ESP_LOGE(TAG, "Failed to reinit wallet");
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  complete_validation(verify_xpub_and_load());
}

// Callback for attribute change confirmation dialog
static void attribute_change_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;

  if (!confirmed) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }

  apply_changes_and_verify();
}

// Stage 2 & 3: Check attributes and verify xpub
static void check_attributes_and_verify(struct wally_descriptor *descriptor,
                                        int key_index) {
  // Get origin path for our key
  char *origin_path = NULL;
  if (wally_descriptor_get_key_origin_path_str(descriptor, key_index,
                                               &origin_path) != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to get key origin path");
    complete_validation(VALIDATION_PARSE_ERROR);
    return;
  }

  // Parse the origin path to extract attributes
  wallet_network_t desc_network;
  wallet_policy_t desc_policy;
  uint32_t desc_account;

  if (!parse_origin_path(origin_path, &desc_network, &desc_policy,
                         &desc_account)) {
    ESP_LOGE(TAG, "Failed to parse origin path: %s", origin_path);
    wally_free_string(origin_path);
    complete_validation(VALIDATION_PARSE_ERROR);
    return;
  }
  wally_free_string(origin_path);

  // Get current wallet attributes
  wallet_network_t wallet_network = wallet_get_network();
  wallet_policy_t wallet_policy = wallet_get_policy();
  uint32_t wallet_account = wallet_get_account();

  // Check for mismatches
  bool network_mismatch = (desc_network != wallet_network);
  bool policy_mismatch = (desc_policy != wallet_policy);
  bool account_mismatch = (desc_account != wallet_account);

  if (!network_mismatch && !policy_mismatch && !account_mismatch) {
    // No changes needed - verify xpub directly
    complete_validation(verify_xpub_and_load());
    return;
  }

  // Store target attributes for later application
  current_ctx->target_network = desc_network;
  current_ctx->target_policy = desc_policy;
  current_ctx->target_account = desc_account;
  current_ctx->needs_network_change = network_mismatch;
  current_ctx->needs_policy_change = policy_mismatch;
  current_ctx->needs_account_change = account_mismatch;

  // Build confirmation message
  char message[384];
  int offset = 0;
  offset += snprintf(message + offset, sizeof(message) - offset,
                     "Descriptor requires different settings:\n\n");

  if (network_mismatch) {
    const char *current_net =
        (wallet_network == WALLET_NETWORK_MAINNET) ? "Mainnet" : "Testnet";
    const char *target_net =
        (desc_network == WALLET_NETWORK_MAINNET) ? "Mainnet" : "Testnet";
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Network: %s -> %s\n", current_net, target_net);
  }

  if (policy_mismatch) {
    const char *current_pol =
        (wallet_policy == WALLET_POLICY_SINGLESIG) ? "Single-sig" : "Multisig";
    const char *target_pol =
        (desc_policy == WALLET_POLICY_SINGLESIG) ? "Single-sig" : "Multisig";
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Policy: %s -> %s\n", current_pol, target_pol);
  }

  if (account_mismatch) {
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Account: %u -> %u\n", wallet_account, desc_account);
  }

  snprintf(message + offset, sizeof(message) - offset,
           "\nApply these changes?");

  // Request confirmation via callback (UI-agnostic)
  if (current_ctx->confirm_cb) {
    current_ctx->confirm_cb(message, attribute_change_confirm_cb);
  } else {
    // No confirmation callback provided, decline by default
    complete_validation(VALIDATION_USER_DECLINED);
  }
}

void descriptor_validate_and_load(const char *descriptor_str,
                                  validation_complete_cb callback,
                                  validation_confirm_cb confirm_cb,
                                  void *user_data) {
  // Clean up any previous context
  cleanup_context();

  if (!descriptor_str || !callback) {
    if (callback) {
      callback(VALIDATION_INTERNAL_ERROR, user_data);
    }
    return;
  }

  if (!key_is_loaded() || !wallet_is_initialized()) {
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return;
  }

  // Allocate context
  current_ctx = malloc(sizeof(validation_context_t));
  if (!current_ctx) {
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return;
  }
  memset(current_ctx, 0, sizeof(validation_context_t));

  current_ctx->descriptor_str = strdup(descriptor_str);
  if (!current_ctx->descriptor_str) {
    cleanup_context();
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return;
  }

  current_ctx->callback = callback;
  current_ctx->confirm_cb = confirm_cb;
  current_ctx->user_data = user_data;

  // Parse descriptor
  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;

  struct wally_descriptor *descriptor = NULL;
  int ret = wally_descriptor_parse(descriptor_str, NULL, wally_network, 0,
                                   &descriptor);

  // If parsing fails with current network, try the other network
  if (ret != WALLY_OK) {
    wally_network = (wally_network == WALLY_NETWORK_BITCOIN_MAINNET)
                        ? WALLY_NETWORK_BITCOIN_TESTNET
                        : WALLY_NETWORK_BITCOIN_MAINNET;
    ret = wally_descriptor_parse(descriptor_str, NULL, wally_network, 0,
                                 &descriptor);
  }

  if (ret != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to parse descriptor: %d", ret);
    complete_validation(VALIDATION_PARSE_ERROR);
    return;
  }

  // Stage 1: Find our key by fingerprint
  int key_index = find_matching_key_index(descriptor);
  if (key_index < 0) {
    ESP_LOGE(TAG, "Wallet fingerprint not found in descriptor");
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_FINGERPRINT_NOT_FOUND);
    return;
  }

  // Stage 2 & 3: Check attributes and verify xpub
  check_attributes_and_verify(descriptor, key_index);
  wally_descriptor_free(descriptor);
}
