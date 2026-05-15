#include "descriptor_validator.h"
#include "key.h"
#include "wallet.h"
#include <esp_log.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#include "../ui/dialog.h"
#include "descriptor_checksum.h"
#include "registry.h"
#include "ss_whitelist.h"
#include "storage.h"

static const char *TAG = "descriptor_validator";

/* Keep the persistent-registration path dormant until descriptor backups can be
 * encrypted to the descriptor's own public keys, per the Bitcoin Encrypted
 * Backup proposal in bitcoin/bips#1951. */
#define DESCRIPTOR_PERSISTENT_REGISTRATION_ENABLED 0

typedef struct {
  char *descriptor_str;
  validation_complete_cb callback;
  validation_confirm_cb confirm_cb;
  validation_info_confirm_cb info_confirm_cb;
  validation_id_loc_cb id_loc_cb;
  void *user_data;
  descriptor_info_t info;
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

// Parse multisig threshold from descriptor string (e.g., "multi(2,..." -> 2)
static uint32_t parse_multisig_threshold(const char *descriptor_str) {
  const char *multi = strstr(descriptor_str, "multi(");
  if (!multi) {
    return 0;
  }
  const char *num_start = multi + 6; // skip "multi("
  char *end = NULL;
  long val = strtol(num_start, &end, 10);
  if (end == num_start || val <= 0) {
    return 0;
  }
  return (uint32_t)val;
}

// Extract descriptor info (policy type, keys) from parsed descriptor
static bool extract_descriptor_info(struct wally_descriptor *descriptor,
                                    const char *descriptor_str,
                                    descriptor_info_t *info) {
  memset(info, 0, sizeof(descriptor_info_t));

  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(descriptor, &num_keys) != WALLY_OK) {
    return false;
  }

  info->is_multisig = (num_keys > 1);
  info->num_keys = (num_keys > DESCRIPTOR_INFO_MAX_KEYS)
                       ? DESCRIPTOR_INFO_MAX_KEYS
                       : num_keys;

  if (info->is_multisig) {
    info->threshold = parse_multisig_threshold(descriptor_str);
  }

  for (uint32_t i = 0; i < info->num_keys; i++) {
    // Fingerprint
    unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
    if (wally_descriptor_get_key_origin_fingerprint(
            descriptor, i, fp, BIP32_KEY_FINGERPRINT_LEN) == WALLY_OK) {
      snprintf(info->keys[i].fingerprint_hex,
               sizeof(info->keys[i].fingerprint_hex), "%02X%02X%02X%02X", fp[0],
               fp[1], fp[2], fp[3]);
    } else {
      strncpy(info->keys[i].fingerprint_hex, "N/A",
              sizeof(info->keys[i].fingerprint_hex));
    }

    // Xpub
    char *key_str = NULL;
    if (wally_descriptor_get_key(descriptor, i, &key_str) == WALLY_OK) {
      char *xpub = extract_xpub_from_key(key_str);
      if (xpub) {
        strncpy(info->keys[i].xpub, xpub, sizeof(info->keys[i].xpub) - 1);
        info->keys[i].xpub[sizeof(info->keys[i].xpub) - 1] = '\0';
        free(xpub);
      }
      wally_free_string(key_str);
    }

    // Derivation path
    char *path_str = NULL;
    if (wally_descriptor_get_key_origin_path_str(descriptor, i, &path_str) ==
        WALLY_OK) {
      snprintf(info->keys[i].derivation, sizeof(info->keys[i].derivation),
               "m/%s", path_str);
      wally_free_string(path_str);
    } else {
      strncpy(info->keys[i].derivation, "N/A",
              sizeof(info->keys[i].derivation));
    }
  }

  return true;
}

static void id_loc_proceed(const char *id, storage_location_t loc,
                           void *user_data) {
  (void)user_data;
  if (!id || strlen(id) == 0) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }
  if (!registry_add_from_string(id, current_ctx->descriptor_str, loc, true)) {
    ESP_LOGE(TAG, "Failed to register descriptor '%s'", id);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }
  complete_validation(VALIDATION_SUCCESS);
}

static bool descriptor_checksum_for_session_id(const char *descriptor_str,
                                               char out[9]) {
  if (!descriptor_str || !out)
    return false;

  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;
  struct wally_descriptor *desc = NULL;
  if (wally_descriptor_parse(descriptor_str, NULL, wally_network, 0, &desc) !=
      WALLY_OK) {
    return false;
  }

  bool ok = descriptor_checksum_from_descriptor(desc, out);
  wally_descriptor_free(desc);
  if (!ok)
    return false;
  return true;
}

static bool build_session_descriptor_id(char out[REGISTRY_ID_MAX_LEN]) {
  char checksum[9];
  if (!descriptor_checksum_for_session_id(current_ctx->descriptor_str,
                                          checksum))
    return false;

  char base[REGISTRY_ID_MAX_LEN];
  snprintf(base, sizeof(base), "desc_%s", checksum);

  for (size_t i = 0; i < REGISTRY_MAX_ENTRIES; i++) {
    if (i == 0)
      snprintf(out, REGISTRY_ID_MAX_LEN, "%s", base);
    else
      snprintf(out, REGISTRY_ID_MAX_LEN, "%s_%zu", base, i + 1);

    if (!registry_find_by_id(out))
      return true;
  }

  return false;
}

static void build_session_descriptor_label(char out[REGISTRY_LABEL_MAX_LEN]) {
  if (!out)
    return;

  if (current_ctx->info.is_multisig) {
    snprintf(out, REGISTRY_LABEL_MAX_LEN, "Multisig (%u of %u)",
             current_ctx->info.threshold, current_ctx->info.num_keys);
  } else {
    snprintf(out, REGISTRY_LABEL_MAX_LEN, "Single-sig");
  }
}

static void session_register_current_descriptor(void) {
  char id[REGISTRY_ID_MAX_LEN];
  if (!build_session_descriptor_id(id)) {
    ESP_LOGE(TAG, "Failed to build session descriptor id");
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  if (!registry_add_from_string(id, current_ctx->descriptor_str, STORAGE_FLASH,
                                false)) {
    ESP_LOGE(TAG, "Failed to load session descriptor '%s'", id);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  char label[REGISTRY_LABEL_MAX_LEN];
  build_session_descriptor_label(label);
  registry_set_label(id, label);

  complete_validation(VALIDATION_SUCCESS);
}

// Callback after user confirms/declines descriptor info
static void info_confirm_proceed(bool confirmed, void *user_data) {
  (void)user_data;

  if (!confirmed) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }

  /* Descriptor registration is disabled: load into the in-memory session
   * registry only. Keep id_loc_cb wired for the future registration flow, but
   * skip it until encrypted descriptor backups are ready. */
  if (DESCRIPTOR_PERSISTENT_REGISTRATION_ENABLED && current_ctx->id_loc_cb) {
    current_ctx->id_loc_cb(id_loc_proceed, NULL);
  } else {
    session_register_current_descriptor();
  }
}

static void psb_warn_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }
  if (current_ctx->info_confirm_cb) {
    current_ctx->info_confirm_cb(&current_ctx->info, info_confirm_proceed);
  } else {
    info_confirm_proceed(true, NULL);
  }
}

// Re-parse descriptor, verify xpub matches wallet, extract info, and show it.
static void verify_xpub_and_show_info(void) {
  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;

  struct wally_descriptor *descriptor = NULL;
  if (wally_descriptor_parse(current_ctx->descriptor_str, NULL, wally_network,
                             0, &descriptor) != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to parse descriptor for xpub verification");
    complete_validation(VALIDATION_PARSE_ERROR);
    return;
  }

  int key_index = find_matching_key_index(descriptor);
  if (key_index < 0) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_FINGERPRINT_NOT_FOUND);
    return;
  }

  char *key_str = NULL;
  if (wally_descriptor_get_key(descriptor, key_index, &key_str) != WALLY_OK) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  char *descriptor_xpub = extract_xpub_from_key(key_str);
  wally_free_string(key_str);

  if (!descriptor_xpub) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_PARSE_ERROR);
    return;
  }

  char *origin_path_str = NULL;
  char full_path[72];
  if (wally_descriptor_get_key_origin_path_str(descriptor, (uint32_t)key_index,
                                               &origin_path_str) != WALLY_OK ||
      !origin_path_str) {
    free(descriptor_xpub);
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }
  snprintf(full_path, sizeof(full_path), "m/%s", origin_path_str);
  wally_free_string(origin_path_str);

  char *wallet_xpub = NULL;
  if (!key_get_xpub(full_path, &wallet_xpub)) {
    free(descriptor_xpub);
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return;
  }

  bool xpub_match = (strcmp(descriptor_xpub, wallet_xpub) == 0);
  free(descriptor_xpub);
  wally_free_string(wallet_xpub);

  if (!xpub_match) {
    ESP_LOGE(TAG, "XPub mismatch");
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_XPUB_MISMATCH);
    return;
  }

  // Run soft purpose-script binding check before freeing the descriptor.
  psb_result_t psb_result = purpose_script_binding_check_soft(descriptor);

  // Build the WARN message while the descriptor is still available.
  char psb_msg[128] = {0};
  if (psb_result == PSB_WARN) {
    // Determine outer script name from canonical form.
    const char *script_name = "unknown";
    char *canon = NULL;
    if (wally_descriptor_canonicalize(
            descriptor, WALLY_MS_CANONICAL_NO_CHECKSUM, &canon) == WALLY_OK &&
        canon) {
      if (strncmp(canon, "sh(wpkh(", 8) == 0)
        script_name = "sh(wpkh)";
      else if (strncmp(canon, "sh(wsh(", 7) == 0)
        script_name = "sh(wsh)";
      else if (strncmp(canon, "wpkh(", 5) == 0)
        script_name = "wpkh";
      else if (strncmp(canon, "wsh(", 4) == 0)
        script_name = "wsh";
      else if (strncmp(canon, "pkh(", 4) == 0)
        script_name = "pkh";
      else if (strncmp(canon, "tr(", 3) == 0)
        script_name = "tr";
      wally_free_string(canon);
    }
    // Extract purpose number from key[0] origin path.
    uint32_t purpose = 0;
    char *path = NULL;
    if (wally_descriptor_get_key_origin_path_str(descriptor, 0, &path) ==
            WALLY_OK &&
        path && path[0] != '\0') {
      char *endp = NULL;
      unsigned long ul = strtoul(path, &endp, 10);
      if (endp != path && ul <= 0x7FFFFFFFul)
        purpose = (uint32_t)ul;
      wally_free_string(path);
    }
    snprintf(psb_msg, sizeof(psb_msg),
             "This descriptor uses a purpose-%" PRIu32 " origin\n"
             "wrapped in a %s script.\n"
             "This is unusual. Register anyway?",
             purpose, script_name);
  }

  // Extract descriptor info before freeing.
  extract_descriptor_info(descriptor, current_ctx->descriptor_str,
                          &current_ctx->info);
  wally_descriptor_free(descriptor);

  // If purpose-script binding mismatch: gate behind a WARN dialog.
  if (psb_result == PSB_WARN) {
    dialog_show_danger_confirm(psb_msg, psb_warn_confirm_cb, NULL,
                               DIALOG_STYLE_OVERLAY);
    return;
  }

  // PSB_OK or PSB_NA: proceed to info confirmation.
  if (current_ctx->info_confirm_cb) {
    current_ctx->info_confirm_cb(&current_ctx->info, info_confirm_proceed);
  } else {
    info_confirm_proceed(true, NULL);
  }
}

void descriptor_validate_and_load(const char *descriptor_str,
                                  validation_complete_cb callback,
                                  validation_confirm_cb confirm_cb,
                                  validation_info_confirm_cb info_confirm_cb,
                                  validation_id_loc_cb id_loc_cb,
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
  current_ctx->info_confirm_cb = info_confirm_cb;
  current_ctx->id_loc_cb = id_loc_cb;
  current_ctx->user_data = user_data;

  // Parse on the wallet's network; if that fails, probe the other
  // network so we can return NETWORK_MISMATCH instead of a generic
  // parse error.
  uint32_t wally_network = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? WALLY_NETWORK_BITCOIN_MAINNET
                               : WALLY_NETWORK_BITCOIN_TESTNET;

  struct wally_descriptor *descriptor = NULL;
  int ret = wally_descriptor_parse(descriptor_str, NULL, wally_network, 0,
                                   &descriptor);

  if (ret != WALLY_OK) {
    uint32_t other_network = (wally_network == WALLY_NETWORK_BITCOIN_MAINNET)
                                 ? WALLY_NETWORK_BITCOIN_TESTNET
                                 : WALLY_NETWORK_BITCOIN_MAINNET;
    struct wally_descriptor *other_desc = NULL;
    if (wally_descriptor_parse(descriptor_str, NULL, other_network, 0,
                               &other_desc) == WALLY_OK) {
      wally_descriptor_free(other_desc);
      complete_validation(VALIDATION_NETWORK_MISMATCH);
      return;
    }
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

  wally_descriptor_free(descriptor);

  /* Stage 1.5: dedup against the current in-memory session only. Descriptor
   * files on flash/SD are explicit backups/import sources and must not behave
   * as registered descriptors while persistent registration is disabled. */
  char existing_id[REGISTRY_ID_MAX_LEN];
  if (registry_session_has_duplicate(current_ctx->descriptor_str, existing_id,
                                     sizeof(existing_id))) {
    char msg[96];
    if (existing_id[0])
      snprintf(msg, sizeof(msg), "Descriptor already loaded as '%s'",
               existing_id);
    else
      snprintf(msg, sizeof(msg), "Descriptor already loaded");
    dialog_show_error(msg, NULL, 2500);
    complete_validation(VALIDATION_DUPLICATE);
    return;
  }

  verify_xpub_and_show_info();
}
