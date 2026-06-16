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

#include "descriptor_checksum.h"
#include "miniscript_policy.h"
#include "psbt_internal.h"
#include "registry.h"
#include "ss_whitelist.h"
#include "storage.h"

static const char *TAG = "descriptor_validator";

/* Keep the persistent-registration path dormant until descriptor backups can be
 * encrypted to the descriptor's own public keys, per the Bitcoin Encrypted
 * Backup proposal in bitcoin/bips#1951. */
#define DESCRIPTOR_PERSISTENT_REGISTRATION_ENABLED 0

typedef struct {
  uint32_t generation; /* set once at create; see pending_generation below */
  char *descriptor_str;
  validation_complete_cb callback;
  validation_confirm_cb confirm_cb;
  validation_info_confirm_cb info_confirm_cb;
  validation_id_loc_cb id_loc_cb;
  void *user_data;
  descriptor_info_t info;
  char descriptor_checksum[9];
  bool watch_only;                /* keyless: skip key/xpub stages */
  wallet_network_t watch_network; /* network for the watch-only registry add */
} validation_context_t;

static validation_context_t *current_ctx = NULL;

/* Monotonic generation assigned to each validate_and_load call. If a previous
 * validation is interrupted (session timeout, navigation away from a pending
 * dialog) and the user starts a new one, the old static callbacks may still
 * fire after current_ctx has been replaced. Each schedule point captures the
 * live ctx's generation into pending_generation; the callback compares it on
 * fire and no-ops on mismatch, preventing the old flow from corrupting the
 * new one (or completing it with the wrong result code). */
static uint32_t next_generation = 1;
static uint32_t pending_generation = 0;

/* Last duplicate descriptor ID stashed by descriptor_validate_and_load before
 * delivering VALIDATION_DUPLICATE. The page layer fetches this via
 * descriptor_validator_get_duplicate_id() and renders the toast itself, so
 * core stays UI-free. Cleared at the start of each validate_and_load call. */
static char last_duplicate_id[REGISTRY_ID_MAX_LEN];

static uint32_t wallet_descriptor_network(void) {
  return (wallet_get_network() == WALLET_NETWORK_MAINNET)
             ? WALLY_NETWORK_BITCOIN_MAINNET
             : WALLY_NETWORK_BITCOIN_TESTNET;
}

static uint32_t alternate_descriptor_network(uint32_t network) {
  return (network == WALLY_NETWORK_BITCOIN_MAINNET)
             ? WALLY_NETWORK_BITCOIN_TESTNET
             : WALLY_NETWORK_BITCOIN_MAINNET;
}

static descriptor_validation_result_t
parse_descriptor_for_wallet(const char *descriptor_str,
                            struct wally_descriptor **descriptor_out) {
  if (!descriptor_str || !descriptor_out)
    return VALIDATION_INTERNAL_ERROR;

  *descriptor_out = NULL;
  uint32_t wally_network = wallet_descriptor_network();
  int ret = wally_descriptor_parse(descriptor_str, NULL, wally_network, 0,
                                   descriptor_out);
  if (ret == WALLY_OK)
    return VALIDATION_SUCCESS;

  struct wally_descriptor *other_desc = NULL;
  if (wally_descriptor_parse(descriptor_str, NULL,
                             alternate_descriptor_network(wally_network), 0,
                             &other_desc) == WALLY_OK) {
    wally_descriptor_free(other_desc);
    return VALIDATION_NETWORK_MISMATCH;
  }

  ESP_LOGE(TAG, "Failed to parse descriptor: %d", ret);
  return VALIDATION_PARSE_ERROR;
}

static bool ctx_callback_is_live(void) {
  return current_ctx && pending_generation != 0 &&
         current_ctx->generation == pending_generation;
}

static void cleanup_context(void) {
  if (current_ctx) {
    if (current_ctx->descriptor_str) {
      free(current_ctx->descriptor_str);
    }
    free(current_ctx);
    current_ctx = NULL;
  }
  pending_generation = 0;
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

// True if the parsed descriptor contains miniscript-only fragments.
// libwally sets WALLY_MS_IS_DESCRIPTOR at parse start and clears it when a
// non-descriptor (miniscript) fragment is found; multi()/sortedmulti() keep it.
static bool descriptor_is_miniscript(const struct wally_descriptor *desc) {
  uint32_t features = 0;
  if (wally_descriptor_get_features(desc, &features) != WALLY_OK)
    return false;
  return (features & WALLY_MS_IS_DESCRIPTOR) == 0;
}

// Miniscript is only supported as segwit v0, i.e. wrapped in a plain wsh().
static bool
miniscript_wrapper_is_supported(const struct wally_descriptor *desc) {
  char *canon = NULL;
  if (wally_descriptor_canonicalize(desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canon) != WALLY_OK ||
      !canon)
    return false;
  bool is_wsh = (strncmp(canon, "wsh(", 4) == 0);
  wally_free_string(canon);
  return is_wsh;
}

// libwally accepts descriptors at parse time that its script generator later
// rejects: multi()/sortedmulti() above 15 keys and sh()/wsh() inner scripts
// over PSBT_MAX_INNER_SCRIPT_LEN (520) bytes. Trial-generate the scriptPubKey
// so unusable descriptors fail at load time instead of at address derivation
// or signing time. A too-small buffer is reported as WALLY_OK with written >
// len, hence the explicit written check.
static bool
descriptor_scripts_are_generatable(const struct wally_descriptor *desc) {
  uint8_t work[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t written = 0;
  return wally_descriptor_to_script(desc, 0, 0, 0, 0, 0, 0, work, sizeof(work),
                                    &written) == WALLY_OK &&
         written <= sizeof(work);
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

  info->is_miniscript = descriptor_is_miniscript(descriptor);
  info->is_multisig = !info->is_miniscript && (num_keys > 1);

  if (info->is_miniscript) {
    char *policy = miniscript_policy_string(descriptor);
    if (policy) {
      snprintf(info->policy, sizeof(info->policy), "%s", policy);
      free(policy);
    }
  }
  /* Unreachable for loadable descriptors: the script-size guard caps key
   * counts well below DESCRIPTOR_INFO_MAX_KEYS. Defensive bound for keys[]. */
  if (num_keys > DESCRIPTOR_INFO_MAX_KEYS) {
    return false;
  }
  info->num_keys = num_keys;

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
  if (!ctx_callback_is_live())
    return;
  pending_generation = 0;
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

static bool build_session_descriptor_id(char out[REGISTRY_ID_MAX_LEN]) {
  if (current_ctx->descriptor_checksum[0] == '\0')
    return false;

  char base[REGISTRY_ID_MAX_LEN];
  snprintf(base, sizeof(base), "desc_%s", current_ctx->descriptor_checksum);

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

  if (current_ctx->info.is_miniscript) {
    snprintf(out, REGISTRY_LABEL_MAX_LEN, "Miniscript (%u key%s)",
             current_ctx->info.num_keys,
             current_ctx->info.num_keys == 1 ? "" : "s");
  } else if (current_ctx->info.is_multisig) {
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

  bool added = current_ctx->watch_only
                   ? registry_add_watch_only(id, current_ctx->descriptor_str,
                                             current_ctx->watch_network)
                   : registry_add_from_string(id, current_ctx->descriptor_str,
                                              STORAGE_FLASH, false);
  if (!added) {
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
  if (!ctx_callback_is_live())
    return;
  pending_generation = 0;

  if (!confirmed) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }

  /* Descriptor registration is disabled: load into the in-memory session
   * registry only. Keep id_loc_cb wired for the future registration flow, but
   * skip it until encrypted descriptor backups are ready. */
  if (DESCRIPTOR_PERSISTENT_REGISTRATION_ENABLED && current_ctx->id_loc_cb) {
    pending_generation = current_ctx->generation;
    current_ctx->id_loc_cb(id_loc_proceed, NULL);
  } else {
    session_register_current_descriptor();
  }
}

static void psb_warn_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!ctx_callback_is_live())
    return;
  pending_generation = 0;
  if (!confirmed) {
    complete_validation(VALIDATION_USER_DECLINED);
    return;
  }
  if (current_ctx->info_confirm_cb) {
    pending_generation = current_ctx->generation;
    current_ctx->info_confirm_cb(&current_ctx->info, info_confirm_proceed);
  } else {
    info_confirm_proceed(true, NULL);
  }
}

// Verify xpub matches wallet, extract info, and show it.
static void verify_xpub_and_show_info(struct wally_descriptor *descriptor,
                                      int key_index) {
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

  // If purpose-script binding mismatch: gate behind a WARN confirmation
  // rendered by the page layer.
  if (psb_result == PSB_WARN) {
    if (current_ctx->confirm_cb) {
      pending_generation = current_ctx->generation;
      current_ctx->confirm_cb(psb_msg, psb_warn_confirm_cb);
    } else {
      // No way to prompt the user: treat as declined.
      complete_validation(VALIDATION_USER_DECLINED);
    }
    return;
  }

  // PSB_OK or PSB_NA: proceed to info confirmation.
  if (current_ctx->info_confirm_cb) {
    pending_generation = current_ctx->generation;
    current_ctx->info_confirm_cb(&current_ctx->info, info_confirm_proceed);
  } else {
    info_confirm_proceed(true, NULL);
  }
}

/* Shared prologue for both validate entry points: guards, context allocation,
 * descriptor copy, common callback wiring, parse, and the keyless static checks
 * (miniscript wrapper, script generatability). On success returns
 * VALIDATION_SUCCESS with *out set to the parsed descriptor (caller owns it);
 * on failure the result is already delivered and *out is NULL. */
static descriptor_validation_result_t
validation_begin(const char *descriptor_str, validation_complete_cb callback,
                 validation_info_confirm_cb info_confirm_cb, void *user_data,
                 struct wally_descriptor **out) {
  *out = NULL;
  cleanup_context();
  last_duplicate_id[0] = '\0';

  if (!descriptor_str || !callback) {
    if (callback)
      callback(VALIDATION_INTERNAL_ERROR, user_data);
    return VALIDATION_INTERNAL_ERROR;
  }

  if (descriptor_text_has_uppercase_hardened(descriptor_str)) {
    callback(VALIDATION_INVALID_HARDENED_NOTATION, user_data);
    return VALIDATION_INVALID_HARDENED_NOTATION;
  }

  current_ctx = malloc(sizeof(validation_context_t));
  if (!current_ctx) {
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return VALIDATION_INTERNAL_ERROR;
  }
  memset(current_ctx, 0, sizeof(validation_context_t));
  current_ctx->generation = next_generation++;
  if (next_generation == 0) /* avoid the 0 sentinel after wrap */
    next_generation = 1;

  current_ctx->descriptor_str = strdup(descriptor_str);
  if (!current_ctx->descriptor_str) {
    cleanup_context();
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return VALIDATION_INTERNAL_ERROR;
  }

  current_ctx->callback = callback;
  current_ctx->info_confirm_cb = info_confirm_cb;
  current_ctx->user_data = user_data;

  struct wally_descriptor *descriptor = NULL;
  descriptor_validation_result_t parse_result =
      parse_descriptor_for_wallet(current_ctx->descriptor_str, &descriptor);
  if (parse_result != VALIDATION_SUCCESS) {
    complete_validation(parse_result);
    return parse_result;
  }

  if (descriptor_is_miniscript(descriptor) &&
      !miniscript_wrapper_is_supported(descriptor)) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_UNSUPPORTED_MINISCRIPT);
    return VALIDATION_UNSUPPORTED_MINISCRIPT;
  }

  if (!descriptor_scripts_are_generatable(descriptor)) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_UNSUPPORTED_SCRIPT);
    return VALIDATION_UNSUPPORTED_SCRIPT;
  }

  *out = descriptor;
  return VALIDATION_SUCCESS;
}

/* Store the descriptor checksum, then reject duplicates already in the
 * in-memory session (h-normalized BIP-380 checksum match). Descriptor files on
 * flash/SD are explicit import sources, not registered descriptors, so dedup is
 * session-scoped. On failure frees `descriptor`, delivers the result, and
 * returns false; the caller must stop. */
static bool checksum_and_dedup(struct wally_descriptor *descriptor) {
  if (!descriptor_checksum_from_descriptor(descriptor,
                                           current_ctx->descriptor_checksum)) {
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_INTERNAL_ERROR);
    return false;
  }

  char existing_id[REGISTRY_ID_MAX_LEN];
  if (registry_session_has_duplicate_checksum(
          current_ctx->descriptor_checksum, existing_id, sizeof(existing_id))) {
    wally_descriptor_free(descriptor);
    strncpy(last_duplicate_id, existing_id, sizeof(last_duplicate_id) - 1);
    last_duplicate_id[sizeof(last_duplicate_id) - 1] = '\0';
    complete_validation(VALIDATION_DUPLICATE);
    return false;
  }
  return true;
}

void descriptor_validate_and_load(const char *descriptor_str,
                                  validation_complete_cb callback,
                                  validation_confirm_cb confirm_cb,
                                  validation_info_confirm_cb info_confirm_cb,
                                  validation_id_loc_cb id_loc_cb,
                                  void *user_data) {
  if (descriptor_str && callback &&
      (!key_is_loaded() || !wallet_is_initialized())) {
    cleanup_context();
    callback(VALIDATION_INTERNAL_ERROR, user_data);
    return;
  }

  struct wally_descriptor *descriptor = NULL;
  if (validation_begin(descriptor_str, callback, info_confirm_cb, user_data,
                       &descriptor) != VALIDATION_SUCCESS)
    return;

  current_ctx->confirm_cb = confirm_cb;
  current_ctx->id_loc_cb = id_loc_cb;

  int key_index = find_matching_key_index(descriptor);
  if (key_index < 0) {
    ESP_LOGE(TAG, "Wallet fingerprint not found in descriptor");
    wally_descriptor_free(descriptor);
    complete_validation(VALIDATION_FINGERPRINT_NOT_FOUND);
    return;
  }

  if (!checksum_and_dedup(descriptor))
    return;

  verify_xpub_and_show_info(descriptor, key_index);
}

// Watch-only: extract info and show the "Load?" dialog, skipping the xpub
// verification and PSB warning that the keyed path performs.
static void watch_only_show_info(struct wally_descriptor *descriptor) {
  extract_descriptor_info(descriptor, current_ctx->descriptor_str,
                          &current_ctx->info);
  wally_descriptor_free(descriptor);

  if (current_ctx->info_confirm_cb) {
    pending_generation = current_ctx->generation;
    current_ctx->info_confirm_cb(&current_ctx->info, info_confirm_proceed);
  } else {
    info_confirm_proceed(true, NULL);
  }
}

bool descriptor_infer_network(const char *descriptor_str,
                              wallet_network_t *network_out) {
  if (!descriptor_str || !network_out)
    return false;
  struct wally_descriptor *desc = NULL;
  if (wally_descriptor_parse(descriptor_str, NULL,
                             WALLY_NETWORK_BITCOIN_MAINNET, 0,
                             &desc) == WALLY_OK) {
    wally_descriptor_free(desc);
    *network_out = WALLET_NETWORK_MAINNET;
    return true;
  }
  if (wally_descriptor_parse(descriptor_str, NULL,
                             WALLY_NETWORK_BITCOIN_TESTNET, 0,
                             &desc) == WALLY_OK) {
    wally_descriptor_free(desc);
    *network_out = WALLET_NETWORK_TESTNET;
    return true;
  }
  return false;
}

void descriptor_validate_and_load_watch_only(
    const char *descriptor_str, wallet_network_t network,
    validation_complete_cb callback, validation_info_confirm_cb info_confirm_cb,
    void *user_data) {
  struct wally_descriptor *descriptor = NULL;
  if (validation_begin(descriptor_str, callback, info_confirm_cb, user_data,
                       &descriptor) != VALIDATION_SUCCESS)
    return;

  current_ctx->watch_only = true;
  current_ctx->watch_network = network;

  if (!checksum_and_dedup(descriptor))
    return;

  watch_only_show_info(descriptor);
}

bool descriptor_validator_get_duplicate_id(char *out, size_t out_len) {
  if (!out || out_len == 0 || last_duplicate_id[0] == '\0')
    return false;
  if (strlen(last_duplicate_id) >= out_len)
    return false;
  strncpy(out, last_duplicate_id, out_len);
  out[out_len - 1] = '\0';
  return true;
}
