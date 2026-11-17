#include "bip_flow.h"

#include "../../components/bbqr/src/bbqr.h"
#include "../../core/bip32_path.h"
#include "../../core/debug_log.h"
#include "../../core/key.h"
#include "../../core/psbt.h"
#include "../../core/registry.h"
#include "../../core/settings.h"
#include "../../core/silent_payments.h"
#include "../../core/sp_psbt.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/parser.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../scan/scan.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "bip388.h"
#include <bipqr.h>
#include <esp_app_desc.h>
#include <inttypes.h>
#include <kern_wally.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>

#define KERN_CAPABILITIES                                                      \
  (BIPQR_CAPABILITY_BIP380_DESCRIPTORS |                                       \
   BIPQR_CAPABILITY_BIP388_WALLET_POLICIES |                                   \
   BIPQR_CAPABILITY_MINISCRIPT_SEGWIT_V0 |                                     \
   BIPQR_CAPABILITY_MINISCRIPT_TAPROOT |                                       \
   BIPQR_CAPABILITY_SILENT_PAYMENT_SENDS |                                     \
   BIPQR_CAPABILITY_SILENT_PAYMENT_ACCOUNTS |                                  \
   BIPQR_CAPABILITY_UNREGISTER_DESCRIPTOR)

typedef struct {
  lv_obj_t *parent;
  void (*return_cb)(void);
  bip_flow_header_t header;
  const bipqr_request *request;
} bip_flow_ctx_t;

static bip_flow_ctx_t ctx;
// The verified address and its BIP-321 URI, both from malloc()
static char *pending_verified_address = NULL;
static char *pending_verified_uri = NULL;
// What the verified address is, shown under the title
static char pending_verify_caption[REGISTRY_ID_MAX_LEN + 32];
static lv_obj_t *verify_address_detail = NULL;
static lv_obj_t *verify_address_approve_btn = NULL;
static bool signing_response_return_pending = false;

static void destroy_verify_address_detail(void) {
  if (verify_address_detail) {
    lv_obj_del(verify_address_detail);
    verify_address_detail = NULL;
  }
  verify_address_approve_btn = NULL;
}

static void clear_pending_verify(void) {
  destroy_verify_address_detail();
  free(pending_verified_address);
  pending_verified_address = NULL;
  free(pending_verified_uri);
  pending_verified_uri = NULL;
  pending_verify_caption[0] = '\0';
}

bool bip_flow_can_handle(const uint8_t *data, size_t len) {
  return data && len >= 6 && memcmp(data, "BIP", 3) == 0;
}

static void cleanup_request(void) {
  registry_clear_preferred();
  registry_sp_clear_named_scan_keys();
  if (ctx.request) {
    bipqr_request_free(ctx.request);
    ctx.request = NULL;
  }
}

static void return_from_response(void) {
  qr_viewer_page_destroy();
  clear_pending_verify();
  cleanup_request();
  if (ctx.return_cb)
    ctx.return_cb();
}

static void signing_response_return_timer_cb(lv_timer_t *timer) {
  (void)timer;
  debug_log_event("bip_flow signing_response deferred_return");
  signing_response_return_pending = false;
  qr_viewer_page_destroy();
  cleanup_request();
  if (ctx.return_cb)
    ctx.return_cb();
}

static void return_from_signing_response(void) {
  debug_log_event("bip_flow signing_response done");
  if (signing_response_return_pending)
    return;
  signing_response_return_pending = true;
  lv_timer_t *timer =
      lv_timer_create(signing_response_return_timer_cb, 1, NULL);
  if (timer) {
    lv_timer_set_repeat_count(timer, 1);
  } else {
    signing_response_return_pending = false;
    signing_response_return_timer_cb(NULL);
  }
}

static void show_response_sized(bipqr_response *response, void (*done_cb)(void),
                                int max_chars) {
  debug_logf("bip_flow show_response is_error=%d", response->is_error);
  bipqr_buf encoded = {0};
  const char *err = NULL;
  int32_t rc = bipqr_response_encode(response, &encoded, &err);
  if (rc != BIPQR_OK || !encoded.ptr || encoded.len == 0) {
    cleanup_request();
    dialog_show_error_timeout(err ? err : "Failed to encode response",
                              ctx.return_cb, 0);
    return;
  }

  BBQrParts *parts =
      bbqr_encode_hex(encoded.ptr, encoded.len, BBQR_TYPE_BINARY, max_chars);
  // A Get Keys response can hold a private key
  secure_memzero(encoded.ptr, encoded.len);
  bipqr_buf_free(encoded);
  if (!parts) {
    cleanup_request();
    dialog_show_error_timeout("Failed to encode response QR", ctx.return_cb, 0);
    return;
  }

  if (!qr_viewer_page_create_with_bbqr_parts(ctx.parent, parts, "Response QR",
                                             done_cb)) {
    cleanup_request();
    dialog_show_error_timeout("Failed to display response", ctx.return_cb, 0);
    return;
  }
  qr_viewer_page_show();
}

static void show_response_with_done(bipqr_response *response,
                                    void (*done_cb)(void)) {
  show_response_sized(response, done_cb, settings_get_qr_density());
}

static void show_response(bipqr_response *response) {
  show_response_with_done(response, return_from_response);
}

static void fill_response_header(bipqr_response *response) {
  memset(response, 0, sizeof(*response));
  memcpy(response->id, ctx.header.id, BIPQR_REQUEST_ID_LEN);
  response->message_type = ctx.header.message_type;
}

static void fill_error_response(bipqr_response *response, uint8_t error,
                                const char *message) {
  debug_logf("bip_flow error_response code=%u msg=%s", (unsigned)error,
             message ? message : "");
  fill_response_header(response);
  response->is_error = true;
  response->body.error.error = error;
  response->body.error.message = message ? message : "Error";
}

static void show_error_response(uint8_t error, const char *message) {
  bipqr_response response;
  fill_error_response(&response, error, message);
  show_response(&response);
}

// Kern keeps its registrations on the device and issues no proof of
// registration, so a proof it receives is not one of its own
static void show_foreign_proof_error(void) {
  show_error_response(BIPQR_RESPONSE_ERROR_INVALID_PROOF,
                      "Kern issues no proof of registration");
}

static bool wallet_is_testnet(void) {
  return wallet_get_network() == WALLET_NETWORK_TESTNET;
}

static void fill_device_fields(const char **vendor, const char **model,
                               bipqr_firmware_version *version,
                               uint32_t *capabilities) {
  *vendor = "Kern";
  *model = CONFIG_KERN_BOARD_NAME;
  const esp_app_desc_t *desc = esp_app_get_description();
  unsigned major = 0, minor = 0, patch = 0;
  if (desc)
    sscanf(desc->version, "%u.%u.%u", &major, &minor, &patch);
  version->major = (uint16_t)major;
  version->minor = (uint16_t)minor;
  version->patch = patch;
  version->flag = BIPQR_RELEASE_STABLE;
  *capabilities = KERN_CAPABILITIES;
}

// Ready with a loaded seed, locked while an encrypted one waits on flash
static bool device_state(uint8_t *state_out) {
  if (key_is_loaded()) {
    *state_out = BIPQR_STATE_READY;
    return true;
  }
  char **files = NULL;
  int count = 0;
  if (storage_list_mnemonics(STORAGE_FLASH, &files, &count) != ESP_OK)
    return false;
  storage_free_file_list(files, count);
  *state_out = count > 0 ? BIPQR_STATE_LOCKED : BIPQR_STATE_UNINITIALIZED;
  return true;
}

static void handle_get_info(void) {
  bipqr_response response;
  fill_response_header(&response);
  bipqr_info *info = &response.body.info;
  fill_device_fields(&info->vendor, &info->model, &info->version,
                     &info->capabilities);
  if (!device_state(&info->state)) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Storage failed");
    return;
  }
  // Coin 1' covers testnet and signet; no regtest, Kern only encodes tb
  // addresses
  info->networks =
      BIPQR_NETWORK_MAINNET | BIPQR_NETWORK_TESTNET | BIPQR_NETWORK_SIGNET;
  info->max_message = QR_PARSER_MAX_STORED_BYTES;
  info->max_alias = REGISTRY_ID_MAX_LEN - 1;
  if (info->state == BIPQR_STATE_READY) {
    if (!key_get_fingerprint(info->fingerprint)) {
      show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Fingerprint failed");
      return;
    }
    info->has_fingerprint = 1;
  }
  show_response(&response);
}

static bool xpub_base58_to_wire(const char *xpub, bipqr_extended_key *out) {
  struct ext_key *key = NULL;
  bool ok = false;
  if (bip32_key_from_base58_alloc(xpub, &key) == WALLY_OK && key) {
    uint8_t serialized[BIPQR_EXTENDED_KEY_LEN];
    if (bip32_key_serialize(key, BIP32_FLAG_KEY_PUBLIC, serialized,
                            sizeof(serialized)) == WALLY_OK) {
      memcpy(out->bytes, serialized, sizeof(out->bytes));
      ok = true;
    }
  }
  if (key)
    bip32_key_free(key);
  return ok;
}

static bool public_key_to_wire(const bipqr_path *path,
                               bipqr_extended_key *out) {
  char *xpub = NULL;
  bool ok = key_get_xpub_components(path->ptr, path->len, &xpub) && xpub &&
            xpub_base58_to_wire(xpub, out);
  if (xpub)
    wally_free_string(xpub);
  return ok;
}

static bool private_key_to_wire(const bipqr_path *path,
                                bipqr_extended_key *out) {
  struct ext_key *key = NULL;
  if (!key_get_derived_key_components(path->ptr, path->len, &key))
    return false;
  bool ok = bip32_key_serialize(key, BIP32_FLAG_KEY_PRIVATE, out->bytes,
                                sizeof(out->bytes)) == WALLY_OK;
  bip32_key_free(key);
  return ok;
}

static void free_keys(bipqr_extended_key *keys, size_t n) {
  secure_memzero(keys, n * sizeof(*keys));
  free(keys);
}

static void get_keys_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    show_error_response(BIPQR_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }

  const bipqr_get_keys *req = &ctx.request->body.get_keys;
  size_t n = req->keys.len;
  bipqr_extended_key *keys = calloc(n, sizeof(*keys));
  // An empty KEYS vector is valid and gets an empty one back
  if (!keys && n) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }

  for (size_t i = 0; i < n; i++) {
    const bipqr_key_request *key = &req->keys.ptr[i];
    bool ok = key->kind == BIPQR_KEY_PRIVATE
                  ? private_key_to_wire(&key->derivation_path, &keys[i])
                  : public_key_to_wire(&key->derivation_path, &keys[i]);
    if (!ok) {
      free_keys(keys, n);
      show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Key failed");
      return;
    }
  }

  bipqr_response response;
  fill_response_header(&response);
  response.body.keys.keys.ptr = keys;
  response.body.keys.keys.len = n;
  if (!key_get_fingerprint(response.body.keys.fingerprint)) {
    free_keys(keys, n);
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Fingerprint failed");
    return;
  }
  fill_device_fields(&response.body.keys.vendor, &response.body.keys.model,
                     &response.body.keys.version,
                     &response.body.keys.capabilities);
  // A quarter of the data per frame: half the modules per side, twice as big
  int max_chars = settings_get_qr_density() / 4;
  show_response_sized(&response, return_from_response,
                      max_chars < QR_DENSITY_MIN ? QR_DENSITY_MIN : max_chars);
  free_keys(keys, n);
}

static bool path_requested_network(const bipqr_path *path,
                                   wallet_network_t *network_out) {
  if (!path || !network_out || path->len < 2)
    return false;

  uint32_t coin = bip32_path_unharden(path->ptr[1]);
  if (coin == 0) {
    *network_out = WALLET_NETWORK_MAINNET;
    return true;
  }
  if (coin == 1) {
    *network_out = WALLET_NETWORK_TESTNET;
    return true;
  }
  return false;
}

static bool get_keys_network_matches_wallet(const bipqr_key_request_list *keys,
                                            char *message,
                                            size_t message_size) {
  if (!keys || !keys->ptr)
    return true;

  bool have_network = false;
  wallet_network_t requested = WALLET_NETWORK_MAINNET;
  for (size_t i = 0; i < keys->len; i++) {
    wallet_network_t path_network;
    if (!path_requested_network(&keys->ptr[i].derivation_path, &path_network))
      continue;
    if (!have_network) {
      requested = path_network;
      have_network = true;
      continue;
    }
    if (requested != path_network) {
      snprintf(message, message_size,
               "Request mixes mainnet and testnet paths");
      return false;
    }
  }

  if (!have_network || requested == wallet_get_network())
    return true;

  snprintf(message, message_size,
           "Request is for %s. Switch Kern network first.",
           requested == WALLET_NETWORK_MAINNET ? "Mainnet" : "Testnet");
  return false;
}

static size_t appendf(char *buf, size_t buf_size, size_t off, const char *fmt,
                      ...) {
  if (off >= buf_size)
    return off;

  va_list args;
  va_start(args, fmt);
  int written = vsnprintf(buf + off, buf_size - off, fmt, args);
  va_end(args);
  if (written < 0)
    return off;
  off += (size_t)written;
  return off > buf_size ? buf_size : off;
}

static size_t append_path_component(char *buf, size_t buf_size, size_t off,
                                    uint32_t component) {
  uint32_t child = bip32_path_unharden(component);
  return bip32_path_is_hardened(component)
             ? appendf(buf, buf_size, off, "/%u'", (unsigned)child)
             : appendf(buf, buf_size, off, "/%u", (unsigned)child);
}

static bool format_key_path_range(const bipqr_key_request_list *keys, char *buf,
                                  size_t buf_size) {
  if (!keys || keys->len < 2 || !keys->ptr || !buf || buf_size == 0)
    return false;

  uint8_t depth = keys->ptr[0].derivation_path.len;
  if (depth == 0)
    return false;

  int varying_index = -1;
  for (uint8_t i = 0; i < depth; i++) {
    uint32_t first = keys->ptr[0].derivation_path.ptr[i];
    bool varies = false;
    for (size_t j = 1; j < keys->len; j++) {
      if (!keys->ptr[j].derivation_path.ptr ||
          keys->ptr[j].derivation_path.len != depth)
        return false;
      if (keys->ptr[j].derivation_path.ptr[i] != first)
        varies = true;
    }
    if (!varies)
      continue;
    if (varying_index >= 0)
      return false;
    varying_index = i;
  }
  if (varying_index < 0)
    return false;

  uint32_t first = keys->ptr[0].derivation_path.ptr[varying_index];
  bool hardened = bip32_path_is_hardened(first);
  uint32_t first_child = bip32_path_unharden(first);
  for (size_t i = 1; i < keys->len; i++) {
    uint32_t component = keys->ptr[i].derivation_path.ptr[varying_index];
    if (bip32_path_is_hardened(component) != hardened)
      return false;
    if (bip32_path_unharden(component) != first_child + i)
      return false;
  }

  size_t off = appendf(buf, buf_size, 0, "m");
  for (uint8_t i = 0; i < depth; i++) {
    if (i == (uint8_t)varying_index) {
      uint32_t last_child = first_child + (uint32_t)keys->len - 1;
      off = appendf(buf, buf_size, off, hardened ? "/{%u-%u}'" : "/{%u-%u}",
                    (unsigned)first_child, (unsigned)last_child);
    } else {
      off = append_path_component(buf, buf_size, off,
                                  keys->ptr[0].derivation_path.ptr[i]);
    }
  }

  return off < buf_size;
}

static size_t append_key_request_paths(char *msg, size_t msg_size, size_t off,
                                       const bipqr_key_request_list *keys) {
  char range_path[128];
  if (format_key_path_range(keys, range_path, sizeof(range_path)))
    return appendf(msg, msg_size, off, "\n\n%s", range_path);

  size_t shown = keys->len < 6 ? keys->len : 6;
  for (size_t i = 0; i < shown && off < msg_size; i++) {
    char path[96];
    if (!bip32_path_format(keys->ptr[i].derivation_path.ptr,
                           keys->ptr[i].derivation_path.len, path,
                           sizeof(path))) {
      snprintf(path, sizeof(path), "<invalid path>");
    }
    off = appendf(msg, msg_size, off, "\n%s", path);
  }
  if (keys->len > shown)
    off = appendf(msg, msg_size, off, "\n...and %zu more", keys->len - shown);
  return off;
}

static bool get_keys_has_private(const bipqr_key_request_list *keys) {
  for (size_t i = 0; i < keys->len; i++) {
    if (keys->ptr[i].kind == BIPQR_KEY_PRIVATE)
      return true;
  }
  return false;
}

// Only the BIP352 scan key leaves the device, so a wallet can scan
static bool get_keys_private_allowed(const bipqr_key_request_list *keys) {
  for (size_t i = 0; i < keys->len; i++) {
    const bipqr_path *path = &keys->ptr[i].derivation_path;
    if (keys->ptr[i].kind == BIPQR_KEY_PRIVATE &&
        !sp_path_on_branch(path->ptr, path->len, wallet_is_testnet(),
                           SP_SCAN_BRANCH))
      return false;
  }
  return true;
}

static void handle_get_keys(void) {
  const bipqr_get_keys *req = &ctx.request->body.get_keys;
  char mismatch[80];
  if (!get_keys_network_matches_wallet(&req->keys, mismatch,
                                       sizeof(mismatch))) {
    debug_logf("bip_flow keys_network_mismatch msg=%s", mismatch);
    show_error_response(BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH, mismatch);
    return;
  }
  if (!get_keys_private_allowed(&req->keys)) {
    show_error_response(BIPQR_RESPONSE_ERROR_PRIVATE_KEY_EXPORT_REFUSED,
                        "Private key export refused");
    return;
  }

  char msg[512];
  size_t off =
      snprintf(msg, sizeof(msg), "Export %zu key(s)?\n", req->keys.len);
  off = append_key_request_paths(msg, sizeof(msg), off, &req->keys);
  if (get_keys_has_private(&req->keys))
    appendf(msg, sizeof(msg), off,
            "\n\nIncludes the scan private key: whoever holds it sees every "
            "payment this account receives, but cannot spend them.");
  dialog_show_confirm(msg, get_keys_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static char *request_descriptor_alloc(const bipqr_descriptor_body *body) {
  if (!body)
    return NULL;
  if (body->tag == BIPQR_DESCRIPTOR_BIP380)
    return body->value.bip380 ? strdup(body->value.bip380) : NULL;
  if (body->tag == BIPQR_DESCRIPTOR_BIP388)
    return bip388_descriptor_alloc(body->value.bip388.policy,
                                   body->value.bip388.keys.ptr,
                                   body->value.bip388.keys.len);
  return NULL;
}

// The error a body request_descriptor_alloc() gives no descriptor for answers
// with: registration failed when it holds none, such as a wallet policy whose
// @N names no key, internal error when the descriptor could not be allocated
static uint8_t request_descriptor_error(const bipqr_descriptor_body *body) {
  bool has_descriptor =
      body && ((body->tag == BIPQR_DESCRIPTOR_BIP380 && body->value.bip380) ||
               (body->tag == BIPQR_DESCRIPTOR_BIP388 &&
                bip388_policy_is_valid(body->value.bip388.policy,
                                       body->value.bip388.keys.ptr,
                                       body->value.bip388.keys.len)));
  return has_descriptor ? BIPQR_RESPONSE_ERROR_INTERNAL
                        : BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
}

static const char *
register_error_message(descriptor_validation_result_t result) {
  switch (result) {
  case VALIDATION_FINGERPRINT_NOT_FOUND:
    return "Key not found in descriptor";
  case VALIDATION_XPUB_MISMATCH:
    return "A key with your fingerprint is not yours";
  case VALIDATION_PARSE_ERROR:
    return "Invalid descriptor format";
  case VALIDATION_INVALID_HARDENED_NOTATION:
    return "Descriptor uses 'H'. Use ' or h for hardened.";
  case VALIDATION_UNSUPPORTED_MINISCRIPT:
    return "Only wsh() and tr() miniscript is supported";
  case VALIDATION_UNSUPPORTED_TOP_LEVEL:
    return "Descriptor type not supported (use sh, wsh or tr)";
  case VALIDATION_UNSUPPORTED_SCRIPT:
    return "Script too large (max 15 multisig keys)";
  case VALIDATION_PRIVATE_KEY:
    return "Descriptor contains a private key";
  case VALIDATION_TOO_MANY_KEYS:
    return "Too many keys in descriptor";
  case VALIDATION_UNSUPPORTED_KEY_ORIGIN:
    return "Your key's derivation path is not supported";
  case VALIDATION_TR_INTERNAL_NOT_UNSPENDABLE:
    return "Taproot internal key not provably unspendable";
  case VALIDATION_NETWORK_MISMATCH:
    return "Descriptor network mismatch";
  case VALIDATION_DUPLICATE:
    return "Descriptor already registered";
  case VALIDATION_INTERNAL_ERROR:
  default:
    return "Registration failed";
  }
}

// The registration status of the request's alias: a descriptor, stored or
// for the session, or our silent payment account, always stored
static void answer_registration(void) {
  const char *alias = ctx.request->body.register_descriptor.descriptor_alias;
  const registry_entry_t *entry = registry_find_by_id(alias);
  bool sp_account = registry_sp_alias_exists(alias);
  bipqr_response response;
  fill_response_header(&response);
  response.body.registration.descriptor_alias = alias;
  response.body.registration.registered = entry || sp_account;
  response.body.registration.stored = (entry && entry->persisted) || sp_account;
  show_response(&response);
}

static void show_alias_taken_error(void) {
  show_error_response(BIPQR_RESPONSE_ERROR_ALREADY_REGISTERED,
                      "Alias already registered");
}

static void register_validation_cb(descriptor_validation_result_t result,
                                   void *user_data) {
  (void)user_data;
  debug_logf("bip_flow register_validation result=%d", result);
  if (result != VALIDATION_SUCCESS) {
    show_error_response(bip_flow_register_error(result),
                        register_error_message(result));
    return;
  }
  answer_registration();
}

// Registers `descriptor` under the request's alias, which `entry` already
// holds when not NULL: a stored alias is taken, a session one may be
// registered again with its own descriptor
static void register_descriptor(const registry_entry_t *entry,
                                const char *descriptor) {
  const char *alias = ctx.request->body.register_descriptor.descriptor_alias;
  if ((entry && (entry->persisted ||
                 !registry_entry_is_descriptor(entry, descriptor))) ||
      registry_sp_alias_exists(alias)) {
    show_alias_taken_error();
    return;
  }
  if (strlen(alias) >= REGISTRY_ID_MAX_LEN) {
    show_error_response(BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                        "Alias too long");
    return;
  }
  debug_logf("bip_flow register descriptor_ok alias=%s", alias);
  descriptor_loader_process_string_with_id(descriptor, alias, STORAGE_FLASH,
                                           register_validation_cb, NULL);
}

static void register_sp_account(const bipqr_register_descriptor *req);

// Without a descriptor the request only asks whether the alias is registered
static void handle_register(void) {
  debug_log_event("bip_flow handle_register");
  const bipqr_register_descriptor *req = &ctx.request->body.register_descriptor;
  const registry_entry_t *entry = registry_find_by_id(req->descriptor_alias);
  if (!req->descriptor) {
    answer_registration();
    return;
  }
  if (req->descriptor->tag == BIPQR_DESCRIPTOR_SP_KEYS) {
    register_sp_account(req);
    return;
  }
  char *descriptor = request_descriptor_alloc(req->descriptor);
  if (!descriptor) {
    uint8_t error = request_descriptor_error(req->descriptor);
    show_error_response(error, error == BIPQR_RESPONSE_ERROR_INTERNAL
                                   ? "Out of memory"
                                   : "Invalid wallet policy");
    return;
  }
  register_descriptor(entry, descriptor);
  free(descriptor);
}

// The registry entry of `alias`, the session registering `body` under it
// when the alias is unknown. Returns 0 or the error code to answer with.
static uint8_t resolve_descriptor(const char *alias,
                                  const bipqr_descriptor_body *body,
                                  const registry_entry_t **entry_out) {
  *entry_out = registry_find_by_id(alias);
  if (*entry_out)
    return 0;
  if (!body)
    return BIPQR_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS;
  char *descriptor = request_descriptor_alloc(body);
  if (!descriptor)
    return request_descriptor_error(body);
  wallet_network_t network;
  if (descriptor_infer_network(descriptor, &network) &&
      network != wallet_get_network()) {
    free(descriptor);
    return BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH;
  }
  bool added =
      registry_add_from_string(alias, descriptor, STORAGE_FLASH, false);
  free(descriptor);
  *entry_out = added ? registry_find_by_id(alias) : NULL;
  return *entry_out ? 0 : BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
}

// Whose account the request's silent payment keys are
static sp_account_t request_sp_account(const bipqr_sp_keys *sp) {
  bool scan_by_path = sp->scan_kind == BIPQR_SCAN_PATH;
  return sp_account_classify(
      sp->fingerprint, sp->spend_path.ptr, sp->spend_path.len,
      scan_by_path ? sp->scan.path.ptr : NULL,
      scan_by_path ? sp->scan.path.len : 0, scan_by_path ? NULL : sp->scan.key,
      wallet_is_testnet());
}

// The scan key of an account whose scan key is not ours, else NULL
static const unsigned char *scan_key_not_ours(const bipqr_sp_keys *sp,
                                              sp_account_t account) {
  return account == SP_ACCOUNT_FOREIGN_SCAN ? sp->scan.key : NULL;
}

// True for an account of our spend key, else the error is answered
static bool sp_account_ok(sp_account_t account) {
  switch (account) {
  case SP_ACCOUNT_OURS:
  case SP_ACCOUNT_FOREIGN_SCAN:
    return true;
  case SP_ACCOUNT_OTHER_NETWORK:
    show_error_response(BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH,
                        "Silent payment account is for another network");
    return false;
  case SP_ACCOUNT_NOT_OURS:
    show_error_response(BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                        "Not this device's silent payment account");
    return false;
  case SP_ACCOUNT_BAD_SCAN_KEY:
    show_error_response(BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Invalid scan key");
    return false;
  case SP_ACCOUNT_ERR_KEYS:
  default:
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Key failed");
    return false;
  }
}

static void sp_register_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    show_error_response(BIPQR_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }
  const bipqr_register_descriptor *req = &ctx.request->body.register_descriptor;
  const bipqr_sp_keys *sp = &req->descriptor->value.sp_keys;
  if (!registry_add_sp_alias(req->descriptor_alias,
                             scan_key_not_ours(sp, request_sp_account(sp)))) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL,
                        "Storing the registration failed");
    return;
  }
  answer_registration();
}

// Registers the request's alias for our silent payment spend key with our
// scan key or the one the request gives, so later requests may name the
// account by its alias alone
static void register_sp_account(const bipqr_register_descriptor *req) {
  const bipqr_sp_keys *sp = &req->descriptor->value.sp_keys;
  const char *alias = req->descriptor_alias;
  sp_account_t account = request_sp_account(sp);
  if (!sp_account_ok(account))
    return;
  if (registry_find_by_id(alias) || registry_sp_alias_exists(alias)) {
    show_alias_taken_error();
    return;
  }
  if (strlen(alias) >= REGISTRY_ID_MAX_LEN) {
    show_error_response(BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                        "Alias too long");
    return;
  }
  if (registry_sp_alias_count() >= REGISTRY_MAX_ENTRIES) {
    show_error_response(BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                        "No room for another silent payment account");
    return;
  }
  char msg[128];
  snprintf(
      msg, sizeof(msg), "Register silent payment keys?\n\nAlias: %s%s", alias,
      scan_key_not_ours(sp, account) ? "\nScan key: external, not this device's"
                                     : "");
  dialog_show_confirm(msg, sp_register_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void show_descriptor_error(uint8_t error) {
  switch (error) {
  case BIPQR_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS:
    show_error_response(error, "Unknown descriptor alias");
    break;
  case BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH:
    show_error_response(error, "Descriptor network mismatch");
    break;
  case BIPQR_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM:
    show_error_response(error, "Descriptor form not taken here");
    break;
  case BIPQR_RESPONSE_ERROR_INTERNAL:
    show_error_response(error, "Out of memory");
    break;
  default:
    show_error_response(error, "Descriptor registration failed");
    break;
  }
}

// The address at `path`, the path under the descriptor: the position in its
// <a;b> tuple when it has several paths, then the index when it is ranged
static bool address_from_entry_path(const registry_entry_t *entry,
                                    const bipqr_path *path, char **out) {
  uint32_t features = 0;
  if (wally_descriptor_get_features(entry->desc, &features) != WALLY_OK)
    return false;
  bool multipath = entry->num_paths > 1;
  bool ranged = features & WALLY_MS_IS_RANGED;
  size_t want = (multipath ? 1 : 0) + (ranged ? 1 : 0);
  if (path->len != want)
    return false;
  for (size_t i = 0; i < want; i++) {
    if (bip32_path_is_hardened(path->ptr[i]))
      return false;
  }
  uint32_t multi_index = multipath ? path->ptr[0] : 0;
  uint32_t child_num = ranged ? path->ptr[want - 1] : 0;
  if (multi_index >= entry->num_paths)
    return false;
  return wally_descriptor_to_address(entry->desc, 0, multi_index, child_num, 0,
                                     out) == WALLY_OK;
}

static bool address_to_spk(const char *address, bool is_testnet,
                           unsigned char *script, size_t script_len,
                           size_t *written) {
  return wally_addr_segwit_to_bytes(address, is_testnet ? "tb" : "bc", 0,
                                    script, script_len, written) == WALLY_OK ||
         wally_address_to_scriptpubkey(address,
                                       is_testnet
                                           ? WALLY_NETWORK_BITCOIN_TESTNET
                                           : WALLY_NETWORK_BITCOIN_MAINNET,
                                       script, script_len, written) == WALLY_OK;
}

// 0 when `given` pays the script of `derived` on the wallet network, else the
// error to answer: Kern signs for the other network on another setting and
// never for regtest
static uint8_t address_error(const char *given, const char *derived) {
  bool testnet = wallet_is_testnet();
  unsigned char given_script[128];
  unsigned char derived_script[128];
  size_t given_len = 0;
  size_t derived_len = 0;
  if (!address_to_spk(given, testnet, given_script, sizeof(given_script),
                      &given_len))
    return address_to_spk(given, !testnet, given_script, sizeof(given_script),
                          &given_len) ||
                   wally_addr_segwit_to_bytes(given, "bcrt", 0, given_script,
                                              sizeof(given_script),
                                              &given_len) == WALLY_OK
               ? BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH
               : BIPQR_RESPONSE_ERROR_ADDRESS_MISMATCH;
  bool same = address_to_spk(derived, testnet, derived_script,
                             sizeof(derived_script), &derived_len) &&
              given_len == derived_len &&
              memcmp(given_script, derived_script, given_len) == 0;
  return same ? 0 : BIPQR_RESPONSE_ERROR_ADDRESS_MISMATCH;
}

static void verify_address_approve_enable_cb(lv_timer_t *timer) {
  (void)timer;
  if (verify_address_approve_btn)
    lv_obj_clear_state(verify_address_approve_btn, LV_STATE_DISABLED);
}

static void verify_address_done_cb(lv_event_t *e) {
  (void)e;
  destroy_verify_address_detail();
  bipqr_response response;
  fill_response_header(&response);
  response.body.address_uri.uri = pending_verified_uri;
  show_response(&response);
}

static void show_verify_address_detail(void) {
  destroy_verify_address_detail();

  int32_t pad = theme_default_padding();
  int32_t scr_w = theme_screen_width();
  bool landscape = theme_is_landscape();
  int32_t square_size = theme_min_dim() * 55 / 100;

  verify_address_detail = lv_obj_create(lv_screen_active());
  lv_obj_set_size(verify_address_detail, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(verify_address_detail);
  lv_obj_set_style_pad_all(verify_address_detail, pad, 0);
  lv_obj_set_flex_flow(verify_address_detail, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(verify_address_detail, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(verify_address_detail, pad, 0);

  lv_obj_t *title =
      theme_create_label(verify_address_detail, "Verify Address", false);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);

  lv_obj_t *caption =
      theme_create_label(verify_address_detail, pending_verify_caption, true);
  lv_obj_set_width(caption, LV_PCT(95));
  lv_label_set_long_mode(caption, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(caption, LV_TEXT_ALIGN_CENTER, 0);

  lv_obj_t *content = lv_obj_create(verify_address_detail);
  lv_obj_remove_style_all(content);
  lv_obj_set_size(content, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(content,
                       landscape ? LV_FLEX_FLOW_ROW : LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(content, pad, 0);
  lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);

  char *upper = qr_bech32_to_upper(pending_verified_address);
  const char *qr_payload = upper ? upper : pending_verified_address;
  lv_obj_t *qr_container = theme_create_qr_container(content, square_size, 15);
  qr_create_optimal(qr_container, square_size - 30, qr_payload);
  qr_viewer_attach_fullscreen(qr_container, qr_payload, "Verify Address");
  free(upper);

  lv_obj_t *addr_label =
      theme_create_label(content, pending_verified_address, false);
  if (landscape)
    lv_obj_set_width(addr_label, scr_w - 2 * pad - square_size - pad);
  else
    lv_obj_set_width(addr_label, LV_PCT(95));
  lv_label_set_long_mode(addr_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(addr_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(addr_label, theme_font_medium(), 0);

  verify_address_approve_btn = lv_btn_create(verify_address_detail);
  lv_obj_set_size(verify_address_approve_btn, LV_PCT(60), LV_SIZE_CONTENT);
  theme_apply_touch_button(verify_address_approve_btn, true);
  lv_obj_add_state(verify_address_approve_btn, LV_STATE_DISABLED);
  lv_obj_t *approve_lbl = lv_label_create(verify_address_approve_btn);
  lv_label_set_text(approve_lbl, "Done");
  lv_obj_center(approve_lbl);
  theme_apply_button_label(approve_lbl, true);
  lv_obj_add_event_cb(verify_address_approve_btn, verify_address_done_cb,
                      LV_EVENT_CLICKED, NULL);
  lv_timer_t *enable_timer =
      lv_timer_create(verify_address_approve_enable_cb, 500, NULL);
  lv_timer_set_repeat_count(enable_timer, 1);
}

// Shows `address` (malloc()ed, taken over) under `caption` for the user to
// check, then answers with `uri_prefix` and the address
static void show_verified_address(char *address, const char *uri_prefix,
                                  const char *caption) {
  size_t uri_len = strlen(uri_prefix) + strlen(address) + 1;
  pending_verified_address = address;
  snprintf(pending_verify_caption, sizeof(pending_verify_caption), "%s",
           caption);
  pending_verified_uri = malloc(uri_len);
  if (!pending_verified_uri) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }
  snprintf(pending_verified_uri, uri_len, "%s%s", uri_prefix, address);
  debug_log_event("bip_flow verify show_detail");
  show_verify_address_detail();
}

// "<alias> receive #7", "<alias> change #3", "<alias> path 2/5": the address
// `path` names under the descriptor of `entry`, as address_from_entry_path
// reads it
static void descriptor_address_caption(const char *alias,
                                       const registry_entry_t *entry,
                                       const bipqr_path *path, char *out,
                                       size_t out_len) {
  bool multipath = entry->num_paths > 1;
  bool ranged = path->len > (multipath ? 1 : 0);
  uint32_t position = multipath ? path->ptr[0] : 0;
  uint32_t index = ranged ? path->ptr[path->len - 1] : 0;
  const char *branch = NULL;
  if (multipath && position == 0)
    branch = "receive";
  else if (multipath && position == 1)
    branch = "change";

  if (branch && ranged)
    snprintf(out, out_len, "%s %s #%" PRIu32, alias, branch, index);
  else if (branch)
    snprintf(out, out_len, "%s %s", alias, branch);
  else if (multipath && ranged)
    snprintf(out, out_len, "%s path %" PRIu32 "/%" PRIu32, alias, position,
             index);
  else if (multipath)
    snprintf(out, out_len, "%s path %" PRIu32, alias, position);
  else if (ranged)
    snprintf(out, out_len, "%s #%" PRIu32, alias, index);
  else
    snprintf(out, out_len, "%s", alias);
}

static void verify_descriptor_address(const bipqr_verify_address *req) {
  const registry_entry_t *entry = NULL;
  uint8_t error =
      resolve_descriptor(req->descriptor_alias, req->descriptor, &entry);
  if (error) {
    show_descriptor_error(error);
    return;
  }
  char *derived = NULL;
  if (!address_from_entry_path(entry, &req->derivation_path, &derived) ||
      !derived) {
    show_error_response(BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Path does not fit the descriptor");
    return;
  }
  char *address = strdup(derived);
  wally_free_string(derived);
  if (!address) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }
  uint8_t mismatch = req->address ? address_error(req->address, address) : 0;
  if (mismatch) {
    free(address);
    show_error_response(mismatch,
                        mismatch == BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH
                            ? "Address is for another network"
                            : "Address mismatch");
    return;
  }
  char caption[sizeof(pending_verify_caption)];
  descriptor_address_caption(req->descriptor_alias, entry,
                             &req->derivation_path, caption, sizeof(caption));
  show_verified_address(address, "bitcoin:", caption);
}

static void verify_sp_address_with(const bipqr_verify_address *req,
                                   const unsigned char *scan_secret,
                                   const unsigned char *spend_pubkey) {
  char *address = NULL;
  switch (sp_account_address_alloc(
      scan_secret, spend_pubkey, req->derivation_path.ptr,
      req->derivation_path.len, wallet_is_testnet(), &address)) {
  case SP_ADDRESS_OK:
    break;
  case SP_ADDRESS_ERR_LABEL:
    show_error_response(BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Label must be one step m >= 1");
    return;
  case SP_ADDRESS_ERR_KEY:
    show_error_response(BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Invalid scan key");
    return;
  case SP_ADDRESS_ERR_ALLOC:
  default:
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Address failed");
    return;
  }
  if (req->address && strcasecmp(req->address, address) != 0) {
    free(address);
    show_error_response(BIPQR_RESPONSE_ERROR_ADDRESS_MISMATCH,
                        "Address mismatch");
    return;
  }
  char caption[sizeof(pending_verify_caption)];
  if (req->derivation_path.len == 1)
    snprintf(caption, sizeof(caption), "%s label %" PRIu32,
             req->descriptor_alias, req->derivation_path.ptr[0]);
  else
    snprintf(caption, sizeof(caption), "%s base address",
             req->descriptor_alias);
  show_verified_address(address, "bitcoin:?sp=", caption);
}

// An address with the HRP of the other network or of regtest
static bool sp_address_on_other_network(const char *address) {
  const char *other = wallet_is_testnet() ? "sp1" : "tsp1";
  return strncasecmp(address, other, strlen(other)) == 0 ||
         strncasecmp(address, "sprt1", strlen("sprt1")) == 0;
}

// The address of our spend key with our scan key, or with `scan_key` when
// not NULL
static void verify_own_sp_address(const bipqr_verify_address *req,
                                  const unsigned char *scan_key) {
  if (req->address && sp_address_on_other_network(req->address)) {
    show_error_response(BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH,
                        "Address is for another network");
    return;
  }
  struct sp_keys keys;
  if (!sp_account_keys_derive(wallet_is_testnet(), scan_key, &keys)) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Key failed");
    return;
  }
  verify_sp_address_with(req, keys.scan_secret, keys.spend_pubkey);
  sp_keys_wipe(&keys);
}

// The spend key must be ours, the scan key ours or the one the request gives
static void verify_sp_address(const bipqr_verify_address *req) {
  const bipqr_sp_keys *sp = &req->descriptor->value.sp_keys;
  sp_account_t account = request_sp_account(sp);
  if (sp_account_ok(account))
    verify_own_sp_address(req, scan_key_not_ours(sp, account));
}

// A registered alias names what it was registered for, whatever the body
static void handle_verify(void) {
  debug_log_event("bip_flow handle_verify");
  const bipqr_verify_address *req = &ctx.request->body.verify_address;
  if (req->proof.ptr) {
    show_foreign_proof_error();
    return;
  }
  bool sp_body =
      req->descriptor && req->descriptor->tag == BIPQR_DESCRIPTOR_SP_KEYS;
  if (registry_sp_alias_exists(req->descriptor_alias))
    verify_own_sp_address(req,
                          registry_sp_alias_scan_key(req->descriptor_alias));
  else if (sp_body && !registry_find_by_id(req->descriptor_alias))
    verify_sp_address(req);
  else
    verify_descriptor_address(req);
}

static size_t signed_input_count(const struct wally_psbt *psbt) {
  if (!psbt)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    size_t n = 0;
    if (wally_psbt_get_input_signatures_size(psbt, i, &n) == WALLY_OK && n > 0)
      count++;
    else if (wally_psbt_get_input_taproot_signature_len(psbt, i, &n) ==
                 WALLY_OK &&
             n > 0)
      count++;
    else if (psbt->inputs[i].taproot_leaf_signatures.num_items > 0)
      count++;
  }
  return count;
}

static void free_signature_list(bipqr_signature *signatures, size_t len) {
  if (!signatures)
    return;
  for (size_t i = 0; i < len; i++) {
    switch (signatures[i].kind) {
    case BIPQR_SIGNATURE_ECDSA:
      free((void *)signatures[i].value.ecdsa.signature.ptr);
      break;
    case BIPQR_SIGNATURE_TAP_KEY:
      free((void *)signatures[i].value.tap_key.signature.ptr);
      break;
    case BIPQR_SIGNATURE_TAP_SCRIPT:
      free((void *)signatures[i].value.tap_script.signature.ptr);
      break;
    default:
      break;
    }
  }
  free(signatures);
}

static bool copy_signature_bytes(const uint8_t *src, size_t len,
                                 bipqr_bytes *out) {
  uint8_t *copy = malloc(len);
  if (!copy)
    return false;
  memcpy(copy, src, len);
  out->ptr = copy;
  out->len = len;
  return true;
}

static bool append_signature(bipqr_signature **signatures, size_t *len,
                             size_t *cap, const bipqr_signature *sig) {
  if (*len == *cap) {
    size_t new_cap = *cap ? *cap * 2 : 4;
    bipqr_signature *new_signatures =
        realloc(*signatures, new_cap * sizeof(*new_signatures));
    if (!new_signatures)
      return false;
    *signatures = new_signatures;
    *cap = new_cap;
  }
  (*signatures)[(*len)++] = *sig;
  return true;
}

static bool collect_signatures(const struct wally_psbt *psbt,
                               bipqr_signature **signatures_out,
                               size_t *len_out) {
  bipqr_signature *signatures = NULL;
  size_t len = 0, cap = 0;

  for (size_t input_index = 0; input_index < psbt->num_inputs; input_index++) {
    const struct wally_psbt_input *input = &psbt->inputs[input_index];
    for (size_t j = 0; j < input->signatures.num_items; j++) {
      const struct wally_map_item *item = &input->signatures.items[j];
      if (item->key_len != BIPQR_PUBLIC_KEY_LEN || !item->key || !item->value)
        continue;
      bipqr_signature sig = {.input_index = (uint32_t)input_index,
                             .kind = BIPQR_SIGNATURE_ECDSA};
      memcpy(sig.value.ecdsa.public_key, item->key, BIPQR_PUBLIC_KEY_LEN);
      if (!copy_signature_bytes(item->value, item->value_len,
                                &sig.value.ecdsa.signature) ||
          !append_signature(&signatures, &len, &cap, &sig)) {
        free((void *)sig.value.ecdsa.signature.ptr);
        free_signature_list(signatures, len);
        return false;
      }
    }

    size_t tap_key_sig_len = 0;
    if (wally_psbt_get_input_taproot_signature_len(
            psbt, input_index, &tap_key_sig_len) == WALLY_OK &&
        tap_key_sig_len > 0) {
      uint8_t *tap_key_sig = malloc(tap_key_sig_len);
      size_t written = 0;
      if (!tap_key_sig ||
          wally_psbt_get_input_taproot_signature(psbt, input_index, tap_key_sig,
                                                 tap_key_sig_len,
                                                 &written) != WALLY_OK ||
          written != tap_key_sig_len) {
        free(tap_key_sig);
        free_signature_list(signatures, len);
        return false;
      }
      bipqr_signature sig = {.input_index = (uint32_t)input_index,
                             .kind = BIPQR_SIGNATURE_TAP_KEY};
      sig.value.tap_key.signature.ptr = tap_key_sig;
      sig.value.tap_key.signature.len = tap_key_sig_len;
      if (!append_signature(&signatures, &len, &cap, &sig)) {
        free(tap_key_sig);
        free_signature_list(signatures, len);
        return false;
      }
    }

    for (size_t j = 0; j < input->taproot_leaf_signatures.num_items; j++) {
      const struct wally_map_item *item =
          &input->taproot_leaf_signatures.items[j];
      if (item->key_len != 64 || !item->key || !item->value)
        continue;
      bipqr_signature sig = {.input_index = (uint32_t)input_index,
                             .kind = BIPQR_SIGNATURE_TAP_SCRIPT};
      memcpy(sig.value.tap_script.xonly_public_key, item->key, 32);
      memcpy(sig.value.tap_script.tap_leaf_hash, item->key + 32, 32);
      if (!copy_signature_bytes(item->value, item->value_len,
                                &sig.value.tap_script.signature) ||
          !append_signature(&signatures, &len, &cap, &sig)) {
        free((void *)sig.value.tap_script.signature.ptr);
        free_signature_list(signatures, len);
        return false;
      }
    }
  }

  *signatures_out = signatures;
  *len_out = len;
  return true;
}

// The ECDH shares and DLEQ proofs Kern contributed: global when it holds
// every eligible input, else one per eligible input it holds
static bool append_sp_shares(const struct wally_psbt *psbt,
                             bipqr_signature **signatures, size_t *len,
                             size_t *cap) {
  sp_share_t *shares = NULL;
  size_t count = 0;
  if (!sp_psbt_shares_alloc(psbt, wallet_is_testnet(), &shares, &count))
    return false;
  bool ok = true;
  for (size_t i = 0; ok && i < count; i++) {
    uint32_t input_index = (uint32_t)shares[i].input_index;
    bipqr_signature share = {.input_index = input_index,
                             .kind = BIPQR_SIGNATURE_SP_ECDH_SHARE};
    share.value.sp_ecdh_share.global = shares[i].global;
    memcpy(share.value.sp_ecdh_share.scan_key, shares[i].scan, SP_PUBKEY_LEN);
    memcpy(share.value.sp_ecdh_share.share, shares[i].share, SP_PUBKEY_LEN);
    bipqr_signature proof = {.input_index = input_index,
                             .kind = BIPQR_SIGNATURE_SP_DLEQ_PROOF};
    proof.value.sp_dleq_proof.global = shares[i].global;
    memcpy(proof.value.sp_dleq_proof.scan_key, shares[i].scan, SP_PUBKEY_LEN);
    memcpy(proof.value.sp_dleq_proof.proof, shares[i].proof,
           BIPQR_DLEQ_PROOF_LEN);
    ok = append_signature(signatures, len, cap, &share) &&
         append_signature(signatures, len, cap, &proof);
  }
  free(shares);
  return ok;
}

static void answer_signatures(const struct wally_psbt *psbt) {
  bipqr_signature *signatures = NULL;
  size_t len = 0;
  if (!collect_signatures(psbt, &signatures, &len)) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL,
                        "Signature extraction failed");
    return;
  }
  // While another signer owes a share there is no signature, only shares
  size_t cap = len;
  if (sp_psbt_has_outputs(psbt) &&
      !append_sp_shares(psbt, &signatures, &len, &cap)) {
    free_signature_list(signatures, len);
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL,
                        "Silent payment share extraction failed");
    return;
  }
  if (len == 0) {
    free_signature_list(signatures, len);
    show_error_response(BIPQR_RESPONSE_ERROR_NOTHING_TO_SIGN,
                        "Nothing to sign");
    return;
  }
  bipqr_response response;
  fill_response_header(&response);
  response.body.signed_body.kind = BIPQR_SIGN_RESPONSE_SIGNATURES;
  response.body.signed_body.value.signatures.ptr = signatures;
  response.body.signed_body.value.signatures.len = len;
  show_response_with_done(&response, return_from_signing_response);
  free_signature_list(signatures, len);
}

static void answer_psbt(const struct wally_psbt *psbt) {
  struct wally_psbt *trimmed =
      ctx.request->body.sign.accept_trimmed ? psbt_trim(psbt) : NULL;
  const struct wally_psbt *export_psbt = trimmed ? trimmed : psbt;
  size_t signed_len = 0;
  debug_logf("bip_flow signed_psbt_cb inputs=%u signed_inputs=%u trimmed=%d",
             (unsigned)export_psbt->num_inputs,
             (unsigned)signed_input_count(export_psbt), trimmed != NULL);
  uint8_t *signed_bytes = NULL;
  bool encoded =
      sp_psbt_serialize_alloc(export_psbt, &signed_bytes, &signed_len);
  if (trimmed)
    wally_psbt_free(trimmed);
  if (!encoded) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "PSBT encode failed");
    return;
  }
  bipqr_response response;
  fill_response_header(&response);
  response.body.signed_body.kind = BIPQR_SIGN_RESPONSE_PSBT;
  response.body.signed_body.value.psbt.ptr = signed_bytes;
  response.body.signed_body.value.psbt.len = signed_len;
  show_response_with_done(&response, return_from_signing_response);
  free(signed_bytes);
}

// An unknown WANT_KIND decodes as absent, so it gets the PSBT
static void signed_psbt_cb(struct wally_psbt *psbt, void *user_data) {
  (void)user_data;
  if (ctx.request->body.sign.want_kind == BIPQR_SIGN_RESPONSE_SIGNATURES)
    answer_signatures(psbt);
  else
    answer_psbt(psbt);
}

static uint8_t sign_failure_error(scan_psbt_failure_t failure) {
  switch (failure) {
  case SCAN_PSBT_DECLINED:
    return BIPQR_RESPONSE_ERROR_USER_DECLINED;
  case SCAN_PSBT_INVALID:
    return BIPQR_RESPONSE_ERROR_INVALID_PSBT;
  case SCAN_PSBT_NOTHING_TO_SIGN:
    return BIPQR_RESPONSE_ERROR_NOTHING_TO_SIGN;
  case SCAN_PSBT_REFUSED:
    return BIPQR_RESPONSE_ERROR_VENDOR;
  case SCAN_PSBT_NETWORK_MISMATCH:
    return BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH;
  case SCAN_PSBT_INTERNAL:
  default:
    return BIPQR_RESPONSE_ERROR_INTERNAL;
  }
}

static void sign_failed_cb(scan_psbt_failure_t failure, const char *message,
                           void *user_data) {
  (void)user_data;
  bipqr_response response;
  fill_error_response(&response, sign_failure_error(failure), message);
  show_response_with_done(&response, return_from_signing_response);
}

// Whose account an sp() descriptor is: ours, on our network or the other one,
// or not ours
static sp_account_t sp_descriptor_account(const char *descriptor) {
  bool testnet = wallet_is_testnet();
  if (sp_descriptor_is_ours(descriptor, testnet))
    return SP_ACCOUNT_OURS;
  if (sp_descriptor_is_ours(descriptor, !testnet))
    return SP_ACCOUNT_OTHER_NETWORK;
  return SP_ACCOUNT_NOT_OURS;
}

// True for an account of our spend key, whose scan key, when not ours, the
// review then pairs with our spend key, else the error is answered
static bool sign_sp_account_ok(const bipqr_sp_keys *sp) {
  sp_account_t account = request_sp_account(sp);
  if (!sp_account_ok(account))
    return false;
  const unsigned char *scan_key = scan_key_not_ours(sp, account);
  if (scan_key && !registry_sp_name_scan_key(scan_key)) {
    show_error_response(BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                        "Too many silent payment accounts");
    return false;
  }
  return true;
}

// True when the inputs spending from `descriptor` can be signed, else the
// error is answered
static bool sign_descriptor_ok(const bipqr_descriptor *descriptor) {
  if (descriptor->proof.ptr) {
    show_foreign_proof_error();
    return false;
  }
  const bipqr_descriptor_body *body = descriptor->body;
  // A registered alias names what it was registered for, whatever the body
  if (registry_sp_alias_exists(descriptor->alias))
    return true;
  if (body && body->tag == BIPQR_DESCRIPTOR_SP_KEYS &&
      !registry_find_by_id(descriptor->alias))
    return sign_sp_account_ok(&body->value.sp_keys);
  char *descriptor_str = request_descriptor_alloc(body);
  // An sp() descriptor carries our scan secret and is never registered
  if (sp_descriptor_is_sp(descriptor_str)) {
    sp_account_t account = sp_descriptor_account(descriptor_str);
    SECURE_FREE_STRING(descriptor_str);
    return sp_account_ok(account);
  }
  free(descriptor_str);
  const registry_entry_t *entry = NULL;
  uint8_t error = resolve_descriptor(descriptor->alias, body, &entry);
  if (error)
    show_descriptor_error(error);
  return !error;
}

// A PSBT needing a capability Kern does not advertise: MuSig2 keys
static bool refuse_unsupported_psbt(const bipqr_sign *req) {
  struct wally_psbt *psbt = NULL;
  // Loose, as a silent payment output has no script until a signer derives it
  bool unsupported = kern_psbt_from_bytes(req->psbt.ptr, req->psbt.len,
                                          WALLY_PSBT_PARSE_FLAG_LOOSE |
                                              WALLY_PSBT_PARSE_FLAG_COMPLETE,
                                          &psbt) == WALLY_OK &&
                     bip_flow_psbt_is_unsupported(psbt);
  wally_psbt_free(psbt);
  if (unsupported)
    show_error_response(BIPQR_RESPONSE_ERROR_UNSUPPORTED_OPERATION,
                        "MuSig2 is not supported");
  return unsupported;
}

static void handle_sign(void) {
  const bipqr_sign *req = &ctx.request->body.sign;
  for (size_t i = 0; i < req->descriptors.len; i++) {
    if (!sign_descriptor_ok(&req->descriptors.ptr[i]))
      return;
    // A script several entries generate is reviewed under the named alias
    registry_prefer(req->descriptors.ptr[i].alias);
  }
  if (refuse_unsupported_psbt(req))
    return;
  scan_review_psbt(ctx.parent, req->psbt.ptr, req->psbt.len, ctx.return_cb,
                   return_from_signing_response, signed_psbt_cb, sign_failed_cb,
                   NULL);
}

static void unregister_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    show_error_response(BIPQR_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }
  const char *alias = ctx.request->body.unregister_descriptor.descriptor_alias;
  if (!registry_unregister(alias)) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL,
                        "Removing the registration failed");
    return;
  }
  debug_logf("bip_flow unregistered alias=%s", alias);
  bipqr_response response;
  fill_response_header(&response);
  response.body.unregistered.descriptor_alias = alias;
  show_response(&response);
}

// Our silent payment account under `alias`: our fingerprint, our spend key
// and whether its scan key is not ours
static void confirm_sp_unregister(const char *alias) {
  char fingerprint[9];
  uint32_t spend_path[SP_PATH_DEPTH];
  char spend[64];
  sp_account_key_path(wallet_is_testnet(), SP_SPEND_BRANCH, spend_path);
  if (!key_get_fingerprint_hex(fingerprint) ||
      !bip32_path_format(spend_path, SP_PATH_DEPTH, spend, sizeof(spend))) {
    show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL, "Key failed");
    return;
  }
  char msg[192];
  snprintf(msg, sizeof(msg),
           "Unregister silent payment keys?\n\nAlias: %s\nFingerprint: "
           "%s\nSpend key: %s%s",
           alias, fingerprint, spend,
           registry_sp_alias_scan_key(alias)
               ? "\nScan key: external, not this device's"
               : "");
  dialog_show_danger_confirm(msg, unregister_confirm_cb, NULL,
                             DIALOG_STYLE_OVERLAY);
}

// The user confirms the alias and what it names before it is removed
static void handle_unregister(void) {
  const char *alias = ctx.request->body.unregister_descriptor.descriptor_alias;
  const registry_entry_t *entry = registry_find_by_id(alias);
  if (entry) {
    if (!descriptor_loader_confirm_unregister(entry, unregister_confirm_cb))
      show_error_response(BIPQR_RESPONSE_ERROR_INTERNAL,
                          "Descriptor review failed");
  } else if (registry_sp_alias_exists(alias)) {
    confirm_sp_unregister(alias);
  } else {
    show_descriptor_error(BIPQR_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS);
  }
}

static void dispatch_request(void) {
  debug_logf("bip_flow dispatch message_type=%d", ctx.request->message_type);
  uint8_t unsupported = bip_flow_unsupported_error(ctx.request);
  if (unsupported) {
    show_error_response(
        unsupported, unsupported == BIPQR_RESPONSE_ERROR_UNSUPPORTED_OPERATION
                         ? "Unsupported request"
                         : "Descriptor form not taken here");
    return;
  }
  switch (ctx.request->message_type) {
  case BIPQR_MESSAGE_GET_INFO:
    handle_get_info();
    break;
  case BIPQR_MESSAGE_GET_KEYS:
    handle_get_keys();
    break;
  case BIPQR_MESSAGE_REGISTER_DESCRIPTOR:
    handle_register();
    break;
  case BIPQR_MESSAGE_ADDRESS_VERIFICATION:
    handle_verify();
    break;
  case BIPQR_MESSAGE_SIGNING:
    handle_sign();
    break;
  case BIPQR_MESSAGE_UNREGISTER_DESCRIPTOR:
    handle_unregister();
    break;
  default:
    show_error_response(BIPQR_RESPONSE_ERROR_UNSUPPORTED_OPERATION,
                        "Unsupported request");
    break;
  }
}

void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void)) {
  debug_log_hex_preview("bip_flow start", data, len, 16);
  ctx.parent = parent;
  ctx.return_cb = return_cb;
  cleanup_request();
  clear_pending_verify();
  if (!bip_flow_read_request_header(data, len, &ctx.header)) {
    debug_log_event("bip_flow unreadable_request");
    show_error_response(BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Unreadable request");
    return;
  }
  const char *err = NULL;
  int32_t rc = bipqr_request_decode(data, len, &ctx.request, &err);
  if (rc != BIPQR_OK || !ctx.request) {
    debug_logf("bip_flow decode_error rc=%d err=%s", (int)rc, err ? err : "");
    cleanup_request();
    show_error_response(bip_flow_decode_error(&ctx.header, rc),
                        err ? err : "Malformed request");
    return;
  }
  debug_log_event("bip_flow decode_ok");
  dispatch_request();
}
