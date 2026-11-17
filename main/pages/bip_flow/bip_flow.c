#include "bip_flow.h"

#include "../../components/bbqr/src/bbqr.h"
#include "../../core/bip32_path.h"
#include "../../core/debug_log.h"
#include "../../core/key.h"
#include "../../core/registry.h"
#include "../../core/settings.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/parser.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../utils/secure_mem.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "bip388.h"
#include <bipqr.h>
#include <esp_app_desc.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#define KERN_CAPABILITIES                                                      \
  (BIPQR_CAPABILITY_BIP380_DESCRIPTORS |                                       \
   BIPQR_CAPABILITY_BIP388_WALLET_POLICIES |                                   \
   BIPQR_CAPABILITY_MINISCRIPT_SEGWIT_V0 |                                     \
   BIPQR_CAPABILITY_MINISCRIPT_TAPROOT)

typedef struct {
  lv_obj_t *parent;
  void (*return_cb)(void);
  bip_flow_header_t header;
  const bipqr_request *request;
} bip_flow_ctx_t;

static bip_flow_ctx_t ctx;
bool bip_flow_can_handle(const uint8_t *data, size_t len) {
  return data && len >= 6 && memcmp(data, "BIP", 3) == 0;
}

static void cleanup_request(void) {
  if (ctx.request) {
    bipqr_request_free(ctx.request);
    ctx.request = NULL;
  }
}

static void return_from_response(void) {
  qr_viewer_page_destroy();
  cleanup_request();
  if (ctx.return_cb)
    ctx.return_cb();
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
    if (!public_key_to_wire(&key->derivation_path, &keys[i])) {
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

static void handle_get_keys(void) {
  const bipqr_get_keys *req = &ctx.request->body.get_keys;
  char mismatch[80];
  if (!get_keys_network_matches_wallet(&req->keys, mismatch,
                                       sizeof(mismatch))) {
    debug_logf("bip_flow keys_network_mismatch msg=%s", mismatch);
    show_error_response(BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH, mismatch);
    return;
  }
  // Kern exports no private key
  if (get_keys_has_private(&req->keys)) {
    show_error_response(BIPQR_RESPONSE_ERROR_PRIVATE_KEY_EXPORT_REFUSED,
                        "Private key export refused");
    return;
  }

  char msg[512];
  size_t off =
      snprintf(msg, sizeof(msg), "Export %zu key(s)?\n", req->keys.len);
  append_key_request_paths(msg, sizeof(msg), off, &req->keys);
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
// for the session
static void answer_registration(void) {
  const char *alias = ctx.request->body.register_descriptor.descriptor_alias;
  const registry_entry_t *entry = registry_find_by_id(alias);
  bipqr_response response;
  fill_response_header(&response);
  response.body.registration.descriptor_alias = alias;
  response.body.registration.registered = entry != NULL;
  response.body.registration.stored = entry && entry->persisted;
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
  if (entry &&
      (entry->persisted || !registry_entry_is_descriptor(entry, descriptor))) {
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

// Without a descriptor the request only asks whether the alias is registered
static void handle_register(void) {
  debug_log_event("bip_flow handle_register");
  const bipqr_register_descriptor *req = &ctx.request->body.register_descriptor;
  const registry_entry_t *entry = registry_find_by_id(req->descriptor_alias);
  if (!req->descriptor) {
    answer_registration();
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
