#include "bip_flow.h"

#include "../../core/bip32_path.h"
#include "../../core/key.h"
#include "../../core/psbt.h"
#include "../../core/registry.h"
#include "../../core/settings.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/parser.h"
#include "../../ui/dialog.h"
#include "../../ui/qr_widget.h"
#include "../../ui/theme.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../scan/scan.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "../shared/qr_viewer.h"
#include "bbqr.h"
#include "bip388.h"
#include <bip377.h>
#include <esp_app_desc.h>
#include <inttypes.h>
#include <kern_wally.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>

#define KERN_CAPABILITIES                                                      \
  (BIP377_CAPABILITY_BIP380_DESCRIPTORS |                                      \
   BIP377_CAPABILITY_BIP388_WALLET_POLICIES |                                  \
   BIP377_CAPABILITY_MINISCRIPT_SEGWIT_V0 |                                    \
   BIP377_CAPABILITY_MINISCRIPT_TAPROOT)

// What a decoded request may take: its strings and byte fields are copies
// of the message, so only a request built to exhaust memory goes past it
#define BIP_FLOW_MAX_REQUEST_MEM (2 * QR_PARSER_MAX_STORED_BYTES)
// The Get Keys answer holds one key per path and has to fit a message
#define BIP_FLOW_MAX_KEYS                                                      \
  ((QR_PARSER_MAX_STORED_BYTES - 256) / BIP377_EXTENDED_KEY_LEN)

typedef struct {
  lv_obj_t *parent;
  void (*return_cb)(void);
  bip377_header header;
  const bip377_request *request;
  // The block `request` is decoded into
  void *request_mem;
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
  return bip377_is_message(data, len);
}

static void cleanup_request(void) {
  registry_clear_preferred();
  free(ctx.request_mem);
  ctx.request_mem = NULL;
  ctx.request = NULL;
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
  signing_response_return_pending = false;
  qr_viewer_page_destroy();
  cleanup_request();
  if (ctx.return_cb)
    ctx.return_cb();
}

static void return_from_signing_response(void) {
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

static void show_response_sized(bip377_response *response,
                                void (*done_cb)(void), int max_chars) {
  size_t encoded_len = 0;
  uint8_t *encoded = NULL;
  bool ok =
      bip377_response_encode(response, NULL, 0, &encoded_len) == BIP377_OK &&
      (encoded = malloc(encoded_len)) != NULL &&
      bip377_response_encode(response, encoded, encoded_len, &encoded_len) ==
          BIP377_OK;
  if (!ok) {
    free(encoded);
    cleanup_request();
    dialog_show_error_timeout("Failed to encode response", ctx.return_cb, 0);
    return;
  }

  BBQrParts *parts =
      bbqr_encode_hex(encoded, encoded_len, BBQR_TYPE_BINARY, max_chars);
  free(encoded);
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

static void show_response_with_done(bip377_response *response,
                                    void (*done_cb)(void)) {
  show_response_sized(response, done_cb, settings_get_qr_density());
}

static void show_response(bip377_response *response) {
  show_response_with_done(response, return_from_response);
}

static void fill_response_header(bip377_response *response) {
  memset(response, 0, sizeof(*response));
  memcpy(response->id, ctx.header.id, BIP377_REQUEST_ID_LEN);
  response->message_type = ctx.header.message_type;
}

static void fill_error_response(bip377_response *response, uint8_t error,
                                const char *message) {
  fill_response_header(response);
  response->is_error = true;
  response->body.error.error = error;
  response->body.error.message = message ? message : "Error";
}

static void show_error_response(uint8_t error, const char *message) {
  bip377_response response;
  fill_error_response(&response, error, message);
  show_response(&response);
}

// Kern keeps its registrations on the device and issues no proof of
// registration, so a proof it receives is not one of its own
static void show_foreign_proof_error(void) {
  show_error_response(BIP377_RESPONSE_ERROR_INVALID_PROOF,
                      "Kern issues no proof of registration");
}

static bool wallet_is_testnet(void) {
  return wallet_get_network() == WALLET_NETWORK_TESTNET;
}

static void fill_device_fields(const char **vendor, const char **model,
                               bip377_firmware_version *version,
                               uint32_t *capabilities) {
  *vendor = "Kern";
  *model = CONFIG_KERN_BOARD_NAME;
  const esp_app_desc_t *desc = esp_app_get_description();
  unsigned major = 0, minor = 0, patch = 0;
  if (desc)
    sscanf(desc->version, "%u.%u.%u", &major, &minor, &patch);
  version->major = (uint16_t)major;
  version->minor = (uint16_t)minor;
  version->patch = (uint16_t)patch;
  version->channel = BIP377_RELEASE_STABLE;
  version->number = 0;
  *capabilities = KERN_CAPABILITIES;
}

// Ready with a loaded seed, locked while an encrypted one waits on flash
static bool device_state(uint8_t *state_out) {
  if (key_is_loaded()) {
    *state_out = BIP377_STATE_READY;
    return true;
  }
  char **files = NULL;
  int count = 0;
  if (storage_list_mnemonics(STORAGE_FLASH, &files, &count) != ESP_OK)
    return false;
  storage_free_file_list(files, count);
  *state_out = count > 0 ? BIP377_STATE_LOCKED : BIP377_STATE_UNINITIALIZED;
  return true;
}

static void handle_get_info(void) {
  bip377_response response;
  fill_response_header(&response);
  bip377_info *info = &response.body.info;
  fill_device_fields(&info->vendor, &info->model, &info->version,
                     &info->capabilities);
  if (!device_state(&info->state)) {
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Storage failed");
    return;
  }
  // Coin 1' covers testnet and signet; no regtest, Kern only encodes tb
  // addresses
  info->networks =
      BIP377_NETWORK_MAINNET | BIP377_NETWORK_TESTNET | BIP377_NETWORK_SIGNET;
  info->max_message = QR_PARSER_MAX_STORED_BYTES;
  info->max_alias = REGISTRY_ID_MAX_LEN - 1;
  if (info->state == BIP377_STATE_READY) {
    if (!key_get_fingerprint(info->fingerprint)) {
      show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Fingerprint failed");
      return;
    }
    info->has_fingerprint = 1;
  }
  show_response(&response);
}

static bool xpub_base58_to_wire(const char *xpub, bip377_extended_key *out) {
  struct ext_key *key = NULL;
  bool ok = false;
  if (bip32_key_from_base58_alloc(xpub, &key) == WALLY_OK && key) {
    uint8_t serialized[BIP377_EXTENDED_KEY_LEN];
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

static bool public_key_to_wire(const bip377_path *path,
                               bip377_extended_key *out) {
  char *xpub = NULL;
  bool ok = key_get_xpub_components(path->ptr, path->len, &xpub) && xpub &&
            xpub_base58_to_wire(xpub, out);
  if (xpub)
    wally_free_string(xpub);
  return ok;
}

static void free_keys(bip377_extended_key *keys, size_t n) {
  secure_memzero(keys, n * sizeof(*keys));
  free(keys);
}

static void get_keys_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    show_error_response(BIP377_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }

  const bip377_get_keys *req = &ctx.request->body.get_keys;
  size_t n = req->keys.len;
  bip377_extended_key *keys = calloc(n, sizeof(*keys));
  // An empty KEYS vector is valid and gets an empty one back
  if (!keys && n) {
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }

  for (size_t i = 0; i < n; i++) {
    if (!public_key_to_wire(&req->keys.ptr[i], &keys[i])) {
      free_keys(keys, n);
      show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Key failed");
      return;
    }
  }

  bip377_response response;
  fill_response_header(&response);
  response.body.keys.keys.ptr = keys;
  response.body.keys.keys.len = n;
  if (!key_get_fingerprint(response.body.keys.fingerprint)) {
    free_keys(keys, n);
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Fingerprint failed");
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

static bool path_requested_network(const bip377_path *path,
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

static bool get_keys_network_matches_wallet(const bip377_path_list *keys,
                                            char *message,
                                            size_t message_size) {
  if (!keys || !keys->ptr)
    return true;

  bool have_network = false;
  wallet_network_t requested = WALLET_NETWORK_MAINNET;
  for (size_t i = 0; i < keys->len; i++) {
    wallet_network_t path_network;
    if (!path_requested_network(&keys->ptr[i], &path_network))
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

static bool format_key_path_range(const bip377_path_list *keys, char *buf,
                                  size_t buf_size) {
  if (!keys || keys->len < 2 || !keys->ptr || !buf || buf_size == 0)
    return false;

  uint8_t depth = keys->ptr[0].len;
  if (depth == 0)
    return false;

  int varying_index = -1;
  for (uint8_t i = 0; i < depth; i++) {
    uint32_t first = keys->ptr[0].ptr[i];
    bool varies = false;
    for (size_t j = 1; j < keys->len; j++) {
      if (!keys->ptr[j].ptr || keys->ptr[j].len != depth)
        return false;
      if (keys->ptr[j].ptr[i] != first)
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

  uint32_t first = keys->ptr[0].ptr[varying_index];
  bool hardened = bip32_path_is_hardened(first);
  uint32_t first_child = bip32_path_unharden(first);
  for (size_t i = 1; i < keys->len; i++) {
    uint32_t component = keys->ptr[i].ptr[varying_index];
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
      off = append_path_component(buf, buf_size, off, keys->ptr[0].ptr[i]);
    }
  }

  return off < buf_size;
}

static size_t append_key_request_paths(char *msg, size_t msg_size, size_t off,
                                       const bip377_path_list *keys) {
  char range_path[128];
  if (format_key_path_range(keys, range_path, sizeof(range_path)))
    return appendf(msg, msg_size, off, "\n\n%s", range_path);

  size_t shown = keys->len < 6 ? keys->len : 6;
  for (size_t i = 0; i < shown && off < msg_size; i++) {
    char path[96];
    if (!bip32_path_format(keys->ptr[i].ptr, keys->ptr[i].len, path,
                           sizeof(path))) {
      snprintf(path, sizeof(path), "<invalid path>");
    }
    off = appendf(msg, msg_size, off, "\n%s", path);
  }
  if (keys->len > shown)
    off = appendf(msg, msg_size, off, "\n...and %zu more", keys->len - shown);
  return off;
}

static void handle_get_keys(void) {
  const bip377_get_keys *req = &ctx.request->body.get_keys;
  char mismatch[80];
  if (!get_keys_network_matches_wallet(&req->keys, mismatch,
                                       sizeof(mismatch))) {
    show_error_response(BIP377_RESPONSE_ERROR_NETWORK_MISMATCH, mismatch);
    return;
  }
  if (req->keys.len > BIP_FLOW_MAX_KEYS) {
    show_error_response(BIP377_RESPONSE_ERROR_VENDOR,
                        "Too many public keys requested");
    return;
  }

  char msg[512];
  size_t off =
      snprintf(msg, sizeof(msg), "Export %zu public key(s)?\n", req->keys.len);
  append_key_request_paths(msg, sizeof(msg), off, &req->keys);
  dialog_show_confirm(msg, get_keys_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static char *request_descriptor_alloc(const bip377_descriptor_body *body) {
  if (!body)
    return NULL;
  if (body->tag == BIP377_DESCRIPTOR_BIP380)
    return body->value.bip380 ? strdup(body->value.bip380) : NULL;
  if (body->tag == BIP377_DESCRIPTOR_BIP388)
    return bip388_descriptor_alloc(body->value.bip388.policy,
                                   body->value.bip388.keys.ptr,
                                   body->value.bip388.keys.len);
  return NULL;
}

// The error a body request_descriptor_alloc() gives no descriptor for answers
// with: registration failed when it holds none, such as a wallet policy whose
// @N names no key, internal error when the descriptor could not be allocated
static uint8_t request_descriptor_error(const bip377_descriptor_body *body) {
  bool has_descriptor =
      body && ((body->tag == BIP377_DESCRIPTOR_BIP380 && body->value.bip380) ||
               (body->tag == BIP377_DESCRIPTOR_BIP388 &&
                bip388_policy_is_valid(body->value.bip388.policy,
                                       body->value.bip388.keys.ptr,
                                       body->value.bip388.keys.len)));
  return has_descriptor ? BIP377_RESPONSE_ERROR_INTERNAL
                        : BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
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
  case VALIDATION_STORE_FAILED:
    return "Could not store the descriptor";
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
  bip377_response response;
  fill_response_header(&response);
  response.body.registration.descriptor_alias = alias;
  response.body.registration.registered = entry != NULL;
  response.body.registration.stored = entry && entry->persisted;
  show_response(&response);
}

// A refused registration: the answer for the coordinator, under the reason
// for the user
static void show_register_refusal(uint8_t error, const char *message) {
  show_error_response(error, message);
  dialog_show_error_timeout(message, NULL, 3000);
}

static void show_alias_taken_error(void) {
  show_register_refusal(BIP377_RESPONSE_ERROR_ALREADY_REGISTERED,
                        "Alias already registered");
}

static void registered_acknowledged_cb(void *user_data) {
  (void)user_data;
  answer_registration();
}

static void register_validation_cb(descriptor_validation_result_t result,
                                   void *user_data) {
  (void)user_data;
  if (result != VALIDATION_SUCCESS) {
    show_error_response(bip_flow_register_error(result),
                        register_error_message(result));
    descriptor_loader_show_error(result);
    return;
  }
  char msg[REGISTRY_ID_MAX_LEN + 64];
  snprintf(msg, sizeof(msg),
           "%s registered.\nIt loads automatically with this key.",
           ctx.request->body.register_descriptor.descriptor_alias);
  dialog_show_info("Registered", msg, registered_acknowledged_cb, NULL,
                   DIALOG_STYLE_FULLSCREEN);
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
    show_register_refusal(BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                          "Alias too long");
    return;
  }
  // A registration of this key that the session did not load holds the name
  if (!entry && registry_name_registered(alias)) {
    show_register_refusal(BIP377_RESPONSE_ERROR_ALREADY_REGISTERED,
                          "A stored descriptor already uses this alias");
    return;
  }
  if (!entry && registry_count() >= REGISTRY_MAX_ENTRIES) {
    show_register_refusal(BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                          "Too many descriptors loaded");
    return;
  }
  descriptor_loader_process_string_with_id(descriptor, alias, STORAGE_FLASH,
                                           register_validation_cb, NULL);
}

// Without a descriptor the request only asks whether the alias is registered
static void handle_register(void) {
  const bip377_register_descriptor *req =
      &ctx.request->body.register_descriptor;
  const registry_entry_t *entry = registry_find_by_id(req->descriptor_alias);
  if (!req->descriptor) {
    answer_registration();
    return;
  }
  char *descriptor = request_descriptor_alloc(req->descriptor);
  if (!descriptor) {
    uint8_t error = request_descriptor_error(req->descriptor);
    show_register_refusal(error, error == BIP377_RESPONSE_ERROR_INTERNAL
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
                                  const bip377_descriptor_body *body,
                                  const registry_entry_t **entry_out) {
  *entry_out = registry_find_by_id(alias);
  if (*entry_out)
    return 0;
  if (!body)
    return BIP377_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS;
  char *descriptor = request_descriptor_alloc(body);
  if (!descriptor)
    return request_descriptor_error(body);
  wallet_network_t network;
  if (descriptor_infer_network(descriptor, &network) &&
      network != wallet_get_network()) {
    free(descriptor);
    return BIP377_RESPONSE_ERROR_NETWORK_MISMATCH;
  }
  bool added =
      registry_add_from_string(alias, descriptor, STORAGE_FLASH, false);
  free(descriptor);
  *entry_out = added ? registry_find_by_id(alias) : NULL;
  return *entry_out ? 0 : BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
}

static void show_descriptor_error(uint8_t error) {
  switch (error) {
  case BIP377_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS:
    show_error_response(error, "Unknown descriptor alias");
    break;
  case BIP377_RESPONSE_ERROR_NETWORK_MISMATCH:
    show_error_response(error, "Descriptor network mismatch");
    break;
  case BIP377_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM:
    show_error_response(error, "Descriptor form not taken here");
    break;
  case BIP377_RESPONSE_ERROR_INTERNAL:
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
                                    const bip377_path *path, char **out) {
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
               ? BIP377_RESPONSE_ERROR_NETWORK_MISMATCH
               : BIP377_RESPONSE_ERROR_ADDRESS_MISMATCH;
  bool same = address_to_spk(derived, testnet, derived_script,
                             sizeof(derived_script), &derived_len) &&
              given_len == derived_len &&
              memcmp(given_script, derived_script, given_len) == 0;
  return same ? 0 : BIP377_RESPONSE_ERROR_ADDRESS_MISMATCH;
}

static void verify_address_approve_enable_cb(lv_timer_t *timer) {
  (void)timer;
  if (verify_address_approve_btn)
    lv_obj_clear_state(verify_address_approve_btn, LV_STATE_DISABLED);
}

static void verify_address_done_cb(lv_event_t *e) {
  (void)e;
  destroy_verify_address_detail();
  bip377_response response;
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
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }
  snprintf(pending_verified_uri, uri_len, "%s%s", uri_prefix, address);
  show_verify_address_detail();
}

// "<alias> receive #7", "<alias> change #3", "<alias> path 2/5": the address
// `path` names under the descriptor of `entry`, as address_from_entry_path
// reads it
static void descriptor_address_caption(const char *alias,
                                       const registry_entry_t *entry,
                                       const bip377_path *path, char *out,
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

static void verify_descriptor_address(const bip377_verify_address *req) {
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
    show_error_response(BIP377_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Path does not fit the descriptor");
    return;
  }
  char *address = strdup(derived);
  wally_free_string(derived);
  if (!address) {
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }
  uint8_t mismatch = req->address ? address_error(req->address, address) : 0;
  if (mismatch) {
    free(address);
    show_error_response(mismatch,
                        mismatch == BIP377_RESPONSE_ERROR_NETWORK_MISMATCH
                            ? "Address is for another network"
                            : "Address mismatch");
    return;
  }
  char caption[sizeof(pending_verify_caption)];
  descriptor_address_caption(req->descriptor_alias, entry,
                             &req->derivation_path, caption, sizeof(caption));
  show_verified_address(address, "bitcoin:", caption);
}

static void handle_verify(void) {
  const bip377_verify_address *req = &ctx.request->body.verify_address;
  if (req->proof.ptr) {
    show_foreign_proof_error();
    return;
  }
  verify_descriptor_address(req);
}

static void free_signature_list(bip377_signature *signatures, size_t len) {
  if (!signatures)
    return;
  for (size_t i = 0; i < len; i++) {
    switch (signatures[i].kind) {
    case BIP377_SIGNATURE_ECDSA:
      free((void *)signatures[i].value.ecdsa.signature.ptr);
      break;
    case BIP377_SIGNATURE_TAP_KEY:
      free((void *)signatures[i].value.tap_key.signature.ptr);
      break;
    case BIP377_SIGNATURE_TAP_SCRIPT:
      free((void *)signatures[i].value.tap_script.signature.ptr);
      break;
    default:
      break;
    }
  }
  free(signatures);
}

static bool copy_signature_bytes(const uint8_t *src, size_t len,
                                 bip377_bytes *out) {
  uint8_t *copy = malloc(len);
  if (!copy)
    return false;
  memcpy(copy, src, len);
  out->ptr = copy;
  out->len = len;
  return true;
}

static bool append_signature(bip377_signature **signatures, size_t *len,
                             size_t *cap, const bip377_signature *sig) {
  if (*len == *cap) {
    size_t new_cap = *cap ? *cap * 2 : 4;
    bip377_signature *new_signatures =
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
                               bip377_signature **signatures_out,
                               size_t *len_out) {
  bip377_signature *signatures = NULL;
  size_t len = 0, cap = 0;

  for (size_t input_index = 0; input_index < psbt->num_inputs; input_index++) {
    const struct wally_psbt_input *input = &psbt->inputs[input_index];
    for (size_t j = 0; j < input->signatures.num_items; j++) {
      const struct wally_map_item *item = &input->signatures.items[j];
      if (item->key_len != BIP377_PUBLIC_KEY_LEN || !item->key || !item->value)
        continue;
      bip377_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BIP377_SIGNATURE_ECDSA};
      memcpy(sig.value.ecdsa.public_key, item->key, BIP377_PUBLIC_KEY_LEN);
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
      bip377_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BIP377_SIGNATURE_TAP_KEY};
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
      bip377_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BIP377_SIGNATURE_TAP_SCRIPT};
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

static void answer_signatures(const struct wally_psbt *psbt) {
  bip377_signature *signatures = NULL;
  size_t len = 0;
  if (!collect_signatures(psbt, &signatures, &len)) {
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL,
                        "Signature extraction failed");
    return;
  }
  if (len == 0) {
    free_signature_list(signatures, len);
    show_error_response(BIP377_RESPONSE_ERROR_NOTHING_TO_SIGN,
                        "Nothing to sign");
    return;
  }
  bip377_response response;
  fill_response_header(&response);
  response.body.signed_body.kind = BIP377_SIGN_RESPONSE_SIGNATURES;
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
  uint8_t *signed_bytes = NULL;
  bool encoded =
      wally_psbt_get_length(export_psbt, 0, &signed_len) == WALLY_OK &&
      (signed_bytes = malloc(signed_len)) != NULL &&
      wally_psbt_to_bytes(export_psbt, 0, signed_bytes, signed_len,
                          &signed_len) == WALLY_OK;
  if (trimmed)
    wally_psbt_free(trimmed);
  if (!encoded) {
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "PSBT encode failed");
    return;
  }
  bip377_response response;
  fill_response_header(&response);
  response.body.signed_body.kind = BIP377_SIGN_RESPONSE_PSBT;
  response.body.signed_body.value.psbt.ptr = signed_bytes;
  response.body.signed_body.value.psbt.len = signed_len;
  show_response_with_done(&response, return_from_signing_response);
  free(signed_bytes);
}

// An unknown WANT_KIND decodes as absent, so it gets the PSBT
static void signed_psbt_cb(struct wally_psbt *psbt, void *user_data) {
  (void)user_data;
  if (ctx.request->body.sign.want_kind == BIP377_SIGN_RESPONSE_SIGNATURES)
    answer_signatures(psbt);
  else
    answer_psbt(psbt);
}

static uint8_t sign_failure_error(scan_psbt_failure_t failure) {
  switch (failure) {
  case SCAN_PSBT_DECLINED:
    return BIP377_RESPONSE_ERROR_USER_DECLINED;
  case SCAN_PSBT_INVALID:
    return BIP377_RESPONSE_ERROR_INVALID_PSBT;
  case SCAN_PSBT_NOTHING_TO_SIGN:
    return BIP377_RESPONSE_ERROR_NOTHING_TO_SIGN;
  case SCAN_PSBT_REFUSED:
    return BIP377_RESPONSE_ERROR_VENDOR;
  case SCAN_PSBT_NETWORK_MISMATCH:
    return BIP377_RESPONSE_ERROR_NETWORK_MISMATCH;
  case SCAN_PSBT_INTERNAL:
  default:
    return BIP377_RESPONSE_ERROR_INTERNAL;
  }
}

static void sign_failed_cb(scan_psbt_failure_t failure, const char *message,
                           void *user_data) {
  (void)user_data;
  bip377_response response;
  fill_error_response(&response, sign_failure_error(failure), message);
  show_response_with_done(&response, return_from_signing_response);
}

// True when the inputs spending from `descriptor` can be signed, else the
// error is answered
static bool sign_descriptor_ok(const bip377_descriptor *descriptor) {
  if (descriptor->proof.ptr) {
    show_foreign_proof_error();
    return false;
  }
  const bip377_descriptor_body *body = descriptor->body;
  const registry_entry_t *entry = NULL;
  uint8_t error = resolve_descriptor(descriptor->alias, body, &entry);
  if (error)
    show_descriptor_error(error);
  return !error;
}

// A PSBT needing a capability Kern does not advertise: a silent payment send
// or MuSig2 keys
static bool refuse_unsupported_psbt(const bip377_sign *req) {
  struct wally_psbt *psbt = NULL;
  // Loose, as a silent payment output has no script until a signer derives it
  bool unsupported = kern_psbt_from_bytes(req->psbt.ptr, req->psbt.len,
                                          WALLY_PSBT_PARSE_FLAG_LOOSE |
                                              WALLY_PSBT_PARSE_FLAG_COMPLETE,
                                          &psbt) == WALLY_OK &&
                     bip_flow_psbt_is_unsupported(psbt);
  wally_psbt_free(psbt);
  if (unsupported)
    show_error_response(BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION,
                        "Silent payment sends and MuSig2 are not supported");
  return unsupported;
}

static void handle_sign(void) {
  const bip377_sign *req = &ctx.request->body.sign;
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

static void dispatch_request(void) {
  uint8_t unsupported = bip_flow_unsupported_error(ctx.request);
  if (unsupported) {
    const char *message =
        unsupported == BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION
            ? "MuSig2 is not supported"
            : "Silent payment descriptors are not supported";
    if (ctx.request->message_type == BIP377_MESSAGE_REGISTER_DESCRIPTOR)
      show_register_refusal(unsupported, message);
    else
      show_error_response(unsupported, message);
    return;
  }
  switch (ctx.request->message_type) {
  case BIP377_MESSAGE_GET_INFO:
    handle_get_info();
    break;
  case BIP377_MESSAGE_GET_KEYS:
    handle_get_keys();
    break;
  case BIP377_MESSAGE_REGISTER_DESCRIPTOR:
    handle_register();
    break;
  case BIP377_MESSAGE_ADDRESS_VERIFICATION:
    handle_verify();
    break;
  case BIP377_MESSAGE_SIGNING:
    handle_sign();
    break;
  default:
    show_error_response(BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION,
                        "Unsupported request");
    break;
  }
}

void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void)) {
  ctx.parent = parent;
  ctx.return_cb = return_cb;
  cleanup_request();
  clear_pending_verify();
  if (!bip377_request_header(data, len, &ctx.header)) {
    show_error_response(BIP377_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Unreadable request");
    return;
  }
  size_t mem_len = 0;
  int rc = bip377_request_decode(data, len, NULL, 0, &mem_len, NULL);
  if (rc != BIP377_OK) {
    show_error_response(bip_flow_decode_error(&ctx.header, rc),
                        bip377_strerror(rc));
    return;
  }
  if (mem_len > BIP_FLOW_MAX_REQUEST_MEM ||
      !(ctx.request_mem = malloc(mem_len)) ||
      bip377_request_decode(data, len, ctx.request_mem, mem_len, NULL,
                            &ctx.request) != BIP377_OK) {
    cleanup_request();
    show_error_response(BIP377_RESPONSE_ERROR_INTERNAL, "Request too large");
    return;
  }
  dispatch_request();
}
