#include "bip_flow.h"

#include "../../components/bbqr/src/bbqr.h"
#include "../../core/bip32_path.h"
#include "../../core/debug_log.h"
#include "../../core/key.h"
#include "../../core/psbt.h"
#include "../../core/registry.h"
#include "../../core/settings.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include "../../ui/theme_widgets.h"
#include "../scan/scan.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include <bwk_qr_protocol.h>
#include <esp_app_desc.h>
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

typedef struct {
  lv_obj_t *parent;
  void (*return_cb)(void);
  const bwk_qr_request *request;
} bip_flow_ctx_t;

static bip_flow_ctx_t ctx;
static char *pending_verified_address = NULL;
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

bool bip_flow_can_handle(const uint8_t *data, size_t len) {
  return data && len >= 6 && memcmp(data, "BIP", 3) == 0;
}

static void cleanup_request(void) {
  if (ctx.request) {
    bwk_qr_request_free(ctx.request);
    ctx.request = NULL;
  }
}

static void return_from_response(void) {
  qr_viewer_page_destroy();
  destroy_verify_address_detail();
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
  lv_timer_t *timer = lv_timer_create(signing_response_return_timer_cb, 1, NULL);
  if (timer) {
    lv_timer_set_repeat_count(timer, 1);
  } else {
    signing_response_return_pending = false;
    signing_response_return_timer_cb(NULL);
  }
}

static void show_response_with_done(bwk_qr_response *response,
                                    void (*done_cb)(void)) {
  debug_logf("bip_flow show_response is_error=%d", response->is_error);
  bwk_qr_buf encoded = {0};
  const char *err = NULL;
  int32_t rc = bwk_qr_response_encode(response, &encoded, &err);
  if (rc != BWK_QR_OK || !encoded.ptr || encoded.len == 0) {
    cleanup_request();
    dialog_show_error_timeout(err ? err : "Failed to encode response",
                              ctx.return_cb, 0);
    return;
  }

  BBQrParts *parts = bbqr_encode_hex(encoded.ptr, encoded.len, BBQR_TYPE_BINARY,
                                     settings_get_qr_density());
  bwk_qr_buf_free(encoded);
  if (!parts) {
    cleanup_request();
    dialog_show_error_timeout("Failed to encode response QR", ctx.return_cb, 0);
    return;
  }

  if (!qr_viewer_page_create_with_bbqr_parts(ctx.parent, parts, "Response QR",
                                             done_cb)) {
    bbqr_parts_free(parts);
    cleanup_request();
    dialog_show_error_timeout("Failed to display response", ctx.return_cb, 0);
    return;
  }
  qr_viewer_page_show();
}

static void show_response(bwk_qr_response *response) {
  show_response_with_done(response, return_from_response);
}

static void fill_response_header(bwk_qr_response *response) {
  memset(response, 0, sizeof(*response));
  memcpy(response->id, ctx.request->id, BWK_QR_REQUEST_ID_LEN);
  response->message_type = ctx.request->message_type;
}

static void show_error_response(uint8_t error, const char *message) {
  debug_logf("bip_flow show_error_response code=%u msg=%s", (unsigned)error,
             message ? message : "");
  bwk_qr_response response;
  fill_response_header(&response);
  response.is_error = true;
  response.body.error.error = error;
  snprintf(response.body.error.message, sizeof(response.body.error.message),
           "%s", message ? message : "Error");
  show_response(&response);
}

static bool xpub_base58_to_wire(const char *xpub, bwk_qr_xpub *out) {
  struct ext_key *key = NULL;
  bool ok = false;
  if (bip32_key_from_base58_alloc(xpub, &key) == WALLY_OK && key) {
    uint8_t serialized[BWK_QR_XPUB_LEN];
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

static void get_xpubs_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    show_error_response(BWK_QR_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }

  const bwk_qr_get_xpubs *req = &ctx.request->body.get_xpubs;
  size_t n = req->derivation_paths.len;
  bwk_qr_xpub *xpubs = calloc(n, sizeof(*xpubs));
  if (!xpubs) {
    show_error_response(BWK_QR_RESPONSE_ERROR_INTERNAL, "Out of memory");
    return;
  }

  for (size_t i = 0; i < n; i++) {
    const bwk_qr_path *path = &req->derivation_paths.ptr[i];
    char *xpub = NULL;
    if (!key_get_xpub_components(path->ptr, path->len, &xpub) || !xpub ||
        !xpub_base58_to_wire(xpub, &xpubs[i])) {
      if (xpub)
        wally_free_string(xpub);
      free(xpubs);
      show_error_response(BWK_QR_RESPONSE_ERROR_INTERNAL, "Xpub failed");
      return;
    }
    wally_free_string(xpub);
  }

  bwk_qr_response response;
  fill_response_header(&response);
  response.body.xpubs.xpubs.ptr = xpubs;
  response.body.xpubs.xpubs.len = n;
  if (!key_get_fingerprint(response.body.xpubs.fingerprint)) {
    free(xpubs);
    show_error_response(BWK_QR_RESPONSE_ERROR_INTERNAL, "Fingerprint failed");
    return;
  }
  snprintf(response.body.xpubs.model, sizeof(response.body.xpubs.model), "Kern");
  const esp_app_desc_t *desc = esp_app_get_description();
  unsigned major = 0, minor = 0, patch = 0;
  if (desc)
    sscanf(desc->version, "%u.%u.%u", &major, &minor, &patch);
  response.body.xpubs.version.major = (uint16_t)major;
  response.body.xpubs.version.minor = (uint16_t)minor;
  response.body.xpubs.version.patch = patch;
  response.body.xpubs.version.flag = BWK_QR_RELEASE_STABLE;
  response.body.xpubs.capabilities = 0x03;
  show_response(&response);
  free(xpubs);
}

static bool path_requested_network(const bwk_qr_path *path,
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

static bool get_xpubs_network_matches_wallet(const bwk_qr_path_list *paths,
                                             char *message,
                                             size_t message_size) {
  if (!paths || !paths->ptr)
    return true;

  bool have_network = false;
  wallet_network_t requested = WALLET_NETWORK_MAINNET;
  for (size_t i = 0; i < paths->len; i++) {
    wallet_network_t path_network;
    if (!path_requested_network(&paths->ptr[i], &path_network))
      continue;
    if (!have_network) {
      requested = path_network;
      have_network = true;
      continue;
    }
    if (requested != path_network) {
      snprintf(message, message_size, "Request mixes mainnet and testnet paths");
      return false;
    }
  }

  if (!have_network || requested == wallet_get_network())
    return true;

  snprintf(message, message_size, "Request is for %s. Switch Kern network first.",
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

static bool format_xpub_path_range(const bwk_qr_path_list *paths, char *buf,
                                   size_t buf_size) {
  if (!paths || paths->len < 2 || !paths->ptr || !buf || buf_size == 0)
    return false;

  uint8_t depth = paths->ptr[0].len;
  if (depth == 0)
    return false;

  int varying_index = -1;
  for (uint8_t i = 0; i < depth; i++) {
    uint32_t first = paths->ptr[0].ptr[i];
    bool varies = false;
    for (size_t j = 1; j < paths->len; j++) {
      if (!paths->ptr[j].ptr || paths->ptr[j].len != depth)
        return false;
      if (paths->ptr[j].ptr[i] != first)
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

  uint32_t first = paths->ptr[0].ptr[varying_index];
  bool hardened = bip32_path_is_hardened(first);
  uint32_t first_child = bip32_path_unharden(first);
  for (size_t i = 1; i < paths->len; i++) {
    uint32_t component = paths->ptr[i].ptr[varying_index];
    if (bip32_path_is_hardened(component) != hardened)
      return false;
    if (bip32_path_unharden(component) != first_child + i)
      return false;
  }

  size_t off = appendf(buf, buf_size, 0, "m");
  for (uint8_t i = 0; i < depth; i++) {
    if (i == (uint8_t)varying_index) {
      uint32_t last_child = first_child + (uint32_t)paths->len - 1;
      off = appendf(buf, buf_size, off, hardened ? "/{%u-%u}'" : "/{%u-%u}",
                    (unsigned)first_child, (unsigned)last_child);
    } else {
      off = append_path_component(buf, buf_size, off, paths->ptr[0].ptr[i]);
    }
  }

  return off < buf_size;
}

static size_t append_xpub_request_paths(char *msg, size_t msg_size, size_t off,
                                        const bwk_qr_path_list *paths) {
  char range_path[128];
  if (format_xpub_path_range(paths, range_path, sizeof(range_path)))
    return appendf(msg, msg_size, off, "\n\n%s", range_path);

  size_t shown = paths->len < 6 ? paths->len : 6;
  for (size_t i = 0; i < shown && off < msg_size; i++) {
    char path[96];
    if (!bip32_path_format(paths->ptr[i].ptr, paths->ptr[i].len, path,
                           sizeof(path))) {
      snprintf(path, sizeof(path), "<invalid path>");
    }
    off = appendf(msg, msg_size, off, "\n%s", path);
  }
  if (paths->len > shown)
    off = appendf(msg, msg_size, off, "\n...and %zu more",
                  paths->len - shown);
  return off;
}

static void handle_get_xpubs(void) {
  const bwk_qr_get_xpubs *req = &ctx.request->body.get_xpubs;
  char mismatch[80];
  if (!get_xpubs_network_matches_wallet(&req->derivation_paths, mismatch,
                                        sizeof(mismatch))) {
    debug_logf("bip_flow xpub_network_mismatch msg=%s", mismatch);
    show_error_response(BWK_QR_RESPONSE_ERROR_MALFORMED_REQUEST, mismatch);
    return;
  }

  char msg[512];
  size_t off = snprintf(msg, sizeof(msg), "Export %zu xpub(s)?\n",
                        req->derivation_paths.len);
  append_xpub_request_paths(msg, sizeof(msg), off, &req->derivation_paths);
  dialog_show_confirm(msg, get_xpubs_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static bool append_bip388_key(char *out, size_t out_size, size_t *off,
                              const bwk_qr_bip388 *bip388,
                              unsigned long index) {
  if (!bip388 || index >= bip388->keys.len || !bip388->keys.ptr[index])
    return false;

  size_t key_len = strlen(bip388->keys.ptr[index]);
  if (*off > out_size || key_len >= out_size - *off)
    return false;

  memcpy(out + *off, bip388->keys.ptr[index], key_len);
  *off += key_len;
  out[*off] = '\0';
  return true;
}

static char *bip388_to_descriptor(const bwk_qr_bip388 *bip388) {
  if (!bip388 || !bip388->policy)
    return NULL;

  size_t out_size = strlen(bip388->policy) + 1;
  for (size_t i = 0; i < bip388->keys.len; i++) {
    if (!bip388->keys.ptr[i])
      return NULL;
    out_size += strlen(bip388->keys.ptr[i]);
  }

  char *out = malloc(out_size);
  if (!out)
    return NULL;

  size_t off = 0;
  for (const char *p = bip388->policy; *p; p++) {
    if (*p != '@') {
      if (off + 1 >= out_size) {
        free(out);
        return NULL;
      }
      out[off++] = *p;
      continue;
    }

    p++;
    if (*p < '0' || *p > '9') {
      free(out);
      return NULL;
    }

    unsigned long index = 0;
    do {
      index = index * 10 + (unsigned long)(*p - '0');
      p++;
    } while (*p >= '0' && *p <= '9');
    p--;

    if (!append_bip388_key(out, out_size, &off, bip388, index)) {
      free(out);
      return NULL;
    }
  }
  out[off] = '\0';
  return out;
}

static char *request_descriptor_alloc(const bwk_qr_descriptor_body *body) {
  if (!body)
    return NULL;
  if (body->tag == BWK_QR_DESCRIPTOR_BIP380)
    return body->value.bip380 ? strdup(body->value.bip380) : NULL;
  if (body->tag == BWK_QR_DESCRIPTOR_BIP388)
    return bip388_to_descriptor(&body->value.bip388);
  return NULL;
}

static const char *register_error_message(descriptor_validation_result_t result) {
  switch (result) {
  case VALIDATION_FINGERPRINT_NOT_FOUND:
    return "Key not found in descriptor";
  case VALIDATION_XPUB_MISMATCH:
    return "XPub mismatch - check passphrase";
  case VALIDATION_PARSE_ERROR:
    return "Invalid descriptor format";
  case VALIDATION_INVALID_HARDENED_NOTATION:
    return "Descriptor uses 'H'. Use ' or h for hardened.";
  case VALIDATION_UNSUPPORTED_MINISCRIPT:
    return "Only wsh() and tr() miniscript is supported";
  case VALIDATION_UNSUPPORTED_SCRIPT:
    return "Script too large (max 15 multisig keys)";
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

static void register_validation_cb(descriptor_validation_result_t result,
                                   void *user_data) {
  (void)user_data;
  debug_logf("bip_flow register_validation result=%d", result);
  const bwk_qr_register_descriptor *req = &ctx.request->body.register_descriptor;
  if (result == VALIDATION_USER_DECLINED) {
    show_error_response(BWK_QR_RESPONSE_ERROR_USER_DECLINED, "Declined");
    return;
  }

  if (!bip_flow_register_validation_result_allows_response(result)) {
    debug_logf("bip_flow register local_error result=%d", result);
    cleanup_request();
    dialog_show_error_timeout(register_error_message(result), ctx.return_cb, 0);
    return;
  }

  bwk_qr_response response;
  fill_response_header(&response);
  response.body.registration.descriptor_alias = req->descriptor_alias;
  response.body.registration.registered = 1;
  response.body.registration.stored = 1;
  response.body.registration.proof.ptr = NULL;
  response.body.registration.proof.len = 0;
  show_response(&response);
}

static void handle_register(void) {
  debug_log_event("bip_flow handle_register");
  const bwk_qr_register_descriptor *req = &ctx.request->body.register_descriptor;
  if (!req->descriptor) {
    debug_log_event("bip_flow register missing_descriptor");
    cleanup_request();
    dialog_show_error_timeout("Descriptor required for registration",
                              ctx.return_cb, 0);
    return;
  }
  char *descriptor = request_descriptor_alloc(req->descriptor);
  if (!descriptor) {
    debug_log_event("bip_flow register unsupported_descriptor");
    cleanup_request();
    dialog_show_error_timeout("Unsupported descriptor", ctx.return_cb, 0);
    return;
  }
  debug_logf("bip_flow register descriptor_ok alias=%s",
             req->descriptor_alias ? req->descriptor_alias : "");
  descriptor_loader_process_string_with_id(descriptor, req->descriptor_alias,
                                            STORAGE_FLASH,
                                            register_validation_cb, NULL);
  free(descriptor);
}

static bool resolve_descriptor(const char *alias, const bwk_qr_descriptor_body *body,
                               const registry_entry_t **entry_out) {
  if (entry_out)
    *entry_out = NULL;
  if (body) {
    char *descriptor = request_descriptor_alloc(body);
    if (!descriptor)
      return false;
    if (alias && !registry_find_by_id(alias) &&
        !registry_add_from_string(alias, descriptor, STORAGE_FLASH, false)) {
      free(descriptor);
      return false;
    }
    const registry_entry_t *entry = alias ? registry_find_by_id(alias) : NULL;
    if (entry_out)
      *entry_out = entry;
    free(descriptor);
    return true;
  }
  const registry_entry_t *entry = registry_find_by_id(alias);
  if (!entry)
    return false;
  if (entry_out)
    *entry_out = entry;
  return true;
}

static bool address_from_entry_path(const registry_entry_t *entry,
                                    const bwk_qr_path *path, char **out) {
  if (!entry || !path || !out)
    return false;

  size_t suffix_start = 0;
  if (path->len == entry->origin_path_len + 2) {
    for (size_t i = 0; i < entry->origin_path_len; i++) {
      if (path->ptr[i] != entry->origin_path[i])
        return false;
    }
    suffix_start = entry->origin_path_len;
  } else if (path->len != 2) {
    return false;
  }

  uint32_t multi_index = path->ptr[suffix_start];
  uint32_t child_num = path->ptr[suffix_start + 1];
  if (bip32_path_is_hardened(multi_index) || bip32_path_is_hardened(child_num))
    return false;
  return wally_descriptor_to_address(entry->desc, 0, multi_index, child_num, 0,
                                     out) == WALLY_OK;
}

static bool address_to_spk(const char *address, unsigned char *script,
                           size_t script_len, size_t *written) {
  if (!address || !script || !written)
    return false;
  return wally_addr_segwit_to_bytes(address, "bc", 0, script, script_len,
                                    written) == WALLY_OK ||
         wally_addr_segwit_to_bytes(address, "tb", 0, script, script_len,
                                    written) == WALLY_OK ||
         wally_addr_segwit_to_bytes(address, "bcrt", 0, script, script_len,
                                    written) == WALLY_OK ||
         wally_address_to_scriptpubkey(address, WALLY_NETWORK_BITCOIN_MAINNET,
                                       script, script_len, written) == WALLY_OK ||
         wally_address_to_scriptpubkey(address, WALLY_NETWORK_BITCOIN_TESTNET,
                                       script, script_len, written) == WALLY_OK;
}

static bool addresses_have_same_spk(const char *a, const char *b) {
  unsigned char a_script[128];
  unsigned char b_script[128];
  size_t a_len = 0;
  size_t b_len = 0;
  return address_to_spk(a, a_script, sizeof(a_script), &a_len) &&
         address_to_spk(b, b_script, sizeof(b_script), &b_len) &&
         a_len == b_len && memcmp(a_script, b_script, a_len) == 0;
}

static void verify_address_approve_enable_cb(lv_timer_t *timer) {
  (void)timer;
  if (verify_address_approve_btn)
    lv_obj_clear_state(verify_address_approve_btn, LV_STATE_DISABLED);
}

static void verify_address_done_cb(lv_event_t *e) {
  (void)e;
  destroy_verify_address_detail();
  if (pending_verified_address) {
    wally_free_string(pending_verified_address);
    pending_verified_address = NULL;
  }
  cleanup_request();
  if (ctx.return_cb)
    ctx.return_cb();
}

static void verify_local_error(const char *message) {
  debug_logf("bip_flow verify local_error msg=%s", message ? message : "");
  if (pending_verified_address) {
    wally_free_string(pending_verified_address);
    pending_verified_address = NULL;
  }
  cleanup_request();
  dialog_show_error_timeout(message ? message : "Address verification failed",
                            ctx.return_cb, 0);
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

  lv_obj_t *title = theme_create_label(verify_address_detail, "Verify Address", false);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);

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

  lv_obj_t *addr_label = theme_create_label(content, pending_verified_address, false);
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
  lv_timer_t *enable_timer = lv_timer_create(verify_address_approve_enable_cb,
                                            500, NULL);
  lv_timer_set_repeat_count(enable_timer, 1);
}

static void handle_verify(void) {
  debug_log_event("bip_flow handle_verify");
  const bwk_qr_verify_address *req = &ctx.request->body.verify_address;
  const registry_entry_t *entry = NULL;
  if (!resolve_descriptor(req->descriptor_alias, req->descriptor, &entry) ||
      !entry) {
    verify_local_error("Unknown descriptor");
    return;
  }
  char *address = NULL;
  if (!address_from_entry_path(entry, &req->derivation_path, &address) || !address) {
    verify_local_error("Failed to derive address");
    return;
  }
  if (req->address && !addresses_have_same_spk(req->address, address)) {
    wally_free_string(address);
    verify_local_error("Address mismatch");
    return;
  }
  if (pending_verified_address)
    wally_free_string(pending_verified_address);
  if (req->address) {
    pending_verified_address = strdup(req->address);
    wally_free_string(address);
    if (!pending_verified_address) {
      verify_local_error("Out of memory");
      return;
    }
  } else {
    pending_verified_address = address;
  }
  debug_log_event("bip_flow verify show_detail");
  cleanup_request();
  show_verify_address_detail();
}

static uint8_t *serialize_psbt(const struct wally_psbt *psbt, size_t *len_out) {
  size_t len = 0, written = 0;
  if (wally_psbt_get_length(psbt, 0, &len) != WALLY_OK || len == 0)
    return NULL;
  uint8_t *buf = malloc(len);
  if (!buf)
    return NULL;
  if (wally_psbt_to_bytes(psbt, 0, buf, len, &written) != WALLY_OK ||
      written != len) {
    free(buf);
    return NULL;
  }
  *len_out = len;
  return buf;
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

static void free_signature_list(bwk_qr_signature *signatures, size_t len) {
  if (!signatures)
    return;
  for (size_t i = 0; i < len; i++) {
    switch (signatures[i].kind) {
    case BWK_QR_SIGNATURE_ECDSA:
      free((void *)signatures[i].value.ecdsa.signature.ptr);
      break;
    case BWK_QR_SIGNATURE_TAP_KEY:
      free((void *)signatures[i].value.tap_key.signature.ptr);
      break;
    case BWK_QR_SIGNATURE_TAP_SCRIPT:
      free((void *)signatures[i].value.tap_script.signature.ptr);
      break;
    default:
      break;
    }
  }
  free(signatures);
}

static bool copy_signature_bytes(const uint8_t *src, size_t len,
                                 bwk_qr_bytes *out) {
  uint8_t *copy = malloc(len);
  if (!copy)
    return false;
  memcpy(copy, src, len);
  out->ptr = copy;
  out->len = len;
  return true;
}

static bool append_signature(bwk_qr_signature **signatures, size_t *len,
                             size_t *cap, const bwk_qr_signature *sig) {
  if (*len == *cap) {
    size_t new_cap = *cap ? *cap * 2 : 4;
    bwk_qr_signature *new_signatures =
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
                               bwk_qr_signature **signatures_out,
                               size_t *len_out) {
  bwk_qr_signature *signatures = NULL;
  size_t len = 0, cap = 0;

  for (size_t input_index = 0; input_index < psbt->num_inputs; input_index++) {
    const struct wally_psbt_input *input = &psbt->inputs[input_index];
    for (size_t j = 0; j < input->signatures.num_items; j++) {
      const struct wally_map_item *item = &input->signatures.items[j];
      if (item->key_len != BWK_QR_PUBLIC_KEY_LEN || !item->key || !item->value)
        continue;
      bwk_qr_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BWK_QR_SIGNATURE_ECDSA};
      memcpy(sig.value.ecdsa.public_key, item->key, BWK_QR_PUBLIC_KEY_LEN);
      if (!copy_signature_bytes(item->value, item->value_len,
                                &sig.value.ecdsa.signature) ||
          !append_signature(&signatures, &len, &cap, &sig)) {
        free((void *)sig.value.ecdsa.signature.ptr);
        free_signature_list(signatures, len);
        return false;
      }
    }

    size_t tap_key_sig_len = 0;
    if (wally_psbt_get_input_taproot_signature_len(psbt, input_index,
                                                   &tap_key_sig_len) ==
            WALLY_OK &&
        tap_key_sig_len > 0) {
      uint8_t *tap_key_sig = malloc(tap_key_sig_len);
      size_t written = 0;
      if (!tap_key_sig ||
          wally_psbt_get_input_taproot_signature(
              psbt, input_index, tap_key_sig, tap_key_sig_len, &written) !=
              WALLY_OK ||
          written != tap_key_sig_len) {
        free(tap_key_sig);
        free_signature_list(signatures, len);
        return false;
      }
      bwk_qr_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BWK_QR_SIGNATURE_TAP_KEY};
      sig.value.tap_key.signature.ptr = tap_key_sig;
      sig.value.tap_key.signature.len = tap_key_sig_len;
      if (!append_signature(&signatures, &len, &cap, &sig)) {
        free(tap_key_sig);
        free_signature_list(signatures, len);
        return false;
      }
    }

    for (size_t j = 0; j < input->taproot_leaf_signatures.num_items; j++) {
      const struct wally_map_item *item = &input->taproot_leaf_signatures.items[j];
      if (item->key_len != 64 || !item->key || !item->value)
        continue;
      bwk_qr_signature sig = {.input_index = (uint32_t)input_index,
                              .kind = BWK_QR_SIGNATURE_TAP_SCRIPT};
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

static void signed_psbt_cb(struct wally_psbt *psbt, void *user_data) {
  (void)user_data;
  bwk_qr_response response;
  fill_response_header(&response);
  if (ctx.request->body.sign.want_kind == BWK_QR_SIGN_RESPONSE_SIGNATURES) {
    bwk_qr_signature *signatures = NULL;
    size_t signatures_len = 0;
    if (!collect_signatures(psbt, &signatures, &signatures_len)) {
      show_error_response(BWK_QR_RESPONSE_ERROR_INTERNAL,
                          "Signature extraction failed");
      return;
    }
    if (signatures_len == 0) {
      free_signature_list(signatures, signatures_len);
      show_error_response(BWK_QR_RESPONSE_ERROR_NOTHING_TO_SIGN,
                          "Nothing to sign");
      return;
    }
    response.body.signed_body.kind = BWK_QR_SIGN_RESPONSE_SIGNATURES;
    response.body.signed_body.value.signatures.ptr = signatures;
    response.body.signed_body.value.signatures.len = signatures_len;
    show_response_with_done(&response, return_from_signing_response);
    free_signature_list(signatures, signatures_len);
  } else {
    struct wally_psbt *trimmed = psbt_trim(psbt);
    const struct wally_psbt *export_psbt = trimmed ? trimmed : psbt;
    size_t signed_len = 0;
    debug_logf("bip_flow signed_psbt_cb inputs=%u signed_inputs=%u trimmed=%d",
               (unsigned)export_psbt->num_inputs,
               (unsigned)signed_input_count(export_psbt), trimmed != NULL);
    uint8_t *signed_bytes = serialize_psbt(export_psbt, &signed_len);
    if (trimmed)
      wally_psbt_free(trimmed);
    if (!signed_bytes) {
      show_error_response(BWK_QR_RESPONSE_ERROR_INTERNAL, "PSBT encode failed");
      return;
    }
    response.body.signed_body.kind = BWK_QR_SIGN_RESPONSE_PSBT;
    response.body.signed_body.value.psbt.ptr = signed_bytes;
    response.body.signed_body.value.psbt.len = signed_len;
    show_response_with_done(&response, return_from_signing_response);
    free(signed_bytes);
  }
}

static void handle_sign(void) {
  const bwk_qr_sign *req = &ctx.request->body.sign;
  for (size_t i = 0; i < req->descriptors.len; i++) {
    const bwk_qr_descriptor *descriptor = &req->descriptors.ptr[i];
    char *descriptor_str = request_descriptor_alloc(&descriptor->body);
    if (!descriptor_str) {
      show_error_response(BWK_QR_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM,
                          "Unsupported descriptor");
      return;
    }
    if (descriptor->alias && !registry_find_by_id(descriptor->alias) &&
        !registry_add_from_string(descriptor->alias, descriptor_str,
                                  STORAGE_FLASH, false)) {
      free(descriptor_str);
      show_error_response(BWK_QR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED,
                           "Descriptor failed");
      return;
    }
    free(descriptor_str);
  }
  scan_review_psbt(ctx.parent, req->psbt.ptr, req->psbt.len, ctx.return_cb,
                   return_from_signing_response, signed_psbt_cb, NULL);
}

static void dispatch_request(void) {
  debug_logf("bip_flow dispatch message_type=%d", ctx.request->message_type);
  switch (ctx.request->message_type) {
  case BWK_QR_MESSAGE_GET_XPUBS:
    handle_get_xpubs();
    break;
  case BWK_QR_MESSAGE_REGISTER_DESCRIPTOR:
    handle_register();
    break;
  case BWK_QR_MESSAGE_ADDRESS_VERIFICATION:
    handle_verify();
    break;
  case BWK_QR_MESSAGE_SIGNING:
    handle_sign();
    break;
  default:
    show_error_response(BWK_QR_RESPONSE_ERROR_MALFORMED_REQUEST,
                        "Unknown request");
    break;
  }
}

void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void)) {
  debug_log_hex_preview("bip_flow start", data, len, 16);
  ctx.parent = parent;
  ctx.return_cb = return_cb;
  cleanup_request();
  if (pending_verified_address) {
    wally_free_string(pending_verified_address);
    pending_verified_address = NULL;
  }
  const char *err = NULL;
  int32_t rc = bwk_qr_request_decode(data, len, &ctx.request, &err);
  if (rc != BWK_QR_OK || !ctx.request) {
    debug_logf("bip_flow decode_error rc=%d err=%s", (int)rc, err ? err : "");
    dialog_show_error_timeout(err ? err : "Invalid request", return_cb, 0);
    return;
  }
  debug_log_event("bip_flow decode_ok");
  dispatch_request();
}
