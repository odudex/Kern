#include "bip377_internal.h"

#include <string.h>

#define CAPABILITIES_DEFINED                                                   \
  (BIP377_CAPABILITY_BIP380_DESCRIPTORS |                                      \
   BIP377_CAPABILITY_BIP388_WALLET_POLICIES |                                  \
   BIP377_CAPABILITY_MINISCRIPT_SEGWIT_V0 |                                    \
   BIP377_CAPABILITY_MINISCRIPT_TAPROOT |                                      \
   BIP377_CAPABILITY_SILENT_PAYMENT_SENDS |                                    \
   BIP377_CAPABILITY_SILENT_PAYMENT_ACCOUNTS |                                 \
   BIP377_CAPABILITY_UNREGISTER_DESCRIPTOR | BIP377_CAPABILITY_MUSIG2)

#define NETWORKS_DEFINED                                                       \
  (BIP377_NETWORK_MAINNET | BIP377_NETWORK_TESTNET | BIP377_NETWORK_SIGNET |   \
   BIP377_NETWORK_REGTEST)

/* `out` is NULL while measuring. The first failure sticks and every later
 * write is dropped, so the encoders below need no check after each field. A
 * message longer than `cap` keeps counting, to report the size it needs. */
typedef struct {
  uint8_t *out;
  size_t cap;
  size_t len;
  int status;
} writer_t;

static void fail(writer_t *w, int status) {
  if (w->status == BIP377_OK)
    w->status = status;
}

static void write_raw(writer_t *w, const void *data, size_t n) {
  if (w->status != BIP377_OK || n == 0)
    return;
  if (n > SIZE_MAX - w->len) {
    fail(w, BIP377_ERR_TOO_LARGE);
    return;
  }
  if (w->out && n <= w->cap && w->len <= w->cap - n)
    memcpy(w->out + w->len, data, n);
  w->len += n;
}

static void write_u8(writer_t *w, uint8_t value) { write_raw(w, &value, 1); }

static void write_u16_be(writer_t *w, uint16_t value) {
  uint8_t b[2] = {(uint8_t)(value >> 8), (uint8_t)value};
  write_raw(w, b, sizeof(b));
}

static void write_u32_be(writer_t *w, uint32_t value) {
  uint8_t b[4] = {(uint8_t)(value >> 24), (uint8_t)(value >> 16),
                  (uint8_t)(value >> 8), (uint8_t)value};
  write_raw(w, b, sizeof(b));
}

static void write_compact(writer_t *w, size_t size) {
  uint64_t value = size;
  uint8_t b[9];
  size_t width;
  if (value < 0xfd) {
    b[0] = (uint8_t)value;
    width = 0;
  } else if (value <= 0xffff) {
    b[0] = 0xfd;
    width = 2;
  } else if (value <= 0xffffffffULL) {
    b[0] = 0xfe;
    width = 4;
  } else {
    b[0] = 0xff;
    width = 8;
  }
  for (size_t i = 0; i < width; i++)
    b[1 + i] = (uint8_t)(value >> (8 * i));
  write_raw(w, b, 1 + width);
}

static void write_flag(writer_t *w, int value) {
  if (value != 0 && value != 1) {
    fail(w, BIP377_ERR_INVALID_BOOL);
    return;
  }
  write_u8(w, (uint8_t)value);
}

static void write_bytes(writer_t *w, bip377_bytes bytes) {
  if (!bytes.ptr && bytes.len) {
    fail(w, BIP377_ERR_NULL_POINTER);
    return;
  }
  write_compact(w, bytes.len);
  write_raw(w, bytes.ptr, bytes.len);
}

static void write_optional_bytes(writer_t *w, bip377_bytes bytes) {
  write_u8(w, bytes.ptr ? 1 : 0);
  if (bytes.ptr)
    write_bytes(w, bytes);
}

static void write_string(writer_t *w, const char *s, size_t max) {
  if (!s) {
    fail(w, BIP377_ERR_NULL_POINTER);
    return;
  }
  size_t len = strlen(s);
  if (len > max) {
    fail(w, BIP377_ERR_STRING_TOO_LONG);
    return;
  }
  int status = bip377_string_check((const uint8_t *)s, len);
  if (status != BIP377_OK) {
    fail(w, status);
    return;
  }
  write_compact(w, len);
  write_raw(w, s, len);
}

static void write_alias(writer_t *w, const char *alias) {
  write_string(w, alias, BIP377_MAX_DESCRIPTOR_ALIAS);
}

static void write_version(writer_t *w, const bip377_firmware_version *v) {
  if (v->channel == BIP377_RELEASE_STABLE && v->number != 0) {
    fail(w, BIP377_ERR_NUMBERED_STABLE_RELEASE);
    return;
  }
  write_u16_be(w, v->major);
  write_u16_be(w, v->minor);
  write_u16_be(w, v->patch);
  write_u8(w, v->channel);
  write_u8(w, v->number);
}

static void write_capabilities(writer_t *w, uint32_t capabilities) {
  if (capabilities & ~(uint32_t)CAPABILITIES_DEFINED) {
    fail(w, BIP377_ERR_RESERVED_CAPABILITY_BITS);
    return;
  }
  write_u32_be(w, capabilities);
}

static void write_info(writer_t *w, const bip377_info *info) {
  if (info->max_alias > BIP377_MAX_DESCRIPTOR_ALIAS) {
    fail(w, BIP377_ERR_MAX_ALIAS_TOO_LARGE);
    return;
  }
  if (info->has_fingerprint && info->state != BIP377_STATE_READY) {
    fail(w, BIP377_ERR_FINGERPRINT_WHEN_NOT_READY);
    return;
  }
  if (info->networks & ~(uint8_t)NETWORKS_DEFINED) {
    fail(w, BIP377_ERR_RESERVED_NETWORK_BITS);
    return;
  }
  write_string(w, info->vendor, SIZE_MAX);
  write_string(w, info->model, SIZE_MAX);
  write_version(w, &info->version);
  write_capabilities(w, info->capabilities);
  write_u8(w, info->state);
  write_u8(w, info->networks);
  write_u32_be(w, info->max_message);
  write_u8(w, info->max_alias);
  write_flag(w, info->has_fingerprint);
  if (info->has_fingerprint)
    write_raw(w, info->fingerprint, sizeof(info->fingerprint));
}

static void write_keys(writer_t *w, const bip377_keys *keys) {
  if (!keys->keys.ptr && keys->keys.len) {
    fail(w, BIP377_ERR_NULL_POINTER);
    return;
  }
  write_compact(w, keys->keys.len);
  for (size_t i = 0; i < keys->keys.len; i++)
    write_raw(w, keys->keys.ptr[i].bytes, BIP377_EXTENDED_KEY_LEN);
  write_raw(w, keys->fingerprint, sizeof(keys->fingerprint));
  write_string(w, keys->vendor, SIZE_MAX);
  write_string(w, keys->model, SIZE_MAX);
  write_version(w, &keys->version);
  write_capabilities(w, keys->capabilities);
}

static void write_registration(writer_t *w, const bip377_registration *r) {
  write_alias(w, r->descriptor_alias);
  write_u8(w, r->registered ? 1 : 0);
  write_u8(w, r->stored == BIP377_ABSENT_BOOL ? 0 : 1);
  if (r->stored != BIP377_ABSENT_BOOL)
    write_flag(w, r->stored);
  write_optional_bytes(w, r->proof);
}

static void write_taproot_signature(writer_t *w, bip377_bytes signature) {
  if (signature.len != BIP377_SCHNORR_SIGNATURE_LEN &&
      signature.len != BIP377_SCHNORR_SIGNATURE_LEN + 1) {
    fail(w, BIP377_ERR_TAPROOT_SIGNATURE_LENGTH);
    return;
  }
  write_bytes(w, signature);
}

static void write_musig_key(writer_t *w, const uint8_t *participant,
                            const uint8_t *aggregate, uint8_t has_leaf_hash,
                            const uint8_t *leaf_hash) {
  write_raw(w, participant, BIP377_PUBLIC_KEY_LEN);
  write_raw(w, aggregate, BIP377_PUBLIC_KEY_LEN);
  write_flag(w, has_leaf_hash);
  if (has_leaf_hash)
    write_raw(w, leaf_hash, BIP377_TAP_LEAF_HASH_LEN);
}

static void write_sp_scope(writer_t *w, uint8_t global, uint32_t input_index,
                           const uint8_t *scan_key) {
  if (global > 1) {
    fail(w, BIP377_ERR_INVALID_BOOL);
    return;
  }
  if (global && input_index != 0) {
    fail(w, BIP377_ERR_GLOBAL_INPUT_INDEX);
    return;
  }
  write_u8(w, global);
  write_raw(w, scan_key, BIP377_PUBLIC_KEY_LEN);
}

/* KIND_FIELDS of one entry */
static void write_signature_fields(writer_t *w, const bip377_signature *s) {
  const bip377_signature_value *v = &s->value;
  switch (s->kind) {
  case 0x00:
    fail(w, BIP377_ERR_DEFINED_SIGNATURE_KIND);
    break;
  case BIP377_SIGNATURE_ECDSA:
    if (v->ecdsa.signature.len > BIP377_ECDSA_SIGNATURE_MAX_LEN) {
      fail(w, BIP377_ERR_ECDSA_SIGNATURE_LENGTH);
      break;
    }
    write_raw(w, v->ecdsa.public_key, BIP377_PUBLIC_KEY_LEN);
    write_bytes(w, v->ecdsa.signature);
    break;
  case BIP377_SIGNATURE_TAP_KEY:
    write_taproot_signature(w, v->tap_key.signature);
    break;
  case BIP377_SIGNATURE_TAP_SCRIPT:
    write_raw(w, v->tap_script.xonly_public_key, BIP377_XONLY_PUBLIC_KEY_LEN);
    write_raw(w, v->tap_script.tap_leaf_hash, BIP377_TAP_LEAF_HASH_LEN);
    write_taproot_signature(w, v->tap_script.signature);
    break;
  case BIP377_SIGNATURE_MUSIG_PUB_NONCE:
    write_musig_key(
        w, v->musig_pub_nonce.participant, v->musig_pub_nonce.aggregate,
        v->musig_pub_nonce.has_leaf_hash, v->musig_pub_nonce.leaf_hash);
    write_raw(w, v->musig_pub_nonce.nonce, BIP377_MUSIG_PUB_NONCE_LEN);
    break;
  case BIP377_SIGNATURE_MUSIG_PARTIAL_SIG:
    write_musig_key(
        w, v->musig_partial_sig.participant, v->musig_partial_sig.aggregate,
        v->musig_partial_sig.has_leaf_hash, v->musig_partial_sig.leaf_hash);
    write_raw(w, v->musig_partial_sig.signature, BIP377_MUSIG_PARTIAL_SIG_LEN);
    break;
  case BIP377_SIGNATURE_SP_ECDH_SHARE:
    write_sp_scope(w, v->sp_ecdh_share.global, s->input_index,
                   v->sp_ecdh_share.scan_key);
    write_raw(w, v->sp_ecdh_share.share, BIP377_PUBLIC_KEY_LEN);
    break;
  case BIP377_SIGNATURE_SP_DLEQ_PROOF:
    write_sp_scope(w, v->sp_dleq_proof.global, s->input_index,
                   v->sp_dleq_proof.scan_key);
    write_raw(w, v->sp_dleq_proof.proof, BIP377_DLEQ_PROOF_LEN);
    break;
  default:
    if (!v->opaque.ptr && v->opaque.len) {
      fail(w, BIP377_ERR_NULL_POINTER);
      break;
    }
    write_raw(w, v->opaque.ptr, v->opaque.len);
    break;
  }
}

static bool is_sp_entry(const bip377_signature *s) {
  return s->kind == BIP377_SIGNATURE_SP_ECDH_SHARE ||
         s->kind == BIP377_SIGNATURE_SP_DLEQ_PROOF;
}

/* sp_ecdh_share and sp_dleq_proof begin with the same two fields */
static bool same_sp_scope(const bip377_signature *a,
                          const bip377_signature *b) {
  const bip377_sp_ecdh_share *x = &a->value.sp_ecdh_share;
  const bip377_sp_ecdh_share *y = &b->value.sp_ecdh_share;
  if (memcmp(x->scan_key, y->scan_key, BIP377_PUBLIC_KEY_LEN) != 0)
    return false;
  if (x->global || y->global)
    return x->global && y->global;
  return a->input_index == b->input_index;
}

/* Each scope and scan key carries exactly one share and one proof */
static int check_sp_entries(const bip377_signature *entries, size_t len) {
  bool missing_proof = false;
  bool missing_share = false;
  for (size_t i = 0; i < len; i++) {
    if (!is_sp_entry(&entries[i]))
      continue;
    bool paired = false;
    for (size_t j = 0; j < len; j++) {
      if (j == i || !is_sp_entry(&entries[j]) ||
          !same_sp_scope(&entries[i], &entries[j]))
        continue;
      if (entries[j].kind != entries[i].kind)
        paired = true;
      else
        return entries[i].kind == BIP377_SIGNATURE_SP_ECDH_SHARE
                   ? BIP377_ERR_DUPLICATE_SP_SHARE
                   : BIP377_ERR_DUPLICATE_SP_PROOF;
    }
    if (!paired) {
      if (entries[i].kind == BIP377_SIGNATURE_SP_ECDH_SHARE)
        missing_proof = true;
      else
        missing_share = true;
    }
  }
  if (missing_proof)
    return BIP377_ERR_MISSING_SP_PROOF;
  return missing_share ? BIP377_ERR_MISSING_SP_SHARE : BIP377_OK;
}

static void write_signatures(writer_t *w, bip377_signature_list list) {
  if (!list.ptr && list.len) {
    fail(w, BIP377_ERR_NULL_POINTER);
    return;
  }
  int status = check_sp_entries(list.ptr, list.len);
  if (status != BIP377_OK) {
    fail(w, status);
    return;
  }
  write_compact(w, list.len);
  for (size_t i = 0; i < list.len && w->status == BIP377_OK; i++) {
    const bip377_signature *s = &list.ptr[i];
    writer_t fields = {NULL, 0, 0, BIP377_OK};
    write_signature_fields(&fields, s);
    if (fields.status != BIP377_OK) {
      fail(w, fields.status);
      return;
    }
    write_u32_be(w, s->input_index);
    write_u8(w, s->kind);
    write_compact(w, fields.len);
    write_signature_fields(w, s);
  }
}

static void write_signed(writer_t *w, const bip377_signed *s) {
  switch (s->kind) {
  case BIP377_SIGN_RESPONSE_PSBT:
    write_u8(w, s->kind);
    write_bytes(w, s->value.psbt);
    break;
  case BIP377_SIGN_RESPONSE_SIGNATURES:
    write_u8(w, s->kind);
    write_signatures(w, s->value.signatures);
    break;
  default:
    fail(w, BIP377_ERR_UNKNOWN_SIGN_RESPONSE_KIND);
    break;
  }
}

static void write_error(writer_t *w, const bip377_response *r) {
  static const uint8_t unreadable_id[BIP377_REQUEST_ID_LEN] = {0};
  const bip377_error_body *e = &r->body.error;
  if (r->message_type == BIP377_MESSAGE_UNREADABLE_REQUEST) {
    if (memcmp(r->id, unreadable_id, sizeof(unreadable_id)) != 0) {
      fail(w, BIP377_ERR_UNREADABLE_REQUEST_ID);
      return;
    }
    if (e->error != BIP377_RESPONSE_ERROR_MALFORMED_REQUEST) {
      fail(w, BIP377_ERR_UNREADABLE_REQUEST_ERROR);
      return;
    }
  }
  if (e->error == 0x00) {
    fail(w, BIP377_ERR_ERROR_CODE_OUT_OF_RANGE);
    return;
  }
  write_u8(w, e->error);
  write_string(w, e->message, SIZE_MAX);
}

static void write_response(writer_t *w, const bip377_response *r) {
  bool unreadable = r->message_type == BIP377_MESSAGE_UNREADABLE_REQUEST;
  if (!unreadable && !bip377_type_is_request(r->message_type)) {
    fail(w, BIP377_ERR_UNKNOWN_MESSAGE_TYPE);
    return;
  }
  if (unreadable && !r->is_error) {
    fail(w, BIP377_ERR_UNREADABLE_REQUEST_TYPE);
    return;
  }

  write_raw(w, BIP377_MAGIC, BIP377_MAGIC_LEN);
  write_u8(w, BIP377_VERSION);
  write_u8(w, r->message_type | BIP377_DIRECTION_RESPONSE |
                  (r->is_error ? BIP377_STATUS_ERROR : 0));
  write_raw(w, r->id, sizeof(r->id));

  if (r->is_error) {
    write_error(w, r);
    return;
  }
  switch (r->message_type) {
  case BIP377_MESSAGE_GET_INFO:
    write_info(w, &r->body.info);
    break;
  case BIP377_MESSAGE_GET_KEYS:
    write_keys(w, &r->body.keys);
    break;
  case BIP377_MESSAGE_REGISTER_DESCRIPTOR:
    write_registration(w, &r->body.registration);
    break;
  case BIP377_MESSAGE_ADDRESS_VERIFICATION:
    write_string(w, r->body.address_uri.uri, SIZE_MAX);
    break;
  case BIP377_MESSAGE_SIGNING:
    write_signed(w, &r->body.signed_body);
    break;
  default: /* BIP377_MESSAGE_UNREGISTER_DESCRIPTOR */
    write_alias(w, r->body.unregistered.descriptor_alias);
    break;
  }
}

int bip377_response_encode(const bip377_response *response, uint8_t *out,
                           size_t out_len, size_t *written) {
  if (!response || !written)
    return BIP377_ERR_NULL_POINTER;

  writer_t writer = {out, out_len, 0, BIP377_OK};
  write_response(&writer, response);
  if (writer.status != BIP377_OK)
    return writer.status;
  *written = writer.len;
  return out && writer.len > out_len ? BIP377_ERR_BUFFER_TOO_SMALL : BIP377_OK;
}
