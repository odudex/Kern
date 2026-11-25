/* The BIP-377 test vectors, signer direction: every request vector decodes to
 * the message its description gives, every response vector is rebuilt and
 * encodes to the same bytes, every malformed request is refused for its
 * reason. Vectors that are malformed responses, or responses of a later
 * version, need a response decoder and are counted as skipped. */

#include "bip377.h"
#include "vectors.h"

#include <inttypes.h>

#define H 0x80000000u
#define MAX_VECTORS 64

static int failures;
static int decoded, encoded, rejected, skipped;

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "%s:%d: %s: check failed: %s\n", __FILE__, __LINE__,     \
              current_name, #cond);                                            \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static const char *current_name = "";

static const uint8_t ID[BIP377_REQUEST_ID_LEN] = {0x00, 0x01};
static const uint8_t PSBT[] = {0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00,
                               0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t POR[] = {0x5a, 0x5a, 0x5a, 0x5a};
static const uint8_t SP_FINGERPRINT[] = {0x73, 0xc5, 0xda, 0x0a};
static const uint32_t SP_SPEND_PATH[] = {H | 352, H | 1, H, H, 0};
static const uint32_t SP_SCAN_PATH[] = {H | 352, H | 1, H, H | 1, 0};
static const char WPKH[] = "wpkh([00000000/84h/1h/0h]xpub/0/*)";

/* BIP-32 test vector 1: m, then m/0' */
static const char XPUB_HEX[] =
    "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb4"
    "2ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8f"
    "f49c85c2";
static const char CHILD_XPUB_HEX[] =
    "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad"
    "16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c70"
    "6cfccc56";
static const char PUBKEY_HEX[] =
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

static void unhex(const char *hex, uint8_t *out, size_t len) {
  size_t n = 0;
  uint8_t *bytes = hex_decode(hex, &n);
  if (!bytes || n != len) {
    fprintf(stderr, "bad test constant\n");
    exit(2);
  }
  memcpy(out, bytes, len);
  free(bytes);
}

static bool path_is(bip377_path path, const uint32_t *want, size_t len) {
  if (path.len != len)
    return false;
  return len == 0 || memcmp(path.ptr, want, len * sizeof(uint32_t)) == 0;
}

static bool bytes_are(bip377_bytes bytes, const uint8_t *want, size_t len) {
  return bytes.ptr && bytes.len == len && memcmp(bytes.ptr, want, len) == 0;
}

static bool str_is(const char *s, const char *want) {
  return s && strcmp(s, want) == 0;
}

/* Decodes a request vector the way a caller does: measure, allocate exactly,
 * fill. Returns the block to free, NULL on failure. */
static void *decode(const vector_t *v, const bip377_request **request) {
  size_t needed = 0;
  int status = bip377_request_decode(v->bytes, v->len, NULL, 0, &needed, NULL);
  CHECK(status == BIP377_OK);
  if (status != BIP377_OK)
    return NULL;
  void *mem = malloc(needed);
  size_t needed_again = 0;
  status = bip377_request_decode(v->bytes, v->len, mem, needed, &needed_again,
                                 request);
  CHECK(status == BIP377_OK);
  CHECK(needed_again == needed);
  if (status != BIP377_OK) {
    free(mem);
    return NULL;
  }
  CHECK((*request)->version == v->bytes[BIP377_MAGIC_LEN]);
  CHECK(memcmp((*request)->id, ID, sizeof(ID)) == 0);

  bip377_header header;
  CHECK(bip377_request_header(v->bytes, v->len, &header));
  CHECK(header.message_type == (*request)->message_type);
  CHECK(header.version == (*request)->version);
  CHECK(memcmp(header.id, ID, sizeof(ID)) == 0);
  decoded++;
  return mem;
}

static bool sp_keys_are(const bip377_descriptor_body *body, bool own_scan) {
  if (!body || body->tag != BIP377_DESCRIPTOR_SP_KEYS)
    return false;
  const bip377_sp_keys *keys = &body->value.sp_keys;
  if (memcmp(keys->fingerprint, SP_FINGERPRINT, sizeof(SP_FINGERPRINT)) != 0 ||
      !path_is(keys->spend_path, SP_SPEND_PATH, 5))
    return false;
  if (own_scan)
    return keys->scan_kind == BIP377_SCAN_PATH &&
           path_is(keys->scan.path, SP_SCAN_PATH, 5);
  uint8_t scan_key[BIP377_SECRET_KEY_LEN];
  unhex("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        scan_key, sizeof(scan_key));
  return keys->scan_kind == BIP377_SCAN_KEY &&
         memcmp(keys->scan.key, scan_key, sizeof(scan_key)) == 0;
}

static bool wpkh_is(const bip377_descriptor_body *body) {
  return body && body->tag == BIP377_DESCRIPTOR_BIP380 &&
         str_is(body->value.bip380, WPKH);
}

/* --- request vectors --- */

static void request_get_info(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->message_type == BIP377_MESSAGE_GET_INFO);
  free(mem);
}

static void request_get_keys_one_path(const vector_t *v) {
  static const uint32_t path[] = {H | 48, H, H, H | 2};
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->message_type == BIP377_MESSAGE_GET_KEYS);
  CHECK(r->body.get_keys.keys.len == 1);
  CHECK(path_is(r->body.get_keys.keys.ptr[0], path, 4));
  free(mem);
}

static void request_get_keys_sp_and_xpubs(const vector_t *v) {
  static const uint32_t spend[] = {H | 352, H | 1, H, H};
  static const uint32_t scan[] = {H | 352, H | 1, H, H | 1};
  static const uint32_t taproot[] = {H | 86, H | 1, H};
  static const uint32_t segwit[] = {H | 84, H | 1, H};
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_path_list *keys = &r->body.get_keys.keys;
  CHECK(r->message_type == BIP377_MESSAGE_GET_KEYS);
  CHECK(keys->len == 4);
  if (keys->len == 4) {
    CHECK(path_is(keys->ptr[0], spend, 4));
    CHECK(path_is(keys->ptr[1], scan, 4));
    CHECK(path_is(keys->ptr[2], taproot, 3));
    CHECK(path_is(keys->ptr[3], segwit, 3));
  }
  free(mem);
}

static void request_register_bip380(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->message_type == BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  CHECK(str_is(r->body.register_descriptor.descriptor_alias, "main"));
  CHECK(wpkh_is(r->body.register_descriptor.descriptor));
  free(mem);
}

static void request_register_bip388(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_descriptor_body *body = r->body.register_descriptor.descriptor;
  CHECK(str_is(r->body.register_descriptor.descriptor_alias, "main"));
  CHECK(body && body->tag == BIP377_DESCRIPTOR_BIP388);
  if (body && body->tag == BIP377_DESCRIPTOR_BIP388) {
    const bip377_bip388 *policy = &body->value.bip388;
    CHECK(policy->keys.len == 2);
    if (policy->keys.len == 2) {
      CHECK(str_is(policy->keys.ptr[0], "[00000000/48h/1h/0h/2h]xpub"));
      CHECK(str_is(policy->keys.ptr[1], "[11111111/48h/1h/0h/2h]xpub"));
    }
    CHECK(str_is(policy->policy, "wsh(sortedmulti(2,@0/**,@1/**))"));
  }
  free(mem);
}

static void request_register_sp_keys(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(str_is(r->body.register_descriptor.descriptor_alias, "main"));
  CHECK(sp_keys_are(r->body.register_descriptor.descriptor, true));
  free(mem);
}

static void request_register_status_query(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->message_type == BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  CHECK(str_is(r->body.register_descriptor.descriptor_alias, "main"));
  CHECK(r->body.register_descriptor.descriptor == NULL);
  free(mem);
}

static void request_unregister(const vector_t *v) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->message_type == BIP377_MESSAGE_UNREGISTER_DESCRIPTOR);
  CHECK(str_is(r->body.unregister_descriptor.descriptor_alias, "main"));
  free(mem);
}

static void request_verify_address(const vector_t *v) {
  static const uint32_t deriv[] = {7};
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_verify_address *req = &r->body.verify_address;
  CHECK(r->message_type == BIP377_MESSAGE_ADDRESS_VERIFICATION);
  CHECK(str_is(req->descriptor_alias, "main"));
  CHECK(path_is(req->derivation_path, deriv, 1));
  CHECK(str_is(req->address, "bc1qxyz"));
  CHECK(wpkh_is(req->descriptor));
  CHECK(bytes_are(req->proof, POR, sizeof(POR)));
  free(mem);
}

static void verify_sp(const vector_t *v, bool with_por) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_verify_address *req = &r->body.verify_address;
  CHECK(str_is(req->descriptor_alias, "main"));
  CHECK(req->derivation_path.len == 0);
  CHECK(str_is(req->address, "sp1qxyz"));
  CHECK(sp_keys_are(req->descriptor, true));
  if (with_por)
    CHECK(bytes_are(req->proof, POR, sizeof(POR)));
  else
    CHECK(req->proof.ptr == NULL && req->proof.len == 0);
  free(mem);
}

static void request_verify_sp(const vector_t *v) { verify_sp(v, false); }

static void request_verify_sp_with_por(const vector_t *v) {
  verify_sp(v, true);
}

static void request_verify_sp_foreign_scan(const vector_t *v) {
  static const uint32_t label[] = {2};
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_verify_address *req = &r->body.verify_address;
  CHECK(str_is(req->descriptor_alias, "main"));
  CHECK(path_is(req->derivation_path, label, 1));
  CHECK(str_is(req->address, "sp1qxyz"));
  CHECK(sp_keys_are(req->descriptor, false));
  CHECK(req->proof.ptr == NULL);
  free(mem);
}

static void sign_request(const vector_t *v, int want_kind, bool trimmed) {
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  const bip377_sign *req = &r->body.sign;
  CHECK(r->message_type == BIP377_MESSAGE_SIGNING);
  CHECK(req->descriptors.len == 1);
  if (req->descriptors.len == 1) {
    const bip377_descriptor *d = &req->descriptors.ptr[0];
    CHECK(str_is(d->alias, "main"));
    CHECK(wpkh_is(d->body));
    CHECK(bytes_are(d->proof, POR, sizeof(POR)));
  }
  CHECK(bytes_are(req->psbt, PSBT, sizeof(PSBT)));
  CHECK(req->want_kind == want_kind);
  CHECK(req->accept_trimmed == trimmed);
  free(mem);
}

static void request_sign(const vector_t *v) {
  sign_request(v, BIP377_SIGN_RESPONSE_SIGNATURES, false);
}

static void request_sign_accept_trimmed(const vector_t *v) {
  sign_request(v, BIP377_SIGN_RESPONSE_PSBT, true);
}

static void request_version_two(const vector_t *v) {
  static const uint32_t path[] = {H | 48, H, H, H | 2};
  const bip377_request *r;
  void *mem = decode(v, &r);
  if (!mem)
    return;
  CHECK(r->version == 2);
  CHECK(r->body.get_keys.keys.len == 1);
  CHECK(path_is(r->body.get_keys.keys.ptr[0], path, 4));
  free(mem);
}

/* --- response vectors --- */

/* Encodes `response` and compares it with the vector, byte for byte */
static void expect_encoding(const vector_t *v,
                            const bip377_response *response) {
  size_t needed = 0;
  int status = bip377_response_encode(response, NULL, 0, &needed);
  CHECK(status == BIP377_OK);
  if (status != BIP377_OK) {
    fprintf(stderr, "  encode: %s\n", bip377_strerror(status));
    return;
  }
  CHECK(needed == v->len);
  uint8_t *out = malloc(needed ? needed : 1);
  size_t written = 0;
  status = bip377_response_encode(response, out, needed, &written);
  CHECK(status == BIP377_OK);
  CHECK(written == needed);
  CHECK(needed == v->len && memcmp(out, v->bytes, v->len) == 0);
  free(out);
  encoded++;
}

static void response_init(bip377_response *r, uint8_t type) {
  memset(r, 0, sizeof(*r));
  memcpy(r->id, ID, sizeof(ID));
  r->message_type = type;
}

static const bip377_firmware_version FW_VERSION = {1, 2, 3, BIP377_RELEASE_BETA,
                                                   2};

static void info_response(const vector_t *v, uint32_t capabilities) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_GET_INFO);
  bip377_info *info = &r.body.info;
  info->vendor = "bip";
  info->model = "bip-signer";
  info->version = FW_VERSION;
  info->capabilities = capabilities;
  info->state = BIP377_STATE_READY;
  info->networks = BIP377_NETWORK_MAINNET | BIP377_NETWORK_TESTNET |
                   BIP377_NETWORK_SIGNET | BIP377_NETWORK_REGTEST;
  info->max_message = 0x00080000;
  info->max_alias = 32;
  info->has_fingerprint = 1;
  unhex("deadbeef", info->fingerprint, sizeof(info->fingerprint));
  expect_encoding(v, &r);
}

static void response_info_ready(const vector_t *v) { info_response(v, 0xbf); }

static void response_info_unregister(const vector_t *v) {
  info_response(v, 0xff);
}

static void response_info_locked(const vector_t *v) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_GET_INFO);
  bip377_info *info = &r.body.info;
  info->vendor = "bip";
  info->model = "bip-signer";
  info->version = FW_VERSION;
  info->capabilities = 0xbf;
  info->state = BIP377_STATE_LOCKED;
  info->networks = BIP377_NETWORK_MAINNET;
  info->max_message = 0x1000;
  info->max_alias = 16;
  expect_encoding(v, &r);
}

static void response_keys(const vector_t *v) {
  bip377_extended_key keys[2];
  unhex(XPUB_HEX, keys[0].bytes, sizeof(keys[0].bytes));
  unhex(CHILD_XPUB_HEX, keys[1].bytes, sizeof(keys[1].bytes));
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_GET_KEYS);
  r.body.keys.keys.ptr = keys;
  r.body.keys.keys.len = 2;
  unhex("deadbeef", r.body.keys.fingerprint, sizeof(r.body.keys.fingerprint));
  r.body.keys.vendor = "bip";
  r.body.keys.model = "bip-signer";
  r.body.keys.version = FW_VERSION;
  r.body.keys.capabilities = 0xbf;
  expect_encoding(v, &r);
}

static void response_registered(const vector_t *v) {
  static const uint8_t proof[8] = {0xaa, 0xaa, 0xaa, 0xaa,
                                   0xaa, 0xaa, 0xaa, 0xaa};
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  r.body.registration.descriptor_alias = "main";
  r.body.registration.registered = true;
  r.body.registration.stored = 1;
  r.body.registration.proof.ptr = proof;
  r.body.registration.proof.len = sizeof(proof);
  expect_encoding(v, &r);
}

static void response_not_registered(const vector_t *v) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  r.body.registration.descriptor_alias = "main";
  r.body.registration.registered = false;
  r.body.registration.stored = BIP377_ABSENT_BOOL;
  expect_encoding(v, &r);
}

static void response_unregistered(const vector_t *v) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_UNREGISTER_DESCRIPTOR);
  r.body.unregistered.descriptor_alias = "main";
  expect_encoding(v, &r);
}

static void response_address_uri(const vector_t *v) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_ADDRESS_VERIFICATION);
  r.body.address_uri.uri = "bitcoin:bc1qxyz";
  expect_encoding(v, &r);
}

static void response_signed_psbt(const vector_t *v) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_SIGNING);
  r.body.signed_body.kind = BIP377_SIGN_RESPONSE_PSBT;
  r.body.signed_body.value.psbt.ptr = PSBT;
  r.body.signed_body.value.psbt.len = sizeof(PSBT);
  expect_encoding(v, &r);
}

static void expect_signatures(const vector_t *v, const bip377_signature *list,
                              size_t len) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_SIGNING);
  r.body.signed_body.kind = BIP377_SIGN_RESPONSE_SIGNATURES;
  r.body.signed_body.value.signatures.ptr = list;
  r.body.signed_body.value.signatures.len = len;
  expect_encoding(v, &r);
}

static uint8_t fill[8][80];

/* A run of `len` bytes of `value`, in slot `slot` */
static bip377_bytes run(int slot, uint8_t value, size_t len) {
  memset(fill[slot], value, len);
  bip377_bytes bytes = {fill[slot], len};
  return bytes;
}

/* A compressed key: `prefix` then 32 bytes of `value` */
static void point(uint8_t *out, uint8_t prefix, uint8_t value) {
  out[0] = prefix;
  memset(out + 1, value, BIP377_PUBLIC_KEY_LEN - 1);
}

static bip377_signature tap_key_entry(uint32_t input, int slot, uint8_t value) {
  bip377_signature s;
  memset(&s, 0, sizeof(s));
  s.input_index = input;
  s.kind = BIP377_SIGNATURE_TAP_KEY;
  s.value.tap_key.signature = run(slot, value, 64);
  return s;
}

static void response_signatures(const vector_t *v) {
  bip377_signature list[3];
  memset(list, 0, sizeof(list));
  list[0].input_index = 0;
  list[0].kind = BIP377_SIGNATURE_ECDSA;
  unhex(PUBKEY_HEX, list[0].value.ecdsa.public_key, BIP377_PUBLIC_KEY_LEN);
  list[0].value.ecdsa.signature = run(0, 0x30, 71);
  list[1] = tap_key_entry(1, 1, 0x01);
  list[2].input_index = 2;
  list[2].kind = BIP377_SIGNATURE_TAP_SCRIPT;
  memset(list[2].value.tap_script.xonly_public_key, 0x02, 32);
  memset(list[2].value.tap_script.tap_leaf_hash, 0x03, 32);
  list[2].value.tap_script.signature = run(2, 0x04, 65);
  expect_signatures(v, list, 3);
}

static void response_musig_pub_nonces(const vector_t *v) {
  bip377_signature list[2];
  memset(list, 0, sizeof(list));
  bip377_musig_pub_nonce *n = &list[0].value.musig_pub_nonce;
  list[0].kind = BIP377_SIGNATURE_MUSIG_PUB_NONCE;
  unhex(PUBKEY_HEX, n->participant, BIP377_PUBLIC_KEY_LEN);
  point(n->aggregate, 0x02, 0x11);
  memset(n->nonce, 0x22, sizeof(n->nonce));

  n = &list[1].value.musig_pub_nonce;
  list[1].input_index = 1;
  list[1].kind = BIP377_SIGNATURE_MUSIG_PUB_NONCE;
  unhex(PUBKEY_HEX, n->participant, BIP377_PUBLIC_KEY_LEN);
  point(n->aggregate, 0x03, 0x33);
  n->has_leaf_hash = 1;
  memset(n->leaf_hash, 0x44, sizeof(n->leaf_hash));
  memset(n->nonce, 0x55, sizeof(n->nonce));
  expect_signatures(v, list, 2);
}

static void response_musig_partial_sigs(const vector_t *v) {
  bip377_signature list[2];
  memset(list, 0, sizeof(list));
  bip377_musig_partial_sig *p = &list[0].value.musig_partial_sig;
  list[0].kind = BIP377_SIGNATURE_MUSIG_PARTIAL_SIG;
  unhex(PUBKEY_HEX, p->participant, BIP377_PUBLIC_KEY_LEN);
  point(p->aggregate, 0x02, 0x11);
  memset(p->signature, 0x66, sizeof(p->signature));

  p = &list[1].value.musig_partial_sig;
  list[1].input_index = 1;
  list[1].kind = BIP377_SIGNATURE_MUSIG_PARTIAL_SIG;
  unhex(PUBKEY_HEX, p->participant, BIP377_PUBLIC_KEY_LEN);
  point(p->aggregate, 0x03, 0x33);
  p->has_leaf_hash = 1;
  memset(p->leaf_hash, 0x44, sizeof(p->leaf_hash));
  memset(p->signature, 0x77, sizeof(p->signature));
  expect_signatures(v, list, 2);
}

static bip377_signature share_entry(uint32_t input, bool global,
                                    uint8_t scan_prefix, uint8_t scan,
                                    uint8_t share) {
  bip377_signature s;
  memset(&s, 0, sizeof(s));
  s.input_index = input;
  s.kind = BIP377_SIGNATURE_SP_ECDH_SHARE;
  s.value.sp_ecdh_share.global = global;
  point(s.value.sp_ecdh_share.scan_key, scan_prefix, scan);
  point(s.value.sp_ecdh_share.share, 0x02, share);
  return s;
}

static bip377_signature proof_entry(uint32_t input, bool global,
                                    uint8_t scan_prefix, uint8_t scan,
                                    uint8_t proof) {
  bip377_signature s;
  memset(&s, 0, sizeof(s));
  s.input_index = input;
  s.kind = BIP377_SIGNATURE_SP_DLEQ_PROOF;
  s.value.sp_dleq_proof.global = global;
  point(s.value.sp_dleq_proof.scan_key, scan_prefix, scan);
  memset(s.value.sp_dleq_proof.proof, proof, BIP377_DLEQ_PROOF_LEN);
  return s;
}

static void response_sp_global(const vector_t *v) {
  bip377_signature list[6];
  list[0] = tap_key_entry(0, 0, 0x01);
  list[1] = tap_key_entry(1, 1, 0x02);
  list[2] = share_entry(0, true, 0x02, 0x5a, 0xa0);
  list[3] = proof_entry(0, true, 0x02, 0x5a, 0xb0);
  list[4] = share_entry(0, true, 0x03, 0x5b, 0xa1);
  list[5] = proof_entry(0, true, 0x03, 0x5b, 0xb1);
  expect_signatures(v, list, 6);
}

static void response_sp_per_input(const vector_t *v) {
  bip377_signature list[6];
  list[0] = tap_key_entry(0, 0, 0x01);
  list[1] = share_entry(0, false, 0x02, 0x5a, 0xa0);
  list[2] = proof_entry(0, false, 0x02, 0x5a, 0xb0);
  list[3] = tap_key_entry(2, 1, 0x03);
  list[4] = share_entry(2, false, 0x02, 0x5a, 0xa2);
  list[5] = proof_entry(2, false, 0x02, 0x5a, 0xb2);
  expect_signatures(v, list, 6);
}

static void response_unknown_sig_kind(const vector_t *v) {
  static const uint8_t fields[] = {0xde, 0xad, 0xbe, 0xef};
  bip377_signature list[2];
  memset(list, 0, sizeof(list));
  list[0].kind = 0x08;
  list[0].value.opaque.ptr = fields;
  list[0].value.opaque.len = sizeof(fields);
  list[1] = tap_key_entry(0, 0, 0x01);
  expect_signatures(v, list, 2);
}

static void error_response(const vector_t *v, uint8_t type, uint8_t error,
                           const char *message) {
  bip377_response r;
  response_init(&r, type);
  r.is_error = true;
  r.body.error.error = error;
  r.body.error.message = message;
  expect_encoding(v, &r);
}

static void response_error_user_declined(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_SIGNING, BIP377_RESPONSE_ERROR_USER_DECLINED,
                 "signing was declined");
}

static void response_error_vendor(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_SIGNING, BIP377_RESPONSE_ERROR_VENDOR,
                 "device is locked");
}

static void response_error_musig_session(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_SIGNING, BIP377_RESPONSE_ERROR_MUSIG_SESSION,
                 "musig2 session missing");
}

static void response_error_already_registered(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_REGISTER_DESCRIPTOR,
                 BIP377_RESPONSE_ERROR_ALREADY_REGISTERED,
                 "alias already registered");
}

static void response_error_unsupported_operation(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_ADDRESS_VERIFICATION,
                 BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION,
                 "silent payments not supported");
}

static void response_error_network_mismatch(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_SIGNING,
                 BIP377_RESPONSE_ERROR_NETWORK_MISMATCH, "wrong network");
}

static void response_error_reserved_code(const vector_t *v) {
  error_response(v, BIP377_MESSAGE_GET_KEYS, 0x11,
                 "code added after version 1");
}

static void response_error_unreadable_request(const vector_t *v) {
  bip377_response r;
  memset(&r, 0, sizeof(r));
  r.message_type = BIP377_MESSAGE_UNREADABLE_REQUEST;
  r.is_error = true;
  r.body.error.error = BIP377_RESPONSE_ERROR_MALFORMED_REQUEST;
  r.body.error.message = "request header is unreadable";
  expect_encoding(v, &r);
}

/* --- the table --- */

typedef struct {
  const char *name;
  void (*check)(const vector_t *v); /* a valid vector */
  int status;      /* a malformed request: what decoding it returns */
  bool unreadable; /* a malformed request: its header is unreadable too */
} case_t;

#define VALID(name, check) {name, check, 0, false}
#define MALFORMED(name, status, unreadable) {name, NULL, status, unreadable}
#define RESPONSE_DECODING(name) {name, NULL, 0, false}

static const case_t CASES[] = {
    VALID("get_info_request", request_get_info),
    VALID("get_info_response_ready", response_info_ready),
    VALID("get_info_response_unregister", response_info_unregister),
    VALID("get_info_response_locked", response_info_locked),
    VALID("get_keys_request_one_path", request_get_keys_one_path),
    VALID("get_keys_request_silent_payment_and_xpubs",
          request_get_keys_sp_and_xpubs),
    VALID("get_keys_response_ok", response_keys),
    VALID("register_descriptor_request_bip380", request_register_bip380),
    VALID("register_descriptor_request_bip388", request_register_bip388),
    VALID("register_descriptor_request_sp_keys", request_register_sp_keys),
    VALID("register_descriptor_request_status_query",
          request_register_status_query),
    VALID("register_descriptor_response_registered", response_registered),
    VALID("register_descriptor_response_not_registered",
          response_not_registered),
    VALID("unregister_descriptor_request", request_unregister),
    VALID("unregister_descriptor_response", response_unregistered),
    VALID("address_verification_request", request_verify_address),
    VALID("address_verification_sp_request", request_verify_sp),
    VALID("address_verification_sp_request_with_por",
          request_verify_sp_with_por),
    VALID("address_verification_sp_foreign_scan_request",
          request_verify_sp_foreign_scan),
    VALID("address_verification_response_uri", response_address_uri),
    VALID("signing_request", request_sign),
    VALID("signing_request_accept_trimmed", request_sign_accept_trimmed),
    VALID("signing_response_psbt", response_signed_psbt),
    VALID("signing_response_signatures", response_signatures),
    VALID("signing_response_musig_pub_nonces", response_musig_pub_nonces),
    VALID("signing_response_musig_partial_sigs", response_musig_partial_sigs),
    VALID("signing_response_silent_payment_global", response_sp_global),
    VALID("signing_response_silent_payment_per_input", response_sp_per_input),
    VALID("signing_response_unknown_sig_kind", response_unknown_sig_kind),
    VALID("error_response_user_declined", response_error_user_declined),
    VALID("error_response_vendor", response_error_vendor),
    VALID("error_response_musig_session", response_error_musig_session),
    VALID("error_response_already_registered",
          response_error_already_registered),
    VALID("error_response_unsupported_operation",
          response_error_unsupported_operation),
    VALID("error_response_network_mismatch", response_error_network_mismatch),
    VALID("error_response_reserved_code", response_error_reserved_code),
    VALID("error_response_unreadable_request",
          response_error_unreadable_request),
    VALID("versioning_get_keys_request_version_two", request_version_two),
    RESPONSE_DECODING("versioning_address_uri_response_version_two"),

    MALFORMED("invalid_magic", BIP377_ERR_INVALID_MAGIC, true),
    MALFORMED("invalid_unreadable_type_in_request",
              BIP377_ERR_UNREADABLE_REQUEST_TYPE, true),
    RESPONSE_DECODING("invalid_unreadable_type_in_ok_response"),
    RESPONSE_DECODING("invalid_unreadable_type_request_id"),
    MALFORMED("invalid_type_unknown", BIP377_ERR_UNKNOWN_MESSAGE_TYPE, true),
    MALFORMED("invalid_status_on_request", BIP377_ERR_ERROR_STATUS_ON_REQUEST,
              true),
    MALFORMED("invalid_truncated", BIP377_ERR_TRUNCATED, false),
    RESPONSE_DECODING("invalid_length_past_input"),
    RESPONSE_DECODING("invalid_sign_kind_reserved"),
    RESPONSE_DECODING("invalid_sign_kind_unknown"),
    RESPONSE_DECODING("invalid_bool"),
    MALFORMED("invalid_accept_trimmed", BIP377_ERR_INVALID_BOOL, false),
    MALFORMED("invalid_form_reserved", BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM,
              false),
    MALFORMED("invalid_form_unknown", BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM,
              false),
    MALFORMED("invalid_alias_too_long", BIP377_ERR_STRING_TOO_LARGE, false),
    MALFORMED("invalid_unregister_descriptor_no_alias", BIP377_ERR_TRUNCATED,
              false),
    MALFORMED("invalid_unregister_descriptor_status_on_request",
              BIP377_ERR_ERROR_STATUS_ON_REQUEST, true),
    MALFORMED("invalid_unregister_descriptor_alias_too_long",
              BIP377_ERR_STRING_TOO_LARGE, false),
    MALFORMED("invalid_sp_keys_scan_path_and_key", BIP377_ERR_SCAN_PATH_AND_KEY,
              false),
    MALFORMED("invalid_sp_keys_no_scan", BIP377_ERR_NO_SCAN, false),
    RESPONSE_DECODING("invalid_string_utf8"),
    RESPONSE_DECODING("invalid_string_nul"),
    RESPONSE_DECODING("invalid_tapkey_signature_short"),
    RESPONSE_DECODING("invalid_taptree_signature_long"),
    RESPONSE_DECODING("invalid_entry_length_unfilled"),
    RESPONSE_DECODING("invalid_entry_length_overflow"),
    RESPONSE_DECODING("invalid_sp_share_without_proof"),
    RESPONSE_DECODING("invalid_sp_proof_without_share"),
    RESPONSE_DECODING("invalid_sp_duplicate_share"),
    RESPONSE_DECODING("invalid_sp_duplicate_proof"),
    RESPONSE_DECODING("invalid_sp_global_input_index"),
    RESPONSE_DECODING("invalid_get_info_stable_release_number"),
    RESPONSE_DECODING("invalid_get_info_max_alias"),
    RESPONSE_DECODING("invalid_get_info_fingerprint_locked"),
};
#define CASE_COUNT (sizeof(CASES) / sizeof(CASES[0]))

static bool seen[CASE_COUNT];

static void run_vector(const vector_t *v) {
  current_name = v->name;
  size_t index = CASE_COUNT;
  for (size_t i = 0; i < CASE_COUNT; i++) {
    if (strcmp(CASES[i].name, v->name) == 0)
      index = i;
  }
  if (index == CASE_COUNT) {
    fprintf(stderr, "%s: no test for this vector\n", v->name);
    failures++;
    return;
  }
  CHECK(!seen[index]);
  seen[index] = true;
  const case_t *c = &CASES[index];

  /* A signer reads requests only: a response never decodes as one */
  if (!v->is_request) {
    size_t needed;
    CHECK(bip377_request_decode(v->bytes, v->len, NULL, 0, &needed, NULL) !=
          BIP377_OK);
  }

  if (c->check) {
    CHECK(!v->decode_error);
    CHECK(v->is_request || !v->decode_only);
    c->check(v);
  } else if (c->status != 0) {
    CHECK(v->is_request && v->decode_error && v->decode_only);
    size_t needed;
    int status =
        bip377_request_decode(v->bytes, v->len, NULL, 0, &needed, NULL);
    if (status != c->status)
      fprintf(stderr, "  got %d (%s), want %d\n", status,
              bip377_strerror(status), c->status);
    CHECK(status == c->status);
    bip377_header header;
    bool readable = bip377_request_header(v->bytes, v->len, &header);
    CHECK(readable == !c->unreadable);
    if (!readable) {
      CHECK(header.message_type == BIP377_MESSAGE_UNREADABLE_REQUEST);
      CHECK(header.id[0] == 0 && header.id[1] == 0);
    }
    rejected++;
  } else {
    CHECK(!v->is_request && v->decode_only);
    skipped++;
  }
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "test/vectors";
  int total = 0;
  for (size_t f = 0; f < VECTOR_FILE_COUNT; f++) {
    vector_t vectors[MAX_VECTORS];
    int count = vectors_load(dir, VECTOR_FILES[f], vectors, MAX_VECTORS);
    if (count <= 0) {
      fprintf(stderr, "%s: no vectors\n", VECTOR_FILES[f]);
      return 1;
    }
    for (int i = 0; i < count; i++)
      run_vector(&vectors[i]);
    total += count;
    vectors_free(vectors, count);
  }
  current_name = "table";
  for (size_t i = 0; i < CASE_COUNT; i++) {
    if (!seen[i]) {
      fprintf(stderr, "%s: vector not found in the files\n", CASES[i].name);
      failures++;
    }
  }
  CHECK((size_t)total == CASE_COUNT);

  printf("bip377 vectors: %d total, %d requests decoded, %d responses encoded, "
         "%d malformed requests refused, %d skipped (response decoding)\n",
         total, decoded, encoded, rejected, skipped);
  if (failures) {
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  return 0;
}
