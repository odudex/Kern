/* What the vectors do not reach: the calling contract of the two functions,
 * every response the encoder refuses, decoder rules without a vector, and a
 * mutation pass that feeds the decoder every truncation and byte change of the
 * valid request vectors. Build with DEBUG=1 to run it under ASan and UBSan:
 * inputs and blocks are sized exactly, so an overread or overrun is caught. */

#include "bip377.h"
#include "vectors.h"

#define MAX_VECTORS 64

static int failures;
static const char *current_name = "";

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "%s:%d: %s: check failed: %s\n", __FILE__, __LINE__,     \
              current_name, #cond);                                            \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static int measure(const uint8_t *msg, size_t len) {
  size_t needed = 0;
  return bip377_request_decode(msg, len, NULL, 0, &needed, NULL);
}

/* Decodes into a block of exactly the measured size; the caller frees it */
static int decode(const uint8_t *msg, size_t len, void **mem_out,
                  const bip377_request **request) {
  size_t needed = 0;
  *mem_out = NULL;
  int status = bip377_request_decode(msg, len, NULL, 0, &needed, NULL);
  if (status != BIP377_OK)
    return status;
  *mem_out = malloc(needed ? needed : 1);
  return bip377_request_decode(msg, len, *mem_out, needed, NULL, request);
}

/* --- decoder rules --- */

#define HEADER(type) 'B', 'I', 'P', '3', '7', '7', 0x01, type, 0x00, 0x01

static void test_decode_rules(void) {
  current_name = "decode rules";
  void *mem;
  const bip377_request *r;

  /* TYPE 0x06 is reserved: unknown to the decoder, unreadable as a header */
  const uint8_t reserved_type[] = {HEADER(0x06)};
  bip377_header header;
  CHECK(measure(reserved_type, sizeof(reserved_type)) ==
        BIP377_ERR_UNKNOWN_MESSAGE_TYPE);
  CHECK(!bip377_request_header(reserved_type, sizeof(reserved_type), &header));
  CHECK(header.message_type == BIP377_MESSAGE_UNREADABLE_REQUEST);

  const uint8_t version_zero[] = {'B', 'I',  'P',  '3',  '7',
                                  '7', 0x00, 0x01, 0x00, 0x01};
  CHECK(measure(version_zero, sizeof(version_zero)) ==
        BIP377_ERR_RESERVED_VERSION);
  CHECK(bip377_request_header(version_zero, sizeof(version_zero), &header));
  CHECK(header.version == 0);

  const uint8_t response[] = {HEADER(0x81)};
  CHECK(measure(response, sizeof(response)) == BIP377_ERR_DIRECTION_DISABLED);

  /* A header one byte short of its REQUEST_ID is unreadable */
  const uint8_t short_id[] = {'B', 'I', 'P', '3', '7', '7', 0x01, 0x01, 0x00};
  CHECK(measure(short_id, sizeof(short_id)) == BIP377_ERR_TRUNCATED);
  CHECK(!bip377_request_header(short_id, sizeof(short_id), &header));
  CHECK(!bip377_request_header(NULL, 0, &header));
  CHECK(!bip377_is_message(NULL, 0));
  CHECK(!bip377_is_message((const uint8_t *)"BIP37", 5));
  CHECK(bip377_is_message((const uint8_t *)"BIP377", 6));

  /* COUNT 1 written on three bytes */
  const uint8_t non_canonical[] = {HEADER(0x02), 0xfd, 0x01, 0x00, 0x00};
  CHECK(measure(non_canonical, sizeof(non_canonical)) ==
        BIP377_ERR_NON_CANONICAL_COMPACT_SIZE);
  const uint8_t non_canonical_32[] = {HEADER(0x02), 0xfe, 0x01, 0x00,
                                      0x00,         0x00, 0x00};
  CHECK(measure(non_canonical_32, sizeof(non_canonical_32)) ==
        BIP377_ERR_NON_CANONICAL_COMPACT_SIZE);
  const uint8_t non_canonical_64[] = {HEADER(0x02), 0xff, 0x01, 0x00, 0x00,
                                      0x00,         0x00, 0x00, 0x00, 0x00};
  CHECK(measure(non_canonical_64, sizeof(non_canonical_64)) ==
        BIP377_ERR_NON_CANONICAL_COMPACT_SIZE);

  /* A COUNT the message cannot hold reserves nothing */
  const uint8_t huge_count[] = {HEADER(0x02), 0xfe, 0xff, 0xff, 0xff, 0x7f};
  CHECK(measure(huge_count, sizeof(huge_count)) == BIP377_ERR_TRUNCATED);
  const uint8_t huge_descriptors[] = {HEADER(0x05), 0xfd, 0xff, 0xff, 0x00};
  CHECK(measure(huge_descriptors, sizeof(huge_descriptors)) ==
        BIP377_ERR_TRUNCATED);

  /* An empty KEYS vector is a valid request */
  const uint8_t no_keys[] = {HEADER(0x02), 0x00};
  CHECK(decode(no_keys, sizeof(no_keys), &mem, &r) == BIP377_OK);
  if (mem) {
    CHECK(r->body.get_keys.keys.len == 0);
    CHECK(r->body.get_keys.keys.ptr == NULL);
  }
  free(mem);

  /* The master key: a path with no child */
  const uint8_t master[] = {HEADER(0x02), 0x01, 0x00};
  CHECK(decode(master, sizeof(master), &mem, &r) == BIP377_OK);
  if (mem) {
    CHECK(r->body.get_keys.keys.len == 1);
    CHECK(r->body.get_keys.keys.ptr[0].len == 0);
  }
  free(mem);

  /* Register: alias "a", PRESENCE 0x02 */
  const uint8_t bad_presence[] = {HEADER(0x03), 0x01, 'a', 0x02};
  CHECK(measure(bad_presence, sizeof(bad_presence)) ==
        BIP377_ERR_INVALID_PRESENCE);

  /* Signing: no descriptor, empty PSBT, WANT_KIND 0x09, not trimmed */
  const uint8_t unknown_want[] = {HEADER(0x05), 0x00, 0x00, 0x01, 0x09, 0x00};
  CHECK(decode(unknown_want, sizeof(unknown_want), &mem, &r) == BIP377_OK);
  if (mem) {
    CHECK(r->body.sign.want_kind == BIP377_ABSENT_KIND);
    CHECK(r->body.sign.descriptors.len == 0);
    CHECK(r->body.sign.psbt.ptr != NULL && r->body.sign.psbt.len == 0);
    CHECK(!r->body.sign.accept_trimmed);
  }
  free(mem);
  const uint8_t absent_want[] = {HEADER(0x05), 0x00, 0x00, 0x00, 0x01};
  CHECK(decode(absent_want, sizeof(absent_want), &mem, &r) == BIP377_OK);
  if (mem) {
    CHECK(r->body.sign.want_kind == BIP377_ABSENT_KIND);
    CHECK(r->body.sign.accept_trimmed);
  }
  free(mem);

  /* Address Verification: alias "a", empty DERIV, no address, no descriptor,
   * a present but empty POR */
  const uint8_t empty_por[] = {HEADER(0x04), 0x01, 'a',  0x00,
                               0x00,         0x00, 0x01, 0x00};
  CHECK(decode(empty_por, sizeof(empty_por), &mem, &r) == BIP377_OK);
  if (mem) {
    const bip377_verify_address *req = &r->body.verify_address;
    CHECK(strcmp(req->descriptor_alias, "a") == 0);
    CHECK(req->address == NULL && req->descriptor == NULL);
    CHECK(req->proof.ptr != NULL && req->proof.len == 0);
  }
  free(mem);

  /* An alias of exactly 32 bytes is the longest one */
  uint8_t alias32[BIP377_HEADER_LEN + 1 + 32] = {HEADER(0x07), 32};
  memset(alias32 + BIP377_HEADER_LEN + 1, 'x', 32);
  CHECK(decode(alias32, sizeof(alias32), &mem, &r) == BIP377_OK);
  if (mem)
    CHECK(strlen(r->body.unregister_descriptor.descriptor_alias) == 32);
  free(mem);
}

static int alias_status(const uint8_t *alias, size_t len) {
  uint8_t msg[BIP377_HEADER_LEN + 1 + 8] = {HEADER(0x07), (uint8_t)len};
  memcpy(msg + BIP377_HEADER_LEN + 1, alias, len);
  return measure(msg, BIP377_HEADER_LEN + 1 + len);
}

static void test_strings(void) {
  current_name = "strings";
  CHECK(alias_status((const uint8_t *)"", 0) == BIP377_OK);
  CHECK(alias_status((const uint8_t *)"caf\xc3\xa9", 5) == BIP377_OK);
  CHECK(alias_status((const uint8_t *)"\xe2\x82\xac", 3) == BIP377_OK);
  CHECK(alias_status((const uint8_t *)"\xf0\x9f\x94\x91", 4) == BIP377_OK);
  CHECK(alias_status((const uint8_t *)"a\0b", 3) == BIP377_ERR_STRING_NUL);
  /* a lone continuation byte, a truncated sequence, an invalid lead byte */
  CHECK(alias_status((const uint8_t *)"\x80", 1) == BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xc3", 1) == BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xff", 1) == BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xc3\x28", 2) ==
        BIP377_ERR_INVALID_UTF8);
  /* overlong forms of '/' and of NUL */
  CHECK(alias_status((const uint8_t *)"\xc0\xaf", 2) ==
        BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xe0\x80\xaf", 3) ==
        BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xc0\x80", 2) ==
        BIP377_ERR_INVALID_UTF8);
  /* a UTF-16 surrogate, a value past U+10FFFF */
  CHECK(alias_status((const uint8_t *)"\xed\xa0\x80", 3) ==
        BIP377_ERR_INVALID_UTF8);
  CHECK(alias_status((const uint8_t *)"\xf4\x90\x80\x80", 4) ==
        BIP377_ERR_INVALID_UTF8);
}

/* --- calling contract --- */

static void test_decode_contract(void) {
  current_name = "decode contract";
  const uint8_t msg[] = {HEADER(0x02), 0x01, 0x02, 0x80, 0x00, 0x00,
                         0x54,         0x80, 0x00, 0x00, 0x00};
  size_t needed = 0;
  const bip377_request *r = NULL;
  CHECK(bip377_request_decode(msg, sizeof(msg), NULL, 0, &needed, NULL) ==
        BIP377_OK);
  CHECK(needed >= sizeof(bip377_request));
  CHECK(bip377_request_decode(msg, sizeof(msg), NULL, 0, NULL, NULL) ==
        BIP377_OK);
  CHECK(bip377_request_decode(NULL, 0, NULL, 0, &needed, NULL) ==
        BIP377_ERR_NULL_POINTER);

  uint8_t *mem = malloc(needed + 1);
  CHECK(bip377_request_decode(msg, sizeof(msg), mem, needed, NULL, NULL) ==
        BIP377_ERR_NULL_POINTER);
  size_t reported = 0;
  CHECK(bip377_request_decode(msg, sizeof(msg), mem, needed - 1, &reported,
                              &r) == BIP377_ERR_BUFFER_TOO_SMALL);
  CHECK(reported == needed && r == NULL);
  CHECK(bip377_request_decode(msg, sizeof(msg), mem + 1, needed, NULL, &r) ==
        BIP377_ERR_BUFFER_MISALIGNED);
  CHECK(bip377_request_decode(msg, sizeof(msg), mem, needed, NULL, &r) ==
        BIP377_OK);
  CHECK((const void *)r == (const void *)mem);
  if (r) {
    CHECK(r->body.get_keys.keys.len == 1);
    CHECK(r->body.get_keys.keys.ptr[0].len == 2);
    CHECK(r->body.get_keys.keys.ptr[0].ptr[0] == 0x80000054u);
    CHECK(r->body.get_keys.keys.ptr[0].ptr[1] == 0x80000000u);
  }
  free(mem);
}

static void response_init(bip377_response *r, uint8_t type) {
  memset(r, 0, sizeof(*r));
  r->id[1] = 0x01;
  r->message_type = type;
}

static int encode_status(const bip377_response *r) {
  size_t written = 0;
  return bip377_response_encode(r, NULL, 0, &written);
}

static void test_encode_contract(void) {
  current_name = "encode contract";
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_ADDRESS_VERIFICATION);
  r.body.address_uri.uri = "bitcoin:bc1qxyz";
  size_t needed = 0;
  CHECK(bip377_response_encode(&r, NULL, 0, &needed) == BIP377_OK);
  CHECK(needed == BIP377_HEADER_LEN + 1 + strlen(r.body.address_uri.uri));
  CHECK(bip377_response_encode(NULL, NULL, 0, &needed) ==
        BIP377_ERR_NULL_POINTER);
  CHECK(bip377_response_encode(&r, NULL, 0, NULL) == BIP377_ERR_NULL_POINTER);

  /* Exactly sized, so a write past the end is caught */
  uint8_t *out = malloc(needed);
  size_t written = 0;
  CHECK(bip377_response_encode(&r, out, needed - 1, &written) ==
        BIP377_ERR_BUFFER_TOO_SMALL);
  CHECK(written == needed);
  CHECK(bip377_response_encode(&r, out, 0, &written) ==
        BIP377_ERR_BUFFER_TOO_SMALL);
  CHECK(bip377_response_encode(&r, out, needed, &written) == BIP377_OK);
  CHECK(written == needed && memcmp(out, BIP377_MAGIC, BIP377_MAGIC_LEN) == 0);
  CHECK(out[BIP377_MAGIC_LEN] == BIP377_VERSION);
  CHECK(out[BIP377_MAGIC_LEN + 1] == 0x84);
  free(out);

  /* A string of 253 bytes takes a three-byte LENGTH */
  char uri[254];
  memset(uri, 'a', 253);
  uri[253] = '\0';
  r.body.address_uri.uri = uri;
  out = malloc(BIP377_HEADER_LEN + 3 + 253);
  CHECK(bip377_response_encode(&r, out, BIP377_HEADER_LEN + 3 + 253,
                               &written) == BIP377_OK);
  CHECK(written == BIP377_HEADER_LEN + 3 + 253);
  CHECK(out[BIP377_HEADER_LEN] == 0xfd && out[BIP377_HEADER_LEN + 1] == 0xfd &&
        out[BIP377_HEADER_LEN + 2] == 0x00);
  free(out);
}

/* --- what the encoder refuses --- */

static void info_init(bip377_response *r) {
  response_init(r, BIP377_MESSAGE_GET_INFO);
  r->body.info.vendor = "v";
  r->body.info.model = "m";
  r->body.info.state = BIP377_STATE_READY;
  r->body.info.networks = BIP377_NETWORK_MAINNET;
  r->body.info.max_alias = 32;
  r->body.info.has_fingerprint = 1;
}

static void test_encode_refusals(void) {
  current_name = "encode refusals";
  bip377_response r;

  info_init(&r);
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.info.max_alias = 33;
  CHECK(encode_status(&r) == BIP377_ERR_MAX_ALIAS_TOO_LARGE);

  info_init(&r);
  r.body.info.state = BIP377_STATE_LOCKED;
  CHECK(encode_status(&r) == BIP377_ERR_FINGERPRINT_WHEN_NOT_READY);
  r.body.info.has_fingerprint = 0;
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.info.state = 0x7f; /* a state a later version defines */
  CHECK(encode_status(&r) == BIP377_OK);

  info_init(&r);
  r.body.info.version.number = 1;
  CHECK(encode_status(&r) == BIP377_ERR_NUMBERED_STABLE_RELEASE);
  r.body.info.version.channel = BIP377_RELEASE_CANDIDATE;
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.info.version.channel = 0x09; /* a channel a later version defines */
  CHECK(encode_status(&r) == BIP377_OK);

  info_init(&r);
  r.body.info.capabilities = 1u << 8;
  CHECK(encode_status(&r) == BIP377_ERR_RESERVED_CAPABILITY_BITS);
  r.body.info.capabilities = 1u << 31;
  CHECK(encode_status(&r) == BIP377_ERR_RESERVED_CAPABILITY_BITS);
  r.body.info.capabilities = 0xff;
  CHECK(encode_status(&r) == BIP377_OK);

  info_init(&r);
  r.body.info.networks = 0x01;
  CHECK(encode_status(&r) == BIP377_ERR_RESERVED_NETWORK_BITS);
  r.body.info.networks = 0x20;
  CHECK(encode_status(&r) == BIP377_ERR_RESERVED_NETWORK_BITS);

  info_init(&r);
  r.body.info.vendor = NULL;
  CHECK(encode_status(&r) == BIP377_ERR_NULL_POINTER);
  r.body.info.vendor = "\xff";
  CHECK(encode_status(&r) == BIP377_ERR_INVALID_UTF8);

  /* Keys shares the version and capability checks */
  response_init(&r, BIP377_MESSAGE_GET_KEYS);
  r.body.keys.vendor = "v";
  r.body.keys.model = "m";
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.keys.capabilities = 1u << 8;
  CHECK(encode_status(&r) == BIP377_ERR_RESERVED_CAPABILITY_BITS);
  r.body.keys.capabilities = 0;
  r.body.keys.keys.len = 1;
  CHECK(encode_status(&r) == BIP377_ERR_NULL_POINTER);

  response_init(&r, BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  r.body.registration.descriptor_alias = "123456789012345678901234567890123";
  r.body.registration.stored = BIP377_ABSENT_BOOL;
  CHECK(encode_status(&r) == BIP377_ERR_STRING_TOO_LONG);
  r.body.registration.descriptor_alias = "12345678901234567890123456789012";
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.registration.stored = 2;
  CHECK(encode_status(&r) == BIP377_ERR_INVALID_BOOL);

  response_init(&r, BIP377_MESSAGE_UNREGISTER_DESCRIPTOR);
  r.body.unregistered.descriptor_alias = "123456789012345678901234567890123";
  CHECK(encode_status(&r) == BIP377_ERR_STRING_TOO_LONG);

  /* Message types */
  response_init(&r, 0x06);
  r.is_error = true;
  r.body.error.error = BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION;
  r.body.error.message = "x";
  CHECK(encode_status(&r) == BIP377_ERR_UNKNOWN_MESSAGE_TYPE);
  r.message_type = 0x08;
  CHECK(encode_status(&r) == BIP377_ERR_UNKNOWN_MESSAGE_TYPE);
  r.message_type = BIP377_MESSAGE_SIGNING;
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.error.error = 0x00;
  CHECK(encode_status(&r) == BIP377_ERR_ERROR_CODE_OUT_OF_RANGE);
  r.body.error.error = 0xfe;
  CHECK(encode_status(&r) == BIP377_OK);
  r.body.error.message = NULL;
  CHECK(encode_status(&r) == BIP377_ERR_NULL_POINTER);

  /* The reply to an unreadable request: an error, id 0x0000, ERROR 0x03 */
  memset(&r, 0, sizeof(r));
  r.message_type = BIP377_MESSAGE_UNREADABLE_REQUEST;
  r.body.error.error = BIP377_RESPONSE_ERROR_MALFORMED_REQUEST;
  r.body.error.message = "x";
  CHECK(encode_status(&r) == BIP377_ERR_UNREADABLE_REQUEST_TYPE);
  r.is_error = true;
  CHECK(encode_status(&r) == BIP377_OK);
  r.id[1] = 0x01;
  CHECK(encode_status(&r) == BIP377_ERR_UNREADABLE_REQUEST_ID);
  r.id[1] = 0x00;
  r.body.error.error = BIP377_RESPONSE_ERROR_INTERNAL;
  CHECK(encode_status(&r) == BIP377_ERR_UNREADABLE_REQUEST_ERROR);

  response_init(&r, BIP377_MESSAGE_SIGNING);
  r.body.signed_body.kind = 0x00;
  CHECK(encode_status(&r) == BIP377_ERR_UNKNOWN_SIGN_RESPONSE_KIND);
  r.body.signed_body.kind = 0x03;
  CHECK(encode_status(&r) == BIP377_ERR_UNKNOWN_SIGN_RESPONSE_KIND);
  r.body.signed_body.kind = BIP377_SIGN_RESPONSE_PSBT;
  r.body.signed_body.value.psbt.len = 4;
  CHECK(encode_status(&r) == BIP377_ERR_NULL_POINTER);
}

static uint8_t signature_bytes[80];

static int signatures_status(const bip377_signature *list, size_t len) {
  bip377_response r;
  response_init(&r, BIP377_MESSAGE_SIGNING);
  r.body.signed_body.kind = BIP377_SIGN_RESPONSE_SIGNATURES;
  r.body.signed_body.value.signatures.ptr = list;
  r.body.signed_body.value.signatures.len = len;
  return encode_status(&r);
}

static bip377_signature sp_entry(uint8_t kind, uint32_t input, uint8_t global,
                                 uint8_t scan) {
  bip377_signature s;
  memset(&s, 0, sizeof(s));
  s.kind = kind;
  s.input_index = input;
  /* both arms begin with `global` then `scan_key` */
  s.value.sp_ecdh_share.global = global;
  memset(s.value.sp_ecdh_share.scan_key, scan, BIP377_PUBLIC_KEY_LEN);
  return s;
}

#define SHARE BIP377_SIGNATURE_SP_ECDH_SHARE
#define PROOF BIP377_SIGNATURE_SP_DLEQ_PROOF

static void test_signature_refusals(void) {
  current_name = "signature refusals";
  bip377_signature s;

  CHECK(signatures_status(NULL, 0) == BIP377_OK);
  CHECK(signatures_status(NULL, 1) == BIP377_ERR_NULL_POINTER);

  memset(&s, 0, sizeof(s));
  CHECK(signatures_status(&s, 1) == BIP377_ERR_DEFINED_SIGNATURE_KIND);

  s.kind = BIP377_SIGNATURE_ECDSA;
  s.value.ecdsa.signature.ptr = signature_bytes;
  s.value.ecdsa.signature.len = 73;
  CHECK(signatures_status(&s, 1) == BIP377_OK);
  s.value.ecdsa.signature.len = 74;
  CHECK(signatures_status(&s, 1) == BIP377_ERR_ECDSA_SIGNATURE_LENGTH);

  static const size_t taproot_lengths[] = {0, 63, 64, 65, 66};
  for (size_t i = 0; i < 5; i++) {
    size_t len = taproot_lengths[i];
    int want = len == 64 || len == 65 ? BIP377_OK
                                      : BIP377_ERR_TAPROOT_SIGNATURE_LENGTH;
    memset(&s, 0, sizeof(s));
    s.kind = BIP377_SIGNATURE_TAP_KEY;
    s.value.tap_key.signature.ptr = signature_bytes;
    s.value.tap_key.signature.len = len;
    CHECK(signatures_status(&s, 1) == want);
    memset(&s, 0, sizeof(s));
    s.kind = BIP377_SIGNATURE_TAP_SCRIPT;
    s.value.tap_script.signature.ptr = signature_bytes;
    s.value.tap_script.signature.len = len;
    CHECK(signatures_status(&s, 1) == want);
  }

  memset(&s, 0, sizeof(s));
  s.kind = BIP377_SIGNATURE_MUSIG_PUB_NONCE;
  s.value.musig_pub_nonce.has_leaf_hash = 2;
  CHECK(signatures_status(&s, 1) == BIP377_ERR_INVALID_BOOL);
  s.kind = BIP377_SIGNATURE_MUSIG_PARTIAL_SIG;
  s.value.musig_partial_sig.has_leaf_hash = 2;
  CHECK(signatures_status(&s, 1) == BIP377_ERR_INVALID_BOOL);

  memset(&s, 0, sizeof(s));
  s.kind = 0x08;
  s.value.opaque.len = 4;
  CHECK(signatures_status(&s, 1) == BIP377_ERR_NULL_POINTER);

  /* Each scope and scan key carries exactly one share and one proof */
  bip377_signature list[4];
  list[0] = sp_entry(SHARE, 0, 1, 0xaa);
  list[1] = sp_entry(PROOF, 0, 1, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_OK);
  CHECK(signatures_status(list, 1) == BIP377_ERR_MISSING_SP_PROOF);
  CHECK(signatures_status(list + 1, 1) == BIP377_ERR_MISSING_SP_SHARE);

  list[2] = sp_entry(SHARE, 0, 1, 0xaa);
  CHECK(signatures_status(list, 3) == BIP377_ERR_DUPLICATE_SP_SHARE);
  list[2] = sp_entry(PROOF, 0, 1, 0xaa);
  CHECK(signatures_status(list, 3) == BIP377_ERR_DUPLICATE_SP_PROOF);

  /* Another scan key, another input or the other scope is another pair */
  list[1] = sp_entry(PROOF, 0, 1, 0xbb);
  CHECK(signatures_status(list, 2) == BIP377_ERR_MISSING_SP_PROOF);
  list[0] = sp_entry(SHARE, 1, 0, 0xaa);
  list[1] = sp_entry(PROOF, 2, 0, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_ERR_MISSING_SP_PROOF);
  list[1] = sp_entry(PROOF, 0, 1, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_ERR_MISSING_SP_PROOF);
  list[1] = sp_entry(PROOF, 1, 0, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_OK);
  list[2] = sp_entry(SHARE, 2, 0, 0xaa);
  list[3] = sp_entry(PROOF, 2, 0, 0xaa);
  CHECK(signatures_status(list, 4) == BIP377_OK);

  list[0] = sp_entry(SHARE, 1, 1, 0xaa);
  list[1] = sp_entry(PROOF, 1, 1, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_ERR_GLOBAL_INPUT_INDEX);
  list[0] = sp_entry(SHARE, 0, 2, 0xaa);
  list[1] = sp_entry(PROOF, 0, 2, 0xaa);
  CHECK(signatures_status(list, 2) == BIP377_ERR_INVALID_BOOL);
}

/* --- mutations --- */

static size_t mutations;

/* Decodes a copy of `msg` held in a block of exactly `len` bytes. Whatever the
 * outcome, the header reader and the decoder must agree on what is readable,
 * and a message that measures must fill a block of the measured size. */
static void decode_mutation(const uint8_t *msg, size_t len) {
  uint8_t *copy = malloc(len ? len : 1);
  memcpy(copy, msg, len);
  mutations++;

  bip377_header header;
  bool readable = bip377_request_header(copy, len, &header);
  size_t needed = 0;
  int status = bip377_request_decode(copy, len, NULL, 0, &needed, NULL);
  if (!readable) {
    CHECK(status != BIP377_OK);
    CHECK(header.message_type == BIP377_MESSAGE_UNREADABLE_REQUEST);
  }
  if (status == BIP377_OK) {
    CHECK(readable);
    void *mem = malloc(needed);
    const bip377_request *r = NULL;
    size_t needed_again = 0;
    CHECK(bip377_request_decode(copy, len, mem, needed, &needed_again, &r) ==
          BIP377_OK);
    CHECK(needed_again == needed);
    /* The tree does not point into the message */
    memset(copy, 0xee, len);
    if (r) {
      CHECK(r->message_type == header.message_type);
      CHECK(memcmp(r->id, header.id, sizeof(header.id)) == 0);
    }
    free(mem);
  }
  free(copy);
}

static void test_mutations(const char *dir) {
  static const uint8_t flips[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                  0x20, 0x40, 0x80, 0xff};
  for (size_t f = 0; f < VECTOR_FILE_COUNT; f++) {
    vector_t vectors[MAX_VECTORS];
    int count = vectors_load(dir, VECTOR_FILES[f], vectors, MAX_VECTORS);
    CHECK(count > 0);
    for (int i = 0; i < count; i++) {
      const vector_t *v = &vectors[i];
      if (!v->is_request || v->decode_error)
        continue;
      current_name = v->name;
      CHECK(measure(v->bytes, v->len) == BIP377_OK);
      for (size_t len = 0; len < v->len; len++)
        decode_mutation(v->bytes, len);

      uint8_t *mutated = malloc(v->len);
      for (size_t pos = 0; pos < v->len; pos++) {
        for (size_t k = 0; k < sizeof(flips); k++) {
          memcpy(mutated, v->bytes, v->len);
          mutated[pos] ^= flips[k];
          decode_mutation(mutated, v->len);
        }
        /* The byte as a LENGTH or COUNT of every width */
        static const uint8_t widths[] = {0xfd, 0xfe, 0xff};
        for (size_t k = 0; k < sizeof(widths); k++) {
          memcpy(mutated, v->bytes, v->len);
          mutated[pos] = widths[k];
          decode_mutation(mutated, v->len);
        }
      }
      free(mutated);
    }
    if (count > 0)
      vectors_free(vectors, count);
  }
}

static void test_strerror(void) {
  current_name = "strerror";
  for (int status = 0; status < 600; status++) {
    const char *text = bip377_strerror(status);
    CHECK(text != NULL && text[0] != '\0');
  }
  CHECK(strcmp(bip377_strerror(BIP377_OK), "ok") == 0);
  CHECK(strcmp(bip377_strerror(BIP377_ERR_TRUNCATED), "unknown error") != 0);
  CHECK(strcmp(bip377_strerror(-1), "unknown error") == 0);
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "test/vectors";
  test_decode_rules();
  test_strings();
  test_decode_contract();
  test_encode_contract();
  test_encode_refusals();
  test_signature_refusals();
  test_mutations(dir);
  test_strerror();

  printf("bip377 api: %zu mutated requests decoded without a fault\n",
         mutations);
  if (failures) {
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  return 0;
}
