#include "../bip_flow.h"

#include <stdio.h>

static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* ENCODING.md's get_keys_request_one_path vector: version 1, Get Keys,
 * request id 0x0001 */
static const uint8_t GET_KEYS_REQUEST[] = {
    0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x02, 0x00, 0x01,
    0x01, 0x04, 0x80, 0x00, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x02, 0x00};

static void expect_rejected(const char *name, size_t offset, uint8_t value,
                            size_t len) {
  uint8_t message[sizeof(GET_KEYS_REQUEST)];
  bip_flow_header_t header;
  memcpy(message, GET_KEYS_REQUEST, sizeof(message));
  message[offset] = value;
  TEST(name);
  if (bip_flow_read_request_header(message, len, &header))
    FAIL("header accepted");
  else if (header.message_type != 0x00 || header.id[0] != 0x00 ||
           header.id[1] != 0x00)
    FAIL("reply header is not TYPE 0x00 and REQUEST_ID 0x0000");
  else
    PASS();
}

static void test_read_header(void) {
  bip_flow_header_t header;
  TEST("a Get Keys request header is read");
  if (bip_flow_read_request_header(GET_KEYS_REQUEST, sizeof(GET_KEYS_REQUEST),
                                   &header) &&
      header.version == 0x01 && header.message_type == 0x02 &&
      header.id[0] == 0x00 && header.id[1] == 0x01)
    PASS();
  else
    FAIL("header fields differ");

  uint8_t response[sizeof(GET_KEYS_REQUEST)];
  memcpy(response, GET_KEYS_REQUEST, sizeof(response));
  response[7] = 0x82;
  TEST("a response header is read with TYPE 0x02 and id 0x0001");
  if (bip_flow_read_request_header(response, sizeof(response), &header) &&
      header.message_type == 0x02 && header.id[0] == 0x00 &&
      header.id[1] == 0x01)
    PASS();
  else
    FAIL("header fields differ");

  expect_rejected("a bad MAGIC is not a request", 3, 0x31,
                  sizeof(GET_KEYS_REQUEST));
  expect_rejected("the error status is not a request", 7, 0x42,
                  sizeof(GET_KEYS_REQUEST));
  expect_rejected("the reserved type 0x00 is not a request", 7, 0x00,
                  sizeof(GET_KEYS_REQUEST));
  expect_rejected("the unknown type 0x08 is not a request", 7, 0x08,
                  sizeof(GET_KEYS_REQUEST));
  expect_rejected("a message without its request id is not a request", 7, 0x02,
                  9);
}

/* bipqr test vectors (efccc5b): unregister_descriptor_request and
 * unregister_descriptor_response for the alias "main", request id 0x0001 */
static const uint8_t UNREGISTER_REQUEST[] = {0x42, 0x49, 0x50, 0x58, 0x58,
                                             0x58, 0x01, 0x07, 0x00, 0x01,
                                             0x04, 0x6d, 0x61, 0x69, 0x6e};
static const uint8_t UNREGISTER_RESPONSE[] = {0x42, 0x49, 0x50, 0x58, 0x58,
                                              0x58, 0x01, 0x87, 0x00, 0x01,
                                              0x04, 0x6d, 0x61, 0x69, 0x6e};

static void test_unregister_request(void) {
  bip_flow_header_t header;
  const bipqr_request *request = NULL;
  TEST("an Unregister Descriptor request header is read");
  if (bip_flow_read_request_header(UNREGISTER_REQUEST,
                                   sizeof(UNREGISTER_REQUEST), &header) &&
      header.version == 0x01 && header.message_type == 0x07 &&
      header.id[0] == 0x00 && header.id[1] == 0x01)
    PASS();
  else
    FAIL("header fields differ");

  TEST("an Unregister Descriptor request decodes to its alias");
  if (bipqr_request_decode(UNREGISTER_REQUEST, sizeof(UNREGISTER_REQUEST),
                           &request, NULL) == BIPQR_OK &&
      request->message_type == 0x07 && request->id[0] == 0x00 &&
      request->id[1] == 0x01 &&
      strcmp(request->body.unregister_descriptor.descriptor_alias, "main") == 0)
    PASS();
  else
    FAIL("request differs");
  bipqr_request_free(request);
}

/* A request whose header reads but whose body does not decode, as
 * bip_flow_start answers it */
static void expect_malformed(const char *name, const uint8_t *message,
                             size_t len) {
  bip_flow_header_t header;
  const bipqr_request *request = NULL;
  TEST(name);
  int32_t status = bip_flow_read_request_header(message, len, &header)
                       ? bipqr_request_decode(message, len, &request, NULL)
                       : BIPQR_OK;
  if (status != BIPQR_OK && !request &&
      bip_flow_decode_error(&header, status) == 0x03)
    PASS();
  else
    FAIL("not answered with malformed request");
  bipqr_request_free(request);
}

static void test_unregister_malformed(void) {
  uint8_t long_alias[BIP_FLOW_HEADER_LEN + 1 + 33];
  memcpy(long_alias, UNREGISTER_REQUEST, BIP_FLOW_HEADER_LEN);
  long_alias[BIP_FLOW_HEADER_LEN] = 33;
  memset(long_alias + BIP_FLOW_HEADER_LEN + 1, 'a', 33);
  expect_malformed("an Unregister Descriptor request without its alias "
                   "answers malformed request",
                   UNREGISTER_REQUEST, BIP_FLOW_HEADER_LEN);
  expect_malformed("an Unregister Descriptor request with a 33-byte alias "
                   "answers malformed request",
                   long_alias, sizeof(long_alias));
}

static void test_unregister_response(void) {
  bipqr_response response;
  bipqr_buf encoded = {0};
  memset(&response, 0, sizeof(response));
  response.id[1] = 0x01;
  response.message_type = BIPQR_MESSAGE_UNREGISTER_DESCRIPTOR;
  response.body.unregistered.descriptor_alias = "main";
  TEST("the Unregister Descriptor ok response echoes the alias");
  if (bipqr_response_encode(&response, &encoded, NULL) == BIPQR_OK &&
      encoded.len == sizeof(UNREGISTER_RESPONSE) &&
      memcmp(encoded.ptr, UNREGISTER_RESPONSE, encoded.len) == 0)
    PASS();
  else
    FAIL("encoding differs from the vector");
  bipqr_buf_free(encoded);
}

static void expect_decode_error(const char *name, uint8_t version,
                                int32_t status, uint8_t expected) {
  bip_flow_header_t header = {.version = version};
  TEST(name);
  if (bip_flow_decode_error(&header, status) == expected)
    PASS();
  else
    FAIL("unexpected error code");
}

static void test_decode_error(void) {
  expect_decode_error("version 0 answers unsupported protocol version", 0x00,
                      BIPQR_ERR_TRUNCATED, 0x02);
  expect_decode_error("version 1 answers malformed request", 0x01,
                      BIPQR_ERR_TRUNCATED, 0x03);
  expect_decode_error("a newer version answers malformed request", 0x02,
                      BIPQR_ERR_TRUNCATED, 0x03);
  expect_decode_error("an unknown FORM answers unsupported descriptor form",
                      0x01, BIPQR_ERR_UNKNOWN_DESCRIPTOR_FORM, 0x06);
  expect_decode_error("an unknown FORM of version 0 answers unsupported "
                      "protocol version",
                      0x00, BIPQR_ERR_UNKNOWN_DESCRIPTOR_FORM, 0x02);
}

/* bipqr test vectors (d7363e0) of requests carrying a descriptor body */
static const uint8_t REGISTER_BIP380_REQUEST[] = {
    0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x03, 0x00, 0x01, 0x04,
    0x6d, 0x61, 0x69, 0x6e, 0x01, 0x01, 0x22, 0x77, 0x70, 0x6b, 0x68,
    0x28, 0x5b, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2f,
    0x38, 0x34, 0x68, 0x2f, 0x31, 0x68, 0x2f, 0x30, 0x68, 0x5d, 0x78,
    0x70, 0x75, 0x62, 0x2f, 0x30, 0x2f, 0x2a, 0x29};
static const uint8_t REGISTER_SP_KEYS_REQUEST[] = {
    0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x03, 0x00, 0x01, 0x04,
    0x6d, 0x61, 0x69, 0x6e, 0x01, 0x03, 0x73, 0xc5, 0xda, 0x0a, 0x05,
    0x80, 0x00, 0x01, 0x60, 0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05,
    0x80, 0x00, 0x01, 0x60, 0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t VERIFY_SP_KEYS_REQUEST[] = {
    0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x04, 0x00, 0x01, 0x04,
    0x6d, 0x61, 0x69, 0x6e, 0x00, 0x01, 0x07, 0x73, 0x70, 0x31, 0x71,
    0x78, 0x79, 0x7a, 0x01, 0x03, 0x73, 0xc5, 0xda, 0x0a, 0x05, 0x80,
    0x00, 0x01, 0x60, 0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x80,
    0x00, 0x01, 0x60, 0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t NONCE_PREPARATION_REQUEST[] = {
    0x42, 0x49, 0x50, 0x58, 0x58, 0x58, 0x01, 0x06, 0x00, 0x01, 0x01,
    0x51, 0x51, 0x51, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05,
    0x80, 0x00, 0x00, 0x56, 0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01};

/* A Register Descriptor request for the alias "main" with a FORM 0x01
 * descriptor, laid out as REGISTER_BIP380_REQUEST */
static size_t register_bip380_request(const char *descriptor, uint8_t *out) {
  size_t len = strlen(descriptor);
  memcpy(out, REGISTER_BIP380_REQUEST, 17);
  out[17] = (uint8_t)len;
  memcpy(out + 18, descriptor, len);
  return 18 + len;
}

/* A Register Descriptor request for the alias "main" with a FORM 0x02 wallet
 * policy of two keys */
static size_t register_bip388_request(const char *key0, const char *key1,
                                      const char *policy, uint8_t *out) {
  const char *strings[] = {key0, key1, policy};
  size_t off = 16;
  memcpy(out, REGISTER_BIP380_REQUEST, off);
  out[off++] = 0x02;
  out[off++] = 2;
  for (size_t i = 0; i < 3; i++) {
    size_t len = strlen(strings[i]);
    out[off++] = (uint8_t)len;
    memcpy(out + off, strings[i], len);
    off += len;
  }
  return off;
}

static void expect_unsupported(const char *name, const uint8_t *message,
                               size_t len, uint8_t expected) {
  const bipqr_request *request = NULL;
  TEST(name);
  if (bipqr_request_decode(message, len, &request, NULL) != BIPQR_OK)
    FAIL("request does not decode");
  else if (bip_flow_unsupported_error(request) != expected)
    FAIL("unexpected error code");
  else
    PASS();
  bipqr_request_free(request);
}

static void test_unsupported_requests(void) {
  uint8_t message[160];
  expect_unsupported("a FORM 0x01 descriptor is taken", REGISTER_BIP380_REQUEST,
                     sizeof(REGISTER_BIP380_REQUEST), 0x00);
  expect_unsupported("FORM 0x03 silent payment keys are taken to register",
                     REGISTER_SP_KEYS_REQUEST, sizeof(REGISTER_SP_KEYS_REQUEST),
                     0x00);
  expect_unsupported("FORM 0x03 silent payment keys are taken to verify an "
                     "address",
                     VERIFY_SP_KEYS_REQUEST, sizeof(VERIFY_SP_KEYS_REQUEST),
                     0x00);
  expect_unsupported("Nonce Preparation answers unsupported operation",
                     NONCE_PREPARATION_REQUEST,
                     sizeof(NONCE_PREPARATION_REQUEST), 0x0F);
  expect_unsupported(
      "a musig() key in a FORM 0x01 descriptor is taken", message,
      register_bip380_request("tr(musig([00000000/86h/1h/0h]xpub,"
                              "[11111111/86h/1h/0h]xpub)/<0;1>/*)",
                              message),
      0x00);
  expect_unsupported("a musig() key in a FORM 0x02 wallet policy is taken",
                     message,
                     register_bip388_request("[00000000/86h/1h/0h]xpub",
                                             "[11111111/86h/1h/0h]xpub",
                                             "tr(musig(@0,@1)/**)", message),
                     0x00);
  expect_unsupported(
      "a FORM 0x02 wallet policy without musig() is taken", message,
      register_bip388_request("[00000000/48h/1h/0h/2h]xpub",
                              "[11111111/48h/1h/0h/2h]xpub",
                              "wsh(sortedmulti(2,@0/**,@1/**))", message),
      0x00);
}

int main(void) {
  printf("BIP flow request header tests\n");
  printf("=============================\n\n");

  test_read_header();
  test_decode_error();
  test_unregister_request();
  test_unregister_malformed();
  test_unregister_response();
  test_unsupported_requests();

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
