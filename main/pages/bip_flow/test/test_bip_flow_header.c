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

/* BIP-377's get_keys_request_one_path vector: version 1, Get Keys,
 * request id 0x0001 */
static const uint8_t GET_KEYS_REQUEST[] = {
    0x42, 0x49, 0x50, 0x33, 0x37, 0x37, 0x01, 0x02, 0x00, 0x01,
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

/* bip377 test vectors (efccc5b): unregister_descriptor_request and
 * unregister_descriptor_response for the alias "main", request id 0x0001 */
static const uint8_t UNREGISTER_REQUEST[] = {0x42, 0x49, 0x50, 0x33, 0x37,
                                             0x37, 0x01, 0x07, 0x00, 0x01,
                                             0x04, 0x6d, 0x61, 0x69, 0x6e};
static const uint8_t UNREGISTER_RESPONSE[] = {0x42, 0x49, 0x50, 0x33, 0x37,
                                              0x37, 0x01, 0x87, 0x00, 0x01,
                                              0x04, 0x6d, 0x61, 0x69, 0x6e};

static void test_unregister_request(void) {
  bip_flow_header_t header;
  const bip377_request *request = NULL;
  TEST("an Unregister Descriptor request header is read");
  if (bip_flow_read_request_header(UNREGISTER_REQUEST,
                                   sizeof(UNREGISTER_REQUEST), &header) &&
      header.version == 0x01 && header.message_type == 0x07 &&
      header.id[0] == 0x00 && header.id[1] == 0x01)
    PASS();
  else
    FAIL("header fields differ");

  TEST("an Unregister Descriptor request decodes to its alias");
  if (bip377_request_decode(UNREGISTER_REQUEST, sizeof(UNREGISTER_REQUEST),
                            &request, NULL) == BIP377_OK &&
      request->message_type == 0x07 && request->id[0] == 0x00 &&
      request->id[1] == 0x01 &&
      strcmp(request->body.unregister_descriptor.descriptor_alias, "main") == 0)
    PASS();
  else
    FAIL("request differs");
  bip377_request_free(request);
}

/* A request whose header reads but whose body does not decode, as
 * bip_flow_start answers it */
static void expect_malformed(const char *name, const uint8_t *message,
                             size_t len) {
  bip_flow_header_t header;
  const bip377_request *request = NULL;
  TEST(name);
  int32_t status = bip_flow_read_request_header(message, len, &header)
                       ? bip377_request_decode(message, len, &request, NULL)
                       : BIP377_OK;
  if (status != BIP377_OK && !request &&
      bip_flow_decode_error(&header, status) == 0x03)
    PASS();
  else
    FAIL("not answered with malformed request");
  bip377_request_free(request);
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
  bip377_response response;
  bip377_buf encoded = {0};
  memset(&response, 0, sizeof(response));
  response.id[1] = 0x01;
  response.message_type = BIP377_MESSAGE_UNREGISTER_DESCRIPTOR;
  response.body.unregistered.descriptor_alias = "main";
  TEST("the Unregister Descriptor ok response echoes the alias");
  if (bip377_response_encode(&response, &encoded, NULL) == BIP377_OK &&
      encoded.len == sizeof(UNREGISTER_RESPONSE) &&
      memcmp(encoded.ptr, UNREGISTER_RESPONSE, encoded.len) == 0)
    PASS();
  else
    FAIL("encoding differs from the vector");
  bip377_buf_free(encoded);
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
                      BIP377_ERR_TRUNCATED, 0x02);
  expect_decode_error("version 1 answers malformed request", 0x01,
                      BIP377_ERR_TRUNCATED, 0x03);
  expect_decode_error("a newer version answers malformed request", 0x02,
                      BIP377_ERR_TRUNCATED, 0x03);
  expect_decode_error("an unknown FORM answers unsupported descriptor form",
                      0x01, BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM, 0x06);
  expect_decode_error("an unknown FORM of version 0 answers unsupported "
                      "protocol version",
                      0x00, BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM, 0x02);
}

int main(void) {
  printf("BIP flow request header tests\n");
  printf("=============================\n\n");

  test_read_header();
  test_decode_error();
  test_unregister_request();
  test_unregister_malformed();
  test_unregister_response();

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
