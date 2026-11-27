/* The four requests Liana sends an air-gapped signer, built as its coordinator
 * builds them from its test wallet (liana-gui/test_assets/airgap), through
 * the codec and the wallet policy expansion. */

#include "../bip388.h"
#include <bip377.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

#define KEY_0                                                                  \
  "[9f141cf0/48'/1'/0'/2']tpubDFnReAwXvYd6RA46X55HuFpmvZsLanDrwHAUsdYEGEpNGTR" \
  "nCdbDRXJGLTwDeqKURCPZUDgdkuuu9dYkuBNQHmSNBUu7V2CdLKwpJjx2JuC"
#define KEY_1                                                                  \
  "[daba2d5f/48'/1'/0'/2']tpubDDwKEc4i4k8rBgVLGxytHrP13VVYucUGmL2cadux7AfMwMn" \
  "RHKcw1YZKt9SMB4fWut7ZAiZqPefzm3BBCNXLZMxDrWJ4Q6VA1AFB6b8GzbT"
#define KEY_2                                                                  \
  "[141cfdf4/48'/1'/0'/2']tpubDEnYysximqdZkZnW5W9gYc7N3sxizKyqfdJfZ2qRfwNvSv6" \
  "E11yDgyLTAnWQqDmVJ7oQ3h3ui59RQm1qmGxMm4jinq5wvSzyueKgrLJj5Cy"

/* The policy keeps the multipath suffixes of the descriptor, two pairs of
 * them, where a BIP-388 template would write a double star */
static const char POLICY[] =
    "wsh(or_i(and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),"
    "a:pkh(@2/<0;1>/*)),older(52596)),and_v(v:pk(@0/<0;1>/*),"
    "pk(@1/<0;1>/*))))";

/* multisig-testnet.descriptor, without its checksum */
static const char DESCRIPTOR[] =
    "wsh(or_i(and_v(v:thresh(2,pkh(" KEY_0 "/<2;3>/*),a:pkh(" KEY_1
    "/<2;3>/*),a:pkh(" KEY_2 "/<0;1>/*)),older(52596)),and_v(v:pk(" KEY_0
    "/<0;1>/*),pk(" KEY_1 "/<0;1>/*))))";

/* The alias of a wallet registered from the installer */
static const char ALIAS[] = "Liana-u768v50p";
static const char ADDRESS[] =
    "tb1qxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzsxyz";

static uint8_t message[2048];
static size_t message_len;

static void put(const void *bytes, size_t len) {
  memcpy(message + message_len, bytes, len);
  message_len += len;
}

static void put_u8(uint8_t value) { put(&value, 1); }

static void put_u32(uint32_t value) {
  uint8_t be[4] = {(uint8_t)(value >> 24), (uint8_t)(value >> 16),
                   (uint8_t)(value >> 8), (uint8_t)value};
  put(be, sizeof(be));
}

/* Every string here is shorter than 253 bytes: a one-byte LENGTH */
static void put_string(const char *s) {
  put_u8((uint8_t)strlen(s));
  put(s, strlen(s));
}

static void begin(uint8_t type) {
  message_len = 0;
  put(BIP377_MAGIC, BIP377_MAGIC_LEN);
  put_u8(BIP377_VERSION);
  put_u8(type);
  put_u8(0x5a);
  put_u8(0xa5);
}

static void put_policy(void) {
  put_u8(BIP377_DESCRIPTOR_BIP388);
  put_u8(3);
  put_string(KEY_0);
  put_string(KEY_1);
  put_string(KEY_2);
  put_string(POLICY);
}

/* Decodes `message` as bip_flow_start does. The caller frees the block. */
static void *decode(const bip377_request **request) {
  size_t mem_len = 0;
  *request = NULL;
  if (bip377_request_decode(message, message_len, NULL, 0, &mem_len, NULL) !=
      BIP377_OK)
    return NULL;
  void *mem = malloc(mem_len);
  if (bip377_request_decode(message, message_len, mem, mem_len, NULL,
                            request) != BIP377_OK) {
    free(mem);
    return NULL;
  }
  return mem;
}

static bool id_is_echoed(const bip377_request *request) {
  return request->id[0] == 0x5a && request->id[1] == 0xa5;
}

static bool policy_is_the_descriptor(const bip377_descriptor_body *body) {
  if (!body || body->tag != BIP377_DESCRIPTOR_BIP388 ||
      body->value.bip388.keys.len != 3 ||
      strcmp(body->value.bip388.policy, POLICY) != 0)
    return false;
  char *descriptor = bip388_descriptor_alloc(body->value.bip388.policy,
                                             body->value.bip388.keys.ptr,
                                             body->value.bip388.keys.len);
  bool same = descriptor && strcmp(descriptor, DESCRIPTOR) == 0;
  free(descriptor);
  return same;
}

/* The ten account keys the installer asks for: m/48'/1'/account'/2' */
static void test_get_keys(void) {
  const bip377_request *request;
  begin(BIP377_MESSAGE_GET_KEYS);
  put_u8(10);
  for (uint32_t account = 0; account < 10; account++) {
    put_u8(4);
    put_u32(0x80000030);
    put_u32(0x80000001);
    put_u32(0x80000000 | account);
    put_u32(0x80000002);
  }

  TEST("the Get Keys request of the installer");
  void *mem = decode(&request);
  bool ok = mem && id_is_echoed(request) &&
            request->message_type == BIP377_MESSAGE_GET_KEYS &&
            request->body.get_keys.keys.len == 10;
  for (uint32_t account = 0; ok && account < 10; account++) {
    const bip377_path *path = &request->body.get_keys.keys.ptr[account];
    ok = path->len == 4 && path->ptr[0] == 0x80000030 &&
         path->ptr[1] == 0x80000001 && path->ptr[2] == (0x80000000 | account) &&
         path->ptr[3] == 0x80000002;
  }
  if (ok)
    PASS();
  else
    FAIL("paths differ");
  free(mem);
}

static void test_register(void) {
  const bip377_request *request;
  begin(BIP377_MESSAGE_REGISTER_DESCRIPTOR);
  put_string(ALIAS);
  put_u8(1);
  put_policy();

  TEST("a wallet policy registration expands to the wallet's descriptor");
  void *mem = decode(&request);
  if (mem && id_is_echoed(request) &&
      request->message_type == BIP377_MESSAGE_REGISTER_DESCRIPTOR &&
      strcmp(request->body.register_descriptor.descriptor_alias, ALIAS) == 0 &&
      policy_is_the_descriptor(request->body.register_descriptor.descriptor))
    PASS();
  else
    FAIL("request differs");
  free(mem);
}

/* Receive address 3: position 0 of each <a;b>, then the index. A signer that
 * stored the registration is named by alias alone. */
static void test_verify_address(void) {
  const bip377_request *request;
  begin(BIP377_MESSAGE_ADDRESS_VERIFICATION);
  put_string(ALIAS);
  put_u8(2);
  put_u32(0);
  put_u32(3);
  put_u8(1);
  put_string(ADDRESS);
  put_u8(0);
  put_u8(0);

  TEST("an address verification by alias");
  void *mem = decode(&request);
  const bip377_verify_address *req = mem ? &request->body.verify_address : NULL;
  if (req && id_is_echoed(request) &&
      strcmp(req->descriptor_alias, ALIAS) == 0 &&
      req->derivation_path.len == 2 && req->derivation_path.ptr[0] == 0 &&
      req->derivation_path.ptr[1] == 3 && req->address &&
      strcmp(req->address, ADDRESS) == 0 && !req->descriptor && !req->proof.ptr)
    PASS();
  else
    FAIL("request differs");
  free(mem);
}

/* One descriptor, signatures preferred, a trimmed PSBT accepted. A signer
 * that did not store the registration gets the wallet policy again. */
static void test_sign(bool stored) {
  static const uint8_t psbt[] = {0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00,
                                 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00};
  const bip377_request *request;
  begin(BIP377_MESSAGE_SIGNING);
  put_u8(1);
  put_string(ALIAS);
  put_u8(stored ? 0 : 1);
  if (!stored)
    put_policy();
  put_u8(0);
  put_u8(sizeof(psbt));
  put(psbt, sizeof(psbt));
  put_u8(1);
  put_u8(BIP377_SIGN_RESPONSE_SIGNATURES);
  put_u8(1);

  TEST(stored ? "a signing request by alias"
              : "a signing request carrying the wallet policy");
  void *mem = decode(&request);
  const bip377_sign *req = mem ? &request->body.sign : NULL;
  bool ok =
      req && id_is_echoed(request) && req->descriptors.len == 1 &&
      strcmp(req->descriptors.ptr[0].alias, ALIAS) == 0 &&
      !req->descriptors.ptr[0].proof.ptr && req->psbt.len == sizeof(psbt) &&
      memcmp(req->psbt.ptr, psbt, sizeof(psbt)) == 0 &&
      req->want_kind == BIP377_SIGN_RESPONSE_SIGNATURES && req->accept_trimmed;
  if (ok && stored)
    ok = req->descriptors.ptr[0].body == NULL;
  else if (ok)
    ok = policy_is_the_descriptor(req->descriptors.ptr[0].body);
  if (ok)
    PASS();
  else
    FAIL("request differs");
  free(mem);
}

int main(void) {
  printf("Liana request tests\n");
  printf("===================\n\n");

  test_get_keys();
  test_register();
  test_verify_address();
  test_sign(true);
  test_sign(false);

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
