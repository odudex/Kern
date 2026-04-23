#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pull in full implementations directly */
#include "../key.c"
#include "../ss_whitelist.c"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* BIP39 test mnemonic, empty passphrase, mainnet */
static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* Reference scriptPubKey (25 bytes, P2PKH m/44'/0'/0'/0/0) */
static const uint8_t REF_SPK_P2PKH[] = {
    0x76, 0xa9, 0x14, 0xd9, 0x86, 0xed, 0x01, 0xb7, 0xa2,
    0x22, 0x25, 0xa7, 0x0e, 0xdb, 0xf2, 0xba, 0x7c, 0xfb,
    0x63, 0xa1, 0x5c, 0xb3, 0xaa, 0x88, 0xac};
static const char REF_ADDR_P2PKH[] = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";

/* Reference scriptPubKey (23 bytes, P2SH-P2WPKH m/49'/0'/0'/0/0) */
static const uint8_t REF_SPK_P2SH_P2WPKH[] = {
    0xa9, 0x14, 0x3f, 0xb6, 0xe9, 0x58, 0x12, 0xe5, 0x7b, 0xb4, 0x69, 0x1f,
    0x9a, 0x4a, 0x62, 0x88, 0x62, 0xa6, 0x1a, 0x4f, 0x76, 0x9b, 0x87};
static const char REF_ADDR_P2SH_P2WPKH[] = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf";

/* Reference scriptPubKey (22 bytes, P2WPKH m/84'/0'/0'/0/0) */
static const uint8_t REF_SPK_P2WPKH[] = {
    0x00, 0x14, 0xc0, 0xce, 0xbc, 0xd6, 0xc3, 0xd3, 0xca, 0x8c, 0x75,
    0xdc, 0x5e, 0xc6, 0x2e, 0xbe, 0x55, 0x33, 0x0e, 0xf9, 0x10, 0xe2};
static const char REF_ADDR_P2WPKH[] =
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

/* Reference scriptPubKey (34 bytes, P2TR m/86'/0'/0'/0/0) */
static const uint8_t REF_SPK_P2TR[] = {
    0x51, 0x20, 0xa6, 0x08, 0x69, 0xf0, 0xdb, 0xcf, 0x1d, 0xc6, 0x59, 0xc9,
    0xce, 0xcb, 0xaf, 0x80, 0x50, 0x13, 0x5e, 0xa9, 0xe8, 0xcd, 0xc4, 0x87,
    0x05, 0x3f, 0x1d, 0xc6, 0x88, 0x09, 0x49, 0xdc, 0x68, 0x4c};
static const char REF_ADDR_P2TR[] =
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

static void test_scriptpubkey(const char *name, ss_script_type_t script,
                              const uint8_t *ref_spk, size_t ref_len) {
  TEST(name);
  uint8_t spk[34];
  size_t spk_len = 0;
  if (!ss_scriptpubkey(script, 0, 0, 0, false, spk, &spk_len)) {
    FAIL("ss_scriptpubkey returned false");
    return;
  }
  if (spk_len != ref_len) {
    FAIL("wrong scriptPubKey length");
    return;
  }
  if (memcmp(spk, ref_spk, ref_len) != 0) {
    FAIL("scriptPubKey bytes mismatch");
    return;
  }
  PASS();
}

static void test_address(const char *name, ss_script_type_t script,
                         const char *ref_addr) {
  TEST(name);
  char addr[SS_ADDRESS_MAX_LEN];
  if (!ss_address(script, 0, 0, 0, false, addr, sizeof(addr))) {
    FAIL("ss_address returned false");
    return;
  }
  if (strcmp(addr, ref_addr) != 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "got '%s'", addr);
    FAIL(msg);
    return;
  }
  PASS();
}

int main(void) {
  printf("=== ss_whitelist regen tests ===\n\n");

  printf("--- Setup: loading test mnemonic ---\n");
  {
    TEST("key_load_from_mnemonic");
    if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false)) {
      FAIL("failed to load mnemonic");
      printf("\n=== ABORT: key load failed ===\n");
      return 1;
    }
    PASS();
  }

  printf("\n--- Group 1: scriptPubKey regeneration (account=0 chain=0 index=0) "
         "---\n");
  test_scriptpubkey("P2PKH spk", SS_SCRIPT_P2PKH, REF_SPK_P2PKH,
                    sizeof(REF_SPK_P2PKH));
  test_scriptpubkey("P2SH-P2WPKH spk", SS_SCRIPT_P2SH_P2WPKH,
                    REF_SPK_P2SH_P2WPKH, sizeof(REF_SPK_P2SH_P2WPKH));
  test_scriptpubkey("P2WPKH spk", SS_SCRIPT_P2WPKH, REF_SPK_P2WPKH,
                    sizeof(REF_SPK_P2WPKH));
  test_scriptpubkey("P2TR spk", SS_SCRIPT_P2TR, REF_SPK_P2TR,
                    sizeof(REF_SPK_P2TR));

  printf("\n--- Group 2: address derivation (account=0 chain=0 index=0) ---\n");
  test_address("P2PKH address", SS_SCRIPT_P2PKH, REF_ADDR_P2PKH);
  test_address("P2SH-P2WPKH address", SS_SCRIPT_P2SH_P2WPKH,
               REF_ADDR_P2SH_P2WPKH);
  test_address("P2WPKH address", SS_SCRIPT_P2WPKH, REF_ADDR_P2WPKH);
  test_address("P2TR address", SS_SCRIPT_P2TR, REF_ADDR_P2TR);

  printf("\n--- Group 3: address buffer overflow ---\n");
  {
    char tiny[5];
    TEST("P2WPKH rejected into tiny buffer");
    if (ss_address(SS_SCRIPT_P2WPKH, 0, 0, 0, false, tiny, sizeof(tiny))) {
      FAIL("should reject when buffer is too small");
    } else {
      PASS();
    }
  }

  key_unload();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
