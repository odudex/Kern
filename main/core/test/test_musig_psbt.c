/*
 * MuSig2 PSBT tests (core/musig_psbt.c).
 *
 * Runs against the real key, wallet and registry modules with the BIP39 test
 * mnemonic loaded on testnet. Our participant is the account 86'/1'/0'; the
 * cosigner is the account 86'/1'/1' of the same seed, given another
 * fingerprint so the registry takes it for a foreign key.
 */

#include "core/key.h"
#include "core/musig_psbt.h"
#include "core/psbt_internal.h"
#include "core/registry.h"
#include "core/storage.h"
#include "core/wallet.h"
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_script.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- storage stubs (registry persistence is never reached) ----------
 */

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  storage_descriptor_format_t format) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)format;
  return ESP_OK;
}

esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  (void)loc;
  (void)filename;
  return ESP_OK;
}

esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  (void)loc;
  *filenames_out = NULL;
  *count_out = 0;
  return ESP_OK;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  storage_descriptor_format_t *format_out) {
  (void)loc;
  (void)filename;
  *data_out = NULL;
  *len_out = 0;
  *format_out = STORAGE_DESCRIPTOR_TXT;
  return -1;
}

void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

/* ---------- fixtures ---------- */

static const char *TEST_MNEMONIC = "abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon "
                                   "abandon about";
#define FP "73c5da0a"
#define OURS "m/86'/1'/0'"
#define COSIGNER "m/86'/1'/1'"

/* musig() of the account keys, derived after aggregation */
#define AGGREGATE_THEN_DERIVE                                                  \
  "tr(musig([" FP "/86'/1'/0']%s,[deadbeef/86'/1'/1']%s)/<0;1>/*)"

/* The same on a recovery path's <2;3> */
#define AGGREGATE_THEN_DERIVE_RECOVERY                                         \
  "tr(musig([" FP "/86'/1'/0']%s,[deadbeef/86'/1'/1']%s)/<2;3>/*)"

static const unsigned char OUR_FP[4] = {0x73, 0xc5, 0xda, 0x0a};
static const unsigned char SYNTHETIC_FP[4] = {0xaa, 0xbb, 0xcc, 0xdd};

static char descriptor_buf[1024];

static const char *xpub_at(const char *path, char *out, size_t len) {
  char *xpub = NULL;
  if (!key_get_xpub(path, &xpub))
    return "";
  snprintf(out, len, "%s", xpub);
  wally_free_string(xpub);
  return out;
}

static bool register_descriptor(const char *fmt) {
  char ours[128], cosigner[128];
  snprintf(descriptor_buf, sizeof(descriptor_buf), fmt,
           xpub_at(OURS, ours, sizeof(ours)),
           xpub_at(COSIGNER, cosigner, sizeof(cosigner)));
  registry_clear();
  return registry_add_from_string("m", descriptor_buf, STORAGE_FLASH, false);
}

/* fp | path little endian, as PSBT_IN_TAP_BIP32_DERIVATION carries it */
static size_t origin(const unsigned char *fp, const uint32_t *path, size_t len,
                     unsigned char *out) {
  memcpy(out, fp, 4);
  for (size_t i = 0; i < len; i++)
    for (size_t b = 0; b < 4; b++)
      out[4 + 4 * i + b] = (unsigned char)(path[i] >> (8 * b));
  return 4 + 4 * len;
}

static size_t script_at(uint32_t multi_index, uint32_t child_num,
                        unsigned char *spk) {
  unsigned char work[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t written = 0;
  if (wally_descriptor_to_script(registry_get(0)->desc, 0, 0, 0, multi_index,
                                 child_num, 0, work, sizeof(work),
                                 &written) != WALLY_OK ||
      written != WALLY_SCRIPTPUBKEY_P2TR_LEN)
    return 0;
  memcpy(spk, work, written);
  return written;
}

static bool claims(const unsigned char *fp, uint32_t multi_index,
                   uint32_t child_num, const unsigned char *spk, size_t spk_len,
                   claim_t *claim) {
  const uint32_t path[] = {multi_index, child_num};
  unsigned char value[4 + 4 * 2];
  struct wally_map map;
  wally_map_init(1, NULL, &map);
  wally_map_add(&map, spk + 2, 32, value, origin(fp, path, 2, value));
  bool claimed = musig_psbt_claim(&map, spk, spk_len, claim);
  wally_map_clear(&map);
  return claimed;
}

/* ---------- claim ---------- */

static void test_claim(void) {
  check("musig() descriptor registers",
        register_descriptor(AGGREGATE_THEN_DERIVE));
  const registry_entry_t *entry = registry_get(0);
  unsigned char receive[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  unsigned char change[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  size_t receive_len = script_at(0, 5, receive);
  size_t change_len = script_at(1, 5, change);
  check("scripts generate", receive_len && change_len);

  claim_t claim;
  check("receive script claimed at 0/5",
        claims(SYNTHETIC_FP, 0, 5, receive, receive_len, &claim) &&
            claim.kind == CLAIM_MUSIG && claim.registry.entry == entry &&
            claim.registry.multi_index == 0 && claim.registry.child_num == 5);
  check("change script claimed at 1/5",
        claims(SYNTHETIC_FP, 1, 5, change, change_len, &claim) &&
            claim.registry.multi_index == 1 && claim.registry.child_num == 5);
  check("receive script with a change origin refused",
        !claims(SYNTHETIC_FP, 1, 5, receive, receive_len, &claim));
  check("receive script with another child refused",
        !claims(SYNTHETIC_FP, 0, 6, receive, receive_len, &claim));
  check("hardened child refused",
        !claims(SYNTHETIC_FP, 0, 0x80000005, receive, receive_len, &claim));
  check("multipath index past the descriptor's refused",
        !claims(SYNTHETIC_FP, 2, 5, receive, receive_len, &claim));
  check("hardened step before the child refused",
        !claims(SYNTHETIC_FP, 0x80000000, 5, receive, receive_len, &claim));
  unsigned char p2wpkh[22] = {0x00, 0x14};
  check("non-taproot script refused",
        !claims(SYNTHETIC_FP, 0, 5, p2wpkh, sizeof(p2wpkh), &claim));

  check("musig() descriptor on <2;3> registers",
        register_descriptor(AGGREGATE_THEN_DERIVE_RECOVERY));
  entry = registry_get(0);
  receive_len = script_at(0, 5, receive);
  change_len = script_at(1, 5, change);
  check("<2;3> scripts generate", receive_len && change_len);
  check("<2;3> script at 2/5 claimed at tuple position 0",
        claims(SYNTHETIC_FP, 2, 5, receive, receive_len, &claim) &&
            claim.kind == CLAIM_MUSIG && claim.registry.entry == entry &&
            claim.registry.multi_index == 0 && claim.registry.child_num == 5);
  check("<2;3> script at 3/5 claimed at tuple position 1",
        claims(SYNTHETIC_FP, 3, 5, change, change_len, &claim) &&
            claim.registry.multi_index == 1 && claim.registry.child_num == 5);
  check("<2;3> script with another child refused",
        !claims(SYNTHETIC_FP, 3, 6, change, change_len, &claim));
  check("<2;3> receive script with a 3/5 origin refused",
        !claims(SYNTHETIC_FP, 3, 5, receive, receive_len, &claim));
  check("<2;3> receive script with a 0/5 origin refused",
        !claims(SYNTHETIC_FP, 0, 5, receive, receive_len, &claim));

  char ours[128];
  snprintf(descriptor_buf, sizeof(descriptor_buf),
           "tr([" FP "/86'/1'/0']%s/<0;1>/*)",
           xpub_at(OURS, ours, sizeof(ours)));
  registry_clear();
  check("plain taproot descriptor registers",
        registry_add_from_string("t", descriptor_buf, STORAGE_FLASH, false));
  receive_len = script_at(0, 5, receive);
  check("a descriptor without our musig() claims nothing",
        receive_len && !claims(OUR_FP, 0, 5, receive, receive_len, &claim));
  registry_clear();
}

int main(void) {
  printf("=== musig_psbt tests ===\n\n");
  check("test mnemonic loads on testnet",
        key_load_from_mnemonic(TEST_MNEMONIC, "", true) &&
            wallet_init(WALLET_NETWORK_TESTNET));
  test_claim();
  registry_clear();
  key_unload();
  wallet_cleanup();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
