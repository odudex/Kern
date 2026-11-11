/*
 * Secure Boot v2 signature checks (core/sbv2.c).
 *
 * fixtures/sbv2_signed.bin is 5000 bytes of filler signed by espsecure with
 * two throwaway RSA-3072 keys (padded to 8192, then the 4 KiB signature
 * sector); fixtures/sbv2_key_digests.bin holds the Secure Boot digests of
 * those two keys plus a third key that did not sign:
 *
 *   espsecure generate-signing-key --version 2 --scheme rsa3072 test-keyN.pem
 *   espsecure digest-sbv2-public-key --keyfile test-keyN.pem -o digestN.bin
 *   espsecure sign-data --version 2 --keyfile test-key0.pem -o s0.bin blob.bin
 *   espsecure sign-data --version 2 --keyfile test-key1.pem \
 *       --append-signatures -o sbv2_signed.bin s0.bin
 */

#include "../sbv2.h"
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define IMAGE_LEN 5000
#define FIXTURE_LEN (8192 + SBV2_SECTOR_SIZE)
#define BLOCK_SIZE 1216
#define OFF_SIGNATURE 812
#define OFF_CRC 1196

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

static size_t read_file(const char *path, uint8_t *buf, size_t len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;
  size_t n = fread(buf, 1, len, f);
  fclose(f);
  return n;
}

static void image_digest(const uint8_t *image, uint8_t out[32]) {
  size_t len = 0;
  psa_hash_compute(PSA_ALG_SHA_256, image, sbv2_sector_offset(IMAGE_LEN), out,
                   32, &len);
}

static void fix_crc(uint8_t *block) {
  uint32_t crc = (uint32_t)crc32(0, block, OFF_CRC);
  for (int i = 0; i < 4; i++)
    block[OFF_CRC + i] = (uint8_t)(crc >> (8 * i));
}

int main(void) {
  static uint8_t image[FIXTURE_LEN], work[FIXTURE_LEN];
  uint8_t keys[3][32], digest[32];

  if (psa_crypto_init() != PSA_SUCCESS ||
      read_file("fixtures/sbv2_signed.bin", image, sizeof(image)) !=
          FIXTURE_LEN ||
      read_file("fixtures/sbv2_key_digests.bin", keys[0], sizeof(keys)) !=
          sizeof(keys)) {
    printf("Missing fixtures\n");
    return 1;
  }
  const uint8_t *sector = image + sbv2_sector_offset(IMAGE_LEN);
  image_digest(image, digest);

  check("sector offset pads to 4 KiB", sbv2_sector_offset(IMAGE_LEN) == 8192 &&
                                           sbv2_sector_offset(8192) == 8192 &&
                                           sbv2_sector_offset(1) == 4096);
  check("first signer verifies", sbv2_signed_by(sector, digest, keys[0]));
  check("second signer verifies", sbv2_signed_by(sector, digest, keys[1]));
  check("key that did not sign is rejected",
        !sbv2_signed_by(sector, digest, keys[2]));

  memcpy(work, image, sizeof(work));
  work[100] ^= 1;
  uint8_t tampered[32];
  image_digest(work, tampered);
  check("modified image is rejected",
        !sbv2_signed_by(sector, tampered, keys[0]));

  uint8_t *block0 = work + sbv2_sector_offset(IMAGE_LEN);
  memcpy(work, image, sizeof(work));
  block0[OFF_SIGNATURE + 10] ^= 1;
  fix_crc(block0);
  check("forged signature with valid CRC is rejected",
        !sbv2_signed_by(block0, digest, keys[0]));
  check("other block still verifies after a forgery",
        sbv2_signed_by(block0, digest, keys[1]));

  memcpy(work, image, sizeof(work));
  block0[2] ^= 1; /* reserved: covered by the CRC only */
  check("bad CRC is rejected", !sbv2_signed_by(block0, digest, keys[0]));
  fix_crc(block0);
  check("CRC is what rejected it", sbv2_signed_by(block0, digest, keys[0]));

  memcpy(work, image, sizeof(work));
  memcpy(block0, block0 + BLOCK_SIZE, BLOCK_SIZE);
  memset(block0 + BLOCK_SIZE, 0xFF, BLOCK_SIZE);
  check("block position does not matter",
        sbv2_signed_by(block0, digest, keys[1]) &&
            !sbv2_signed_by(block0, digest, keys[0]));

  memcpy(work, image, sizeof(work));
  block0[1] = 0x03;
  fix_crc(block0);
  check("non-RSA block version is rejected",
        !sbv2_signed_by(block0, digest, keys[0]));

  printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);
  return tests_failed ? 1 : 0;
}
