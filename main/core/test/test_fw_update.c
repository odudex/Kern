/*
 * Firmware update pre-flight tests (core/fw_update.c).
 *
 * Images are synthesised in memory following the ESP-IDF layout the real
 * signed kern.bin uses: 24-byte header, segments, checksum byte padded to 16,
 * optional 32-byte SHA-256, padding to a 4 KiB boundary, then the 4 KiB
 * Secure Boot v2 signature sector.  The ESP-IDF OTA and secure-boot calls are
 * replaced by fakes below so the tests can drive every failure path and
 * observe exactly which digest the signature verifier is handed.
 */

#include "../fw_update.h"
#include <esp_app_desc.h>
#include <esp_app_format.h>
#include <esp_ota_ops.h>
#include <esp_secure_boot.h>
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- ESP-IDF fakes ---------- */

#define RUNNING_PROJECT "kern"
#define RUNNING_VERSION "0.0.18"

static esp_app_desc_t running_desc;
static bool fake_sb_enabled;
static unsigned fake_sb_num_digests;
static esp_err_t fake_sb_blocks_ret;
static bool fake_sig_valid;
static int fake_verify_calls;
static uint8_t fake_last_digest[32];
static uint8_t fake_last_sig_magic;

static esp_partition_t fake_next_part = {
    .address = 0x620000, .size = 6 * 1024 * 1024, .label = "ota_1"};
static bool fake_next_missing;
static uint8_t *fake_ota_buf;
static size_t fake_ota_written;
static long fake_ota_fail_write_at;
static bool fake_ota_end_fail;
static bool fake_ota_began, fake_ota_aborted, fake_ota_ended;
static const esp_partition_t *fake_boot_set;

static esp_partition_t fake_running_part = {
    .address = 0x20000, .size = 6 * 1024 * 1024, .label = "ota_0"};
static bool fake_running_missing;
static esp_ota_img_states_t fake_running_state;
static int fake_mark_valid_calls;

static void fakes_reset(void) {
  memset(&running_desc, 0, sizeof(running_desc));
  running_desc.magic_word = ESP_APP_DESC_MAGIC_WORD;
  strcpy(running_desc.project_name, RUNNING_PROJECT);
  strcpy(running_desc.version, RUNNING_VERSION);
  running_desc.secure_version = 0;

  fake_sb_enabled = false;
  fake_sb_num_digests = 1;
  fake_sb_blocks_ret = ESP_OK;
  fake_sig_valid = true;
  fake_verify_calls = 0;
  memset(fake_last_digest, 0, sizeof(fake_last_digest));
  fake_last_sig_magic = 0;

  fake_next_missing = false;
  free(fake_ota_buf);
  fake_ota_buf = NULL;
  fake_ota_written = 0;
  fake_ota_fail_write_at = -1;
  fake_ota_end_fail = false;
  fake_ota_began = fake_ota_aborted = fake_ota_ended = false;
  fake_boot_set = NULL;

  fake_running_missing = false;
  fake_running_state = ESP_OTA_IMG_VALID;
  fake_mark_valid_calls = 0;
}

const char *esp_err_to_name(esp_err_t code) {
  (void)code;
  return "fake";
}

const esp_app_desc_t *esp_app_get_description(void) { return &running_desc; }

bool esp_secure_boot_enabled(void) { return fake_sb_enabled; }

esp_err_t esp_secure_boot_get_signature_blocks_for_running_app(
    bool digest_public_keys,
    esp_image_sig_public_key_digests_t *public_key_digests) {
  (void)digest_public_keys;
  memset(public_key_digests, 0, sizeof(*public_key_digests));
  public_key_digests->num_digests = fake_sb_num_digests;
  return fake_sb_blocks_ret;
}

esp_err_t esp_secure_boot_verify_sbv2_signature_block(
    const ets_secure_boot_signature_t *sig_block, const uint8_t *image_digest,
    uint8_t *verified_digest) {
  fake_verify_calls++;
  fake_last_sig_magic = sig_block->raw[0];
  memcpy(fake_last_digest, image_digest, 32);
  if (!fake_sig_valid)
    return ESP_FAIL;
  memcpy(verified_digest, image_digest, 32);
  return ESP_OK;
}

const esp_partition_t *
esp_ota_get_next_update_partition(const esp_partition_t *start_from) {
  (void)start_from;
  return fake_next_missing ? NULL : &fake_next_part;
}

const esp_partition_t *esp_ota_get_running_partition(void) {
  return fake_running_missing ? NULL : &fake_running_part;
}

esp_err_t esp_ota_begin(const esp_partition_t *partition, size_t image_size,
                        esp_ota_handle_t *out_handle) {
  if (partition != &fake_next_part || image_size != OTA_WITH_SEQUENTIAL_WRITES)
    return ESP_ERR_INVALID_ARG;
  free(fake_ota_buf);
  fake_ota_buf = calloc(1, partition->size);
  fake_ota_written = 0;
  fake_ota_began = true;
  *out_handle = 0x1234;
  return ESP_OK;
}

esp_err_t esp_ota_write(esp_ota_handle_t handle, const void *data,
                        size_t size) {
  if (handle != 0x1234 || !fake_ota_began)
    return ESP_ERR_INVALID_ARG;
  if (fake_ota_fail_write_at >= 0 &&
      (long)fake_ota_written >= fake_ota_fail_write_at)
    return ESP_FAIL;
  if (fake_ota_written + size > fake_next_part.size)
    return ESP_ERR_INVALID_ARG;
  memcpy(fake_ota_buf + fake_ota_written, data, size);
  fake_ota_written += size;
  return ESP_OK;
}

esp_err_t esp_ota_end(esp_ota_handle_t handle) {
  if (handle != 0x1234)
    return ESP_ERR_INVALID_ARG;
  fake_ota_ended = true;
  return fake_ota_end_fail ? ESP_ERR_OTA_VALIDATE_FAILED : ESP_OK;
}

esp_err_t esp_ota_abort(esp_ota_handle_t handle) {
  if (handle != 0x1234)
    return ESP_ERR_INVALID_ARG;
  fake_ota_aborted = true;
  return ESP_OK;
}

esp_err_t esp_ota_set_boot_partition(const esp_partition_t *partition) {
  fake_boot_set = partition;
  return ESP_OK;
}

esp_err_t esp_ota_get_state_partition(const esp_partition_t *partition,
                                      esp_ota_img_states_t *ota_state) {
  if (partition != &fake_running_part)
    return ESP_ERR_NOT_FOUND;
  *ota_state = fake_running_state;
  return ESP_OK;
}

esp_err_t esp_ota_mark_app_valid_cancel_rollback(void) {
  fake_mark_valid_calls++;
  return ESP_OK;
}

/* ---------- image synthesis ---------- */

#define SIG_SECTOR 4096
#define SIG_MAGIC 0xE7

typedef struct {
  uint8_t magic;
  uint16_t chip_id;
  uint8_t hash_appended;
  uint32_t desc_magic;
  const char *project;
  const char *version;
  uint32_t secure_version;
  int extra_segments;
  uint32_t first_seg_extra; /* filler after the app descriptor */
  bool sign;
} img_opts_t;

static img_opts_t default_opts(void) {
  img_opts_t o = {.magic = ESP_IMAGE_HEADER_MAGIC,
                  .chip_id = ESP_CHIP_ID_ESP32P4,
                  .hash_appended = 1,
                  .desc_magic = ESP_APP_DESC_MAGIC_WORD,
                  .project = RUNNING_PROJECT,
                  .version = "0.0.19",
                  .secure_version = 0,
                  .extra_segments = 2,
                  .first_seg_extra = 1000,
                  .sign = true};
  return o;
}

static void fill_pattern(uint8_t *p, size_t len, uint32_t seed) {
  for (size_t i = 0; i < len; i++) {
    seed = seed * 1103515245u + 12345u;
    p[i] = (uint8_t)(seed >> 16);
  }
}

static size_t align_up(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }

/* Returns the image length; *sig_offset_out receives where the signature
 * sector starts (also the end of the signed range). */
static size_t build_image(const img_opts_t *o, uint8_t **out,
                          size_t *sig_offset_out) {
  size_t body = sizeof(esp_image_header_t);
  body += sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t) +
          o->first_seg_extra;
  for (int i = 0; i < o->extra_segments; i++)
    body += sizeof(esp_image_segment_header_t) + 300 + 17 * i;
  body = align_up(body + 1, 16);
  if (o->hash_appended)
    body += 32;
  size_t sig_offset = align_up(body, SIG_SECTOR);
  size_t total = o->sign ? sig_offset + SIG_SECTOR : sig_offset;

  uint8_t *img = calloc(1, total);
  fill_pattern(img, total, 0xC0FFEE);

  esp_image_header_t hdr = {0};
  hdr.magic = o->magic;
  hdr.segment_count = (uint8_t)(1 + o->extra_segments);
  hdr.chip_id = (esp_chip_id_t)o->chip_id;
  hdr.hash_appended = o->hash_appended;
  memcpy(img, &hdr, sizeof(hdr));

  size_t pos = sizeof(hdr);
  esp_image_segment_header_t seg = {
      .load_addr = 0x40000000,
      .data_len = (uint32_t)(sizeof(esp_app_desc_t) + o->first_seg_extra)};
  memcpy(img + pos, &seg, sizeof(seg));
  pos += sizeof(seg);

  esp_app_desc_t desc = {0};
  desc.magic_word = o->desc_magic;
  desc.secure_version = o->secure_version;
  strncpy(desc.version, o->version, sizeof(desc.version) - 1);
  strncpy(desc.project_name, o->project, sizeof(desc.project_name) - 1);
  memcpy(img + pos, &desc, sizeof(desc));
  pos += seg.data_len;

  for (int i = 0; i < o->extra_segments; i++) {
    seg.load_addr = 0x40100000 + 0x1000 * i;
    seg.data_len = 300 + 17 * i;
    memcpy(img + pos, &seg, sizeof(seg));
    pos += sizeof(seg) + seg.data_len;
  }

  if (o->sign) {
    memset(img + sig_offset, 0, SIG_SECTOR);
    img[sig_offset] = SIG_MAGIC;
    fill_pattern(img + sig_offset + 1, SIG_SECTOR - 1, 0x5164);
  }

  *out = img;
  *sig_offset_out = sig_offset;
  return total;
}

static char tmp_path[] = "/tmp/kern_fw_test_XXXXXX";

static const char *write_tmp(const uint8_t *data, size_t len) {
  strcpy(tmp_path, "/tmp/kern_fw_test_XXXXXX");
  int fd = mkstemp(tmp_path);
  if (fd < 0)
    return NULL;
  FILE *f = fdopen(fd, "wb");
  fwrite(data, 1, len, f);
  fclose(f);
  return tmp_path;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  size_t olen = 0;
  psa_crypto_init();
  psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &olen);
}

/* Builds, writes and validates; returns the validate result and frees
 * nothing so callers can inspect img afterwards. */
static int validate_image(uint8_t *img, size_t len, fw_update_info_t *info,
                          const char **err) {
  const char *path = write_tmp(img, len);
  *err = NULL;
  int r = fw_update_validate(path, info, err);
  unlink(path);
  return r;
}

static bool err_is(const char *err, const char *expect) {
  return err && strcmp(err, expect) == 0;
}

/* ---------- validate: accept paths ---------- */

static void test_valid_image(void) {
  fakes_reset();
  img_opts_t o = default_opts();
  uint8_t *img;
  size_t sig_offset;
  size_t len = build_image(&o, &img, &sig_offset);

  fw_update_info_t info;
  const char *err;
  int r = validate_image(img, len, &info, &err);
  check("valid image accepted", r == 0 && err == NULL);
  check("info reports candidate version", strcmp(info.version, "0.0.19") == 0);
  check("info reports running version",
        strcmp(info.current_version, RUNNING_VERSION) == 0);
  check("info reports image size", info.image_size == len);
  check("info reports secure version", info.secure_version == 0);
  check("verifier called exactly once", fake_verify_calls == 1);
  check("verifier handed the signature sector",
        fake_last_sig_magic == SIG_MAGIC);

  uint8_t expect[32];
  sha256(img, sig_offset, expect);
  check("digest covers exactly the bytes before the signature sector",
        memcmp(fake_last_digest, expect, 32) == 0);

  /* Every byte of the signed range must influence the digest, including the
   * zero padding between the appended hash and the signature sector. */
  uint8_t before[32];
  memcpy(before, fake_last_digest, 32);
  img[sig_offset - 1] ^= 0x01;
  r = validate_image(img, len, NULL, &err);
  check("padding byte is inside the signed range",
        r == 0 && memcmp(fake_last_digest, before, 32) != 0);
  img[sig_offset - 1] ^= 0x01;

  img[sig_offset + 100] ^= 0x01;
  r = validate_image(img, len, NULL, &err);
  check("signature sector is outside the signed range",
        r == 0 && memcmp(fake_last_digest, before, 32) == 0);

  free(img);
}

static void test_valid_variants(void) {
  fakes_reset();
  uint8_t *img;
  size_t sig_offset;
  fw_update_info_t info;
  const char *err;

  img_opts_t o = default_opts();
  o.hash_appended = 0;
  size_t len = build_image(&o, &img, &sig_offset);
  check("image without appended hash accepted",
        validate_image(img, len, &info, &err) == 0);
  free(img);

  o = default_opts();
  o.extra_segments = 0;
  len = build_image(&o, &img, &sig_offset);
  check("single-segment image accepted",
        validate_image(img, len, &info, &err) == 0);
  free(img);

  o = default_opts();
  o.extra_segments = 15;
  len = build_image(&o, &img, &sig_offset);
  check("sixteen-segment image accepted",
        validate_image(img, len, &info, &err) == 0);
  free(img);

  /* Body already 4 KiB aligned: no padding before the signature sector. */
  o = default_opts();
  o.extra_segments = 0;
  o.hash_appended = 0;
  size_t fixed = sizeof(esp_image_header_t) +
                 sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t);
  o.first_seg_extra = (uint32_t)(SIG_SECTOR - fixed - 16);
  len = build_image(&o, &img, &sig_offset);
  check("aligned body needs no padding",
        sig_offset == SIG_SECTOR && validate_image(img, len, &info, &err) == 0);
  free(img);

  o = default_opts();
  o.secure_version = 3;
  running_desc.secure_version = 3;
  len = build_image(&o, &img, &sig_offset);
  check("equal secure version accepted",
        validate_image(img, len, &info, &err) == 0 && info.secure_version == 3);
  free(img);

  o.secure_version = 4;
  len = build_image(&o, &img, &sig_offset);
  check("newer secure version accepted",
        validate_image(img, len, &info, &err) == 0 && info.secure_version == 4);
  free(img);

  running_desc.secure_version = 0;
  fake_sb_enabled = true;
  fake_sb_blocks_ret = ESP_ERR_NOT_FOUND;
  fake_sb_num_digests = 0;
  o = default_opts();
  len = build_image(&o, &img, &sig_offset);
  check("secure boot enabled skips running-app digest lookup",
        validate_image(img, len, &info, &err) == 0);
  free(img);
}

/* ---------- validate: reject paths ---------- */

static void test_reject_headers(void) {
  fakes_reset();
  uint8_t *img;
  size_t sig_offset, len;
  fw_update_info_t info;
  const char *err;
  img_opts_t o;

  int r = fw_update_validate("/nonexistent/kern.bin", &info, &err);
  check("missing file rejected", r != 0 && err_is(err, "Cannot open file"));

  uint8_t tiny[512] = {ESP_IMAGE_HEADER_MAGIC};
  r = validate_image(tiny, sizeof(tiny), &info, &err);
  check("undersized file rejected",
        r != 0 && err_is(err, "Invalid firmware file"));

  o = default_opts();
  o.magic = 0xE8;
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("bad image magic rejected",
        r != 0 && err_is(err, "Invalid firmware file"));
  free(img);

  o = default_opts();
  o.chip_id = ESP_CHIP_ID_ESP32S3;
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("other chip rejected", r != 0 && err_is(err, "Not an ESP32-P4 image"));
  free(img);

  o = default_opts();
  o.desc_magic = 0xABCD5433;
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("bad app descriptor magic rejected",
        r != 0 && err_is(err, "Invalid firmware file"));
  free(img);

  o = default_opts();
  o.project = "krux";
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("other project rejected",
        r != 0 && err_is(err, "Different project firmware"));
  free(img);

  o = default_opts();
  o.project = "kern2";
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("project name prefix match rejected",
        r != 0 && err_is(err, "Different project firmware"));
  free(img);

  o = default_opts();
  o.secure_version = 1;
  running_desc.secure_version = 2;
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("older secure version rejected",
        r != 0 && err_is(err, "Older security version rejected"));
  free(img);
  running_desc.secure_version = 0;

  check("rejections never reach the verifier", fake_verify_calls == 0);
}

static void test_reject_layout(void) {
  fakes_reset();
  uint8_t *img;
  size_t sig_offset, len;
  fw_update_info_t info;
  const char *err;
  img_opts_t o;

  o = default_opts();
  o.sign = false;
  len = build_image(&o, &img, &sig_offset);
  int r = validate_image(img, len, &info, &err);
  check("unsigned image below the size floor rejected",
        r != 0 && err_is(err, "Invalid firmware file"));
  free(img);

  o = default_opts();
  o.sign = false;
  o.first_seg_extra = 6000;
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len, &info, &err);
  check("unsigned image rejected",
        r != 0 && err_is(err, "Image is not signed"));
  free(img);

  o = default_opts();
  len = build_image(&o, &img, &sig_offset);
  r = validate_image(img, len - 1, &info, &err);
  check("truncated signature sector rejected",
        r != 0 && err_is(err, "Image is not signed"));

  uint8_t *grown = realloc(img, len + 1);
  grown[len] = 0;
  r = validate_image(grown, len + 1, &info, &err);
  check("trailing byte after signature rejected",
        r != 0 && err_is(err, "Image is not signed"));
  free(grown);

  /* Two signature sectors' worth of tail: the first is the real sector. */
  o = default_opts();
  len = build_image(&o, &img, &sig_offset);
  grown = realloc(img, len + SIG_SECTOR);
  memset(grown + len, 0xAA, SIG_SECTOR);
  r = validate_image(grown, len + SIG_SECTOR, &info, &err);
  check("extra trailing sector rejected",
        r != 0 && err_is(err, "Image is not signed"));
  free(grown);

  o = default_opts();
  len = build_image(&o, &img, &sig_offset);
  esp_image_segment_header_t seg;
  size_t seg0 = sizeof(esp_image_header_t);
  memcpy(&seg, img + seg0, sizeof(seg));
  seg.data_len = 0x7FFFFFF0;
  memcpy(img + seg0, &seg, sizeof(seg));
  r = validate_image(img, len, &info, &err);
  check("segment overrunning the file rejected",
        r != 0 && err_is(err, "Image is not signed"));

  seg.data_len = 0xFFFFFFF0;
  memcpy(img + seg0, &seg, sizeof(seg));
  r = validate_image(img, len, &info, &err);
  check("segment length that wraps the offset rejected",
        r != 0 && err_is(err, "Image is not signed"));

  memcpy(&seg, img + seg0, sizeof(seg));
  seg.data_len = (uint32_t)(len - seg0 - sizeof(seg) - 200);
  memcpy(img + seg0, &seg, sizeof(seg));
  r = validate_image(img, len, &info, &err);
  check("segment table ending inside the signature rejected",
        r != 0 && err_is(err, "Image is not signed"));
  free(img);

  o = default_opts();
  len = build_image(&o, &img, &sig_offset);
  img[1] = 0xFF; /* walk continues into segment data and overruns */
  r = validate_image(img, len, &info, &err);
  check("inflated segment count rejected",
        r != 0 && err_is(err, "Image is not signed"));
  free(img);

  check("layout rejections never reach the verifier", fake_verify_calls == 0);
}

static void test_reject_signature(void) {
  fakes_reset();
  uint8_t *img;
  size_t sig_offset;
  fw_update_info_t info;
  const char *err;
  img_opts_t o = default_opts();
  size_t len = build_image(&o, &img, &sig_offset);

  fake_sb_enabled = false;
  fake_sb_num_digests = 0;
  int r = validate_image(img, len, &info, &err);
  check("unsigned running firmware cannot verify",
        r != 0 &&
            err_is(err, "Running firmware is unsigned; cannot verify updates"));
  check("no verification attempted without trusted keys",
        fake_verify_calls == 0);

  fake_sb_num_digests = 1;
  fake_sb_blocks_ret = ESP_FAIL;
  r = validate_image(img, len, &info, &err);
  check("trusted key lookup failure rejects",
        r != 0 &&
            err_is(err, "Running firmware is unsigned; cannot verify updates"));

  fake_sb_blocks_ret = ESP_OK;
  fake_sig_valid = false;
  memset(&info, 0xEE, sizeof(info));
  r = validate_image(img, len, &info, &err);
  check("bad signature rejected",
        r != 0 && err_is(err, "Signature verification failed"));
  check("info untouched on rejection", (uint8_t)info.version[0] == 0xEE);
  check("verifier still saw the right digest", fake_verify_calls == 1);

  fake_sig_valid = true;
  r = validate_image(img, len, NULL, &err);
  check("NULL info accepted", r == 0);
  free(img);
}

/* ---------- apply ---------- */

static int progress_last;
static bool progress_monotonic;
static int progress_calls;

static void progress_cb(int percent, void *user_data) {
  (void)user_data;
  progress_calls++;
  if (percent < progress_last || percent > 100)
    progress_monotonic = false;
  progress_last = percent;
}

static void progress_reset(void) {
  progress_last = 0;
  progress_monotonic = true;
  progress_calls = 0;
}

static void test_apply(void) {
  fakes_reset();
  uint8_t *img;
  size_t sig_offset;
  img_opts_t o = default_opts();
  o.first_seg_extra = 20000; /* several read chunks */
  size_t len = build_image(&o, &img, &sig_offset);
  const char *err;

  int r = fw_update_apply("/nonexistent/kern.bin", NULL, NULL, &err);
  check("apply: missing file rejected",
        r != 0 && err_is(err, "Cannot open file"));

  const char *path = write_tmp(img, len);

  fake_next_missing = true;
  r = fw_update_apply(path, NULL, NULL, &err);
  check("apply: no OTA slot rejected",
        r != 0 && err_is(err, "No OTA partition available") && !fake_ota_began);
  fake_next_missing = false;

  fake_next_part.size = (uint32_t)len - 1;
  r = fw_update_apply(path, NULL, NULL, &err);
  check("apply: oversized image rejected before erase",
        r != 0 && err_is(err, "Image too large for OTA partition") &&
            !fake_ota_began);
  fake_next_part.size = 6 * 1024 * 1024;

  fake_ota_fail_write_at = 8192;
  r = fw_update_apply(path, NULL, NULL, &err);
  check("apply: flash write failure reported",
        r != 0 && err_is(err, "Flash write failed"));
  check("apply: write failure aborts the OTA handle",
        fake_ota_aborted && !fake_ota_ended && fake_boot_set == NULL);
  fake_ota_fail_write_at = -1;
  fake_ota_aborted = false;

  fake_ota_end_fail = true;
  r = fw_update_apply(path, NULL, NULL, &err);
  check("apply: end-of-image validation failure reported",
        r != 0 && err_is(err, "Image verification failed"));
  check("apply: failed validation leaves boot partition alone",
        fake_ota_ended && !fake_ota_aborted && fake_boot_set == NULL);
  fake_ota_end_fail = false;
  fake_ota_ended = false;

  progress_reset();
  r = fw_update_apply(path, progress_cb, NULL, &err);
  check("apply: success", r == 0);
  check("apply: whole file streamed to the slot",
        fake_ota_written == len && memcmp(fake_ota_buf, img, len) == 0);
  check("apply: boot partition switched to the new slot",
        fake_boot_set == &fake_next_part && !fake_ota_aborted);
  check("apply: progress monotonic and ends at 100",
        progress_monotonic && progress_last == 100 && progress_calls >= 3);

  unlink(path);
  free(img);
}

/* ---------- boot confirm ---------- */

static void test_boot_confirm(void) {
  fakes_reset();
  fake_running_state = ESP_OTA_IMG_PENDING_VERIFY;
  fw_update_boot_confirm();
  check("pending image marked valid", fake_mark_valid_calls == 1);

  fake_running_state = ESP_OTA_IMG_VALID;
  fw_update_boot_confirm();
  check("already-valid image not re-marked", fake_mark_valid_calls == 1);

  fake_running_state = ESP_OTA_IMG_NEW;
  fw_update_boot_confirm();
  check("fresh image not marked", fake_mark_valid_calls == 1);

  fake_running_missing = true;
  fw_update_boot_confirm();
  check("missing running partition tolerated", fake_mark_valid_calls == 1);
}

int main(void) {
  printf("=== fw_update tests ===\n\n");

  test_valid_image();
  test_valid_variants();
  test_reject_headers();
  test_reject_layout();
  test_reject_signature();
  test_apply();
  test_boot_confirm();

  fakes_reset();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
