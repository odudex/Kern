#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#include "core/descriptor_text.h"
#include "utils/text_file.h"

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

#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define BARE "wpkh([73c5da0a/84h/0h/0h]" XPUB_84 ")"
#define BARE_OTHER "wpkh([73c5da0a/84h/0h/1h]" XPUB_84 ")"
#define DERIVED "wpkh([73c5da0a/84h/0h/0h]" XPUB_84 "/<0;1>/*)"

/* libwally's own checksum of `body`, as the oracle: "body#checksum". */
static char *checksummed(const char *body) {
  struct wally_descriptor *d = NULL;
  char *out = NULL;
  if (wally_descriptor_parse(body, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0,
                             &d) != WALLY_OK ||
      wally_descriptor_canonicalize(d, 0, &out) != WALLY_OK)
    out = NULL;
  wally_descriptor_free(d);
  return out;
}

static bool parses(const char *text) {
  struct wally_descriptor *d = NULL;
  bool ok = wally_descriptor_parse(text, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0,
                                   &d) == WALLY_OK;
  wally_descriptor_free(d);
  return ok;
}

static void expect(const char *name, const char *in, const char *want) {
  TEST(name);
  char *out = descriptor_to_unambiguous(in);
  if (!want && out)
    FAIL("expected no rewrite");
  else if (want && (!out || strcmp(out, want) != 0))
    FAIL("unexpected rewrite");
  else
    PASS();
  free(out);
}

int main(void) {
  /* The host libwally hashes through PSA, as the device does, which needs
   * wally_init. */
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
  printf("=== descriptor_to_unambiguous tests ===\n\n");
  char *good = checksummed(BARE);
  char *other = checksummed(BARE_OTHER);
  if (!good || !other || strlen(good) != strlen(BARE) + 9) {
    printf("ABORT: no reference checksum\n");
    return 1;
  }

  expect("bare xpub gains /<0;1>/*", BARE, DERIVED);
  expect("correct checksum: rewritten, checksum dropped", good, DERIVED);
  expect("a derived key is left alone", DERIVED, NULL);

  /* The other descriptor's checksum on this body: a transcription error. */
  char stale[512];
  snprintf(stale, sizeof(stale), "%s#%s", BARE, other + strlen(BARE_OTHER) + 1);
  expect("stale checksum: not rewritten", stale, NULL);
  TEST("stale checksum: the original then fails to parse");
  if (!parses(stale))
    PASS();
  else
    FAIL("libwally should reject the checksum");

  expect("garbage checksum: not rewritten", BARE "#aaaaaaaa", NULL);

  /* Load Descriptor from flash or SD reads files the way Scan does. */
  TEST("file text: trailing newline, BOM and comment lines dropped");
  const char file[] =
      "\xEF\xBB\xBF# exported by a coordinator\r\n" BARE "\r\n\n";
  char *text = text_file_normalize((const uint8_t *)file, sizeof(file) - 1);
  if (text && strcmp(text, BARE) == 0)
    PASS();
  else
    FAIL("expected the bare descriptor line");
  free(text);

  free(good);
  free(other);
  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
