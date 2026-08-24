#include <stdbool.h>
#include <stdio.h>

#include "core/descriptor_validator.h"
#include "core/registry.h"

#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"

#define DESC_WPKH "wpkh([00000000/84'/0'/0']" XPUB_84 "/<0;1>/*)#d9qwe873"

static int tests_failed = 0;
static bool info_confirm_called = false;
static bool id_loc_called = false;
static bool validation_completed = false;
static descriptor_validation_result_t validation_result = VALIDATION_INTERNAL_ERROR;
static void (*pending_info_proceed)(bool confirmed, void *user_data) = NULL;

#define TEST(name)                                                             \
  do {                                                                         \
    printf("Testing: %s... ", name);                                          \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                        \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                \
    tests_failed++;                                                            \
  } while (0)

static void validation_cb(descriptor_validation_result_t result,
                          void *user_data) {
  (void)user_data;
  validation_completed = true;
  validation_result = result;
}

static void confirm_cb(const char *message,
                       void (*proceed)(bool confirmed, void *user_data)) {
  (void)message;
  proceed(true, NULL);
}

static void info_confirm_cb(const descriptor_info_t *info,
                            void (*proceed)(bool confirmed, void *user_data)) {
  (void)info;
  info_confirm_called = true;
  pending_info_proceed = proceed;
}

static void id_loc_cb(void (*proceed)(const char *id, storage_location_t loc,
                                      void *user_data),
                      void *user_data) {
  id_loc_called = true;
  (void)user_data;
  proceed("persisted", STORAGE_FLASH, NULL);
}

int main(void) {
  printf("=== descriptor_validator persistent registration tests ===\n\n");

  registry_clear();
  if (!registry_add_from_string("persisted", DESC_WPKH, STORAGE_FLASH, false)) {
    printf("setup failed\n");
    return 1;
  }

  descriptor_validate_and_load_persistent(DESC_WPKH, validation_cb, confirm_cb,
                                          info_confirm_cb, id_loc_cb, NULL);

  TEST("persistent duplicate completes without descriptor review");
  if (!info_confirm_called && validation_completed &&
      validation_result == VALIDATION_DUPLICATE && !pending_info_proceed) {
    PASS();
  } else {
    FAIL("duplicate descriptor was reviewed or did not complete as duplicate");
  }

  TEST("persistent duplicate does not request storage id");
  if (!id_loc_called) {
    PASS();
  } else {
    FAIL("duplicate descriptor requested registration storage");
  }

  TEST("persistent duplicate does not append registry entry");
  if (registry_count() == 1) {
    PASS();
  } else {
    FAIL("duplicate descriptor was appended");
  }

  registry_clear();
  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
