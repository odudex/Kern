#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/crypto_init.h"
#include "core/self_test.h"
#include "core/wallet.h"

wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

/* The device's self test, run on the host: every vector it carries must hold
 * here too, so a device failure means the device, not the vector. Only the
 * PBKDF2 accelerator check is skipped, having no engine on the host. */
int main(void) {
  if (!crypto_init()) {
    printf("ABORT: crypto_init failed\n");
    return 1;
  }
  printf("=== self_test tests ===\n\n");

  self_test_result_t results[16];
  size_t count = self_test_count();
  if (count > sizeof(results) / sizeof(results[0])) {
    printf("ABORT: %zu checks, room for %zu\n", count,
           sizeof(results) / sizeof(results[0]));
    return 1;
  }
  volatile size_t progress = 0;
  self_test_run_all(results, &progress);

  int failed = progress == count ? 0 : 1;
  if (failed)
    printf("Testing: progress counts every check... FAIL\n");
  for (size_t i = 0; i < count; i++) {
    bool want_skip = strcmp(results[i].name, "PBKDF2 accelerator") == 0;
    bool ok = results[i].skipped ? want_skip : results[i].passed && !want_skip;
    printf("Testing: %s... %s (%u ms)\n", results[i].name,
           ok ? (results[i].skipped ? "SKIP" : "PASS") : "FAIL",
           (unsigned)results[i].ms);
    failed += !ok;
  }
  printf("\n=== Results: %zu passed, %d failed ===\n", count - failed, failed);
  return failed ? 1 : 0;
}
