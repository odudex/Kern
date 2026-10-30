#ifndef SELF_TEST_H
#define SELF_TEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Known-answer checks of the device's crypto: hashing, AES and PBKDF2 on their
 * hardware engines, BIP39/32/85, signing, and dice mnemonics. Every check uses
 * fixed public test keys, never the loaded wallet. Needs crypto_init(). */

typedef struct {
  const char *name;
  bool passed;
  bool skipped; /* not applicable to this build */
  uint32_t ms;
} self_test_result_t;

size_t self_test_count(void);

/* Runs every check in order into results[self_test_count()]. *progress counts
 * the finished checks, for a caller polling from another task. */
void self_test_run_all(self_test_result_t *results, volatile size_t *progress);

#endif // SELF_TEST_H
