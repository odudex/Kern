#ifndef KERN_FUZZ_H
#define KERN_FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* libFuzzer's entry point; fuzz_driver.c calls it when built without
 * -fsanitize=fuzzer (gcc). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Loads the abandon...about test key and the wallet once per process. */
void fuzz_load_test_key(void);

#endif // KERN_FUZZ_H
