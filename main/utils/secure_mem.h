/*
 * Secure Memory Utilities
 * Primitives for handling sensitive data (seeds, mnemonics, keys)
 */

#ifndef SECURE_MEM_H
#define SECURE_MEM_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Volatile function pointer prevents the compiler from optimizing away
 * the memset call via dead store elimination. This is the same technique
 * used by libsodium and OpenSSL.
 */
static void *(*const volatile secure_memset_fn)(void *, int, size_t) = memset;

/* Guaranteed memory zeroing - cannot be optimized away */
static inline void secure_memzero(void *ptr, size_t len) {
  if (ptr && len > 0) {
    secure_memset_fn(ptr, 0, len);
  }
}

/* Constant-time memory comparison - prevents timing side-channels.
 * Returns 0 if equal, non-zero otherwise. */
static inline int secure_memcmp(const void *a, const void *b, size_t len) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  unsigned char diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= pa[i] ^ pb[i];
  }
  return diff;
}

/* Securely free a heap-allocated string: zero contents, free, set to NULL */
#define SECURE_FREE_STRING(ptr)                                                \
  do {                                                                         \
    if (ptr) {                                                                 \
      secure_memzero(ptr, strlen(ptr));                                        \
      free(ptr);                                                               \
      ptr = NULL;                                                              \
    }                                                                          \
  } while (0)

/* Securely free a heap buffer of known size: zero contents, free, set to NULL
 */
#define SECURE_FREE_BUFFER(ptr, len)                                           \
  do {                                                                         \
    if (ptr) {                                                                 \
      secure_memzero(ptr, len);                                                \
      free(ptr);                                                               \
      ptr = NULL;                                                              \
    }                                                                          \
  } while (0)

#endif // SECURE_MEM_H
