#include "kern_wally.h"
#include "secure_memory.h"
#include <stdlib.h>
#include <wally_core.h>

/* Install once, before tasks start. Only the calling thread's allocation
 * policy changes during a secret operation; no global callback swapping. */
static _Thread_local unsigned secret_depth;
static void *(*default_malloc)(size_t);

static void *policy_malloc(size_t size) {
  return secret_depth ? kern_secret_alloc(size) : default_malloc(size);
}

static void __attribute__((constructor)) init_secret_policy(void) {
  struct wally_operations ops = {.struct_size = sizeof(ops)};
  if (wally_get_operations(&ops) != WALLY_OK)
    abort();
  default_malloc = ops.malloc_fn;
  ops.malloc_fn = policy_malloc;
  if (wally_set_operations(&ops) != WALLY_OK)
    abort();
}

/* Check the hook before every protected operation: a future allocator
 * override must fail closed instead of silently changing placement. */
static int enter_secret_operation(void) {
  struct wally_operations ops = {.struct_size = sizeof(ops)};
  if (wally_get_operations(&ops) != WALLY_OK || ops.malloc_fn != policy_malloc)
    return WALLY_ERROR;
  ++secret_depth;
  return WALLY_OK;
}

#define SECRET_CALL(call)                                                      \
  do {                                                                         \
    int status = enter_secret_operation();                                     \
    if (status != WALLY_OK)                                                    \
      return status;                                                           \
    status = (call);                                                           \
    --secret_depth;                                                            \
    return status;                                                             \
  } while (0)

int kern_bip32_key_from_seed_alloc(const unsigned char *seed, size_t len,
                                   uint32_t version, uint32_t flags,
                                   struct ext_key **out) {
  if (out)
    *out = NULL;
  SECRET_CALL(bip32_key_from_seed_alloc(seed, len, version, flags, out));
}

int kern_bip32_key_from_parent_path_alloc(const struct ext_key *parent,
                                          const uint32_t *path, size_t len,
                                          uint32_t flags,
                                          struct ext_key **out) {
  if (out)
    *out = NULL;
  SECRET_CALL(bip32_key_from_parent_path_alloc(parent, path, len, flags, out));
}

int kern_bip39_mnemonic_from_bytes(const struct words *words,
                                   const unsigned char *entropy, size_t len,
                                   char **out) {
  if (out)
    *out = NULL;
  SECRET_CALL(bip39_mnemonic_from_bytes(words, entropy, len, out));
}

int kern_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                unsigned char *out, size_t len,
                                size_t *written) {
  if (written)
    *written = 0;
  SECRET_CALL(bip39_mnemonic_to_seed(mnemonic, passphrase, out, len, written));
}

int kern_bip39_mnemonic_to_seed512(const char *mnemonic, const char *passphrase,
                                   unsigned char *out, size_t len) {
  SECRET_CALL(bip39_mnemonic_to_seed512(mnemonic, passphrase, out, len));
}
