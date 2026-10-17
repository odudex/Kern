#include "kern_wally.h"
#include "secure_memory.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#ifdef ESP_PLATFORM
#include <esp_heap_caps.h>
#endif

/* Install once, before tasks start. Only the calling thread's allocation
 * policy changes during a secret operation; no global callback swapping. */
static _Thread_local unsigned secret_depth;
static _Thread_local unsigned bulk_depth;
static void *(*default_malloc)(size_t);
static void (*default_free)(void *);

static void *policy_malloc(size_t size) {
  if (secret_depth)
    return kern_secret_alloc(size);
#ifdef ESP_PLATFORM
  /* Bulk public data: PSRAM first, internal RAM only when PSRAM is full. */
  if (bulk_depth)
    return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_DEFAULT);
#endif
  return default_malloc(size);
}

static void __attribute__((constructor)) init_secret_policy(void) {
  struct wally_operations ops = {.struct_size = sizeof(ops)};
  if (wally_get_operations(&ops) != WALLY_OK)
    abort();
  default_malloc = ops.malloc_fn;
  default_free = ops.free_fn;
  ops.malloc_fn = policy_malloc;
  if (wally_set_operations(&ops) != WALLY_OK)
    abort();
}

/* Check the hooks before every protected operation: a future allocator
 * override must fail closed instead of silently changing placement, and a
 * different free_fn would no longer release the kern_secret_alloc blocks
 * policy_malloc hands out (see kern_wally.h). */
static bool hooks_in_place(void) {
  struct wally_operations ops = {.struct_size = sizeof(ops)};
  return wally_get_operations(&ops) == WALLY_OK &&
         ops.malloc_fn == policy_malloc && ops.free_fn == default_free;
}

static int enter_secret_operation(void) {
  if (!hooks_in_place())
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

#define BULK_CALL(call)                                                        \
  do {                                                                         \
    if (!hooks_in_place())                                                     \
      return WALLY_ERROR;                                                      \
    ++bulk_depth;                                                              \
    int status = (call);                                                       \
    --bulk_depth;                                                              \
    return status;                                                             \
  } while (0)

int kern_psbt_from_bytes(const unsigned char *bytes, size_t len, uint32_t flags,
                         struct wally_psbt **out) {
  if (out)
    *out = NULL;
  BULK_CALL(wally_psbt_from_bytes(bytes, len, flags, out));
}

int kern_psbt_from_base64(const char *base64, uint32_t flags,
                          struct wally_psbt **out) {
  if (out)
    *out = NULL;
  BULK_CALL(wally_psbt_from_base64(base64, flags, out));
}

int kern_psbt_clone_alloc(const struct wally_psbt *psbt, uint32_t flags,
                          struct wally_psbt **out) {
  if (out)
    *out = NULL;
  BULK_CALL(wally_psbt_clone_alloc(psbt, flags, out));
}

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

int kern_bip39_mnemonic_validate(const struct words *words,
                                 const char *mnemonic) {
  SECRET_CALL(bip39_mnemonic_validate(words, mnemonic));
}

int kern_bip39_mnemonic_to_bytes(const struct words *words,
                                 const char *mnemonic, unsigned char *out,
                                 size_t len, size_t *written) {
  if (written)
    *written = 0;
  SECRET_CALL(bip39_mnemonic_to_bytes(words, mnemonic, out, len, written));
}

static kern_pbkdf2_sha512_fn bip39_pbkdf2;

void kern_set_bip39_pbkdf2(kern_pbkdf2_sha512_fn fn) { bip39_pbkdf2 = fn; }

int kern_bip39_mnemonic_to_seed512(const char *mnemonic, const char *passphrase,
                                   unsigned char *out, size_t len) {
  if (!bip39_pbkdf2)
    SECRET_CALL(bip39_mnemonic_to_seed512(mnemonic, passphrase, out, len));

  /* The same salt and checks as libwally's bip39_mnemonic_to_seed. */
  static const char prefix[] = "mnemonic";
  const size_t prefix_len = sizeof(prefix) - 1;
  if (!mnemonic || !out || len != BIP39_SEED_LEN_512)
    return WALLY_EINVAL;
  size_t passphrase_len = passphrase ? strlen(passphrase) : 0;
  size_t salt_len = prefix_len + passphrase_len;
  unsigned char *salt = kern_secret_alloc(salt_len);
  if (!salt)
    return WALLY_ENOMEM;
  memcpy(salt, prefix, prefix_len);
  if (passphrase_len)
    memcpy(salt + prefix_len, passphrase, passphrase_len);
  int ret = bip39_pbkdf2((const uint8_t *)mnemonic, strlen(mnemonic), salt,
                         salt_len, 2048, out, len);
  wally_bzero(salt, salt_len);
  free(salt);
  if (ret != 0) {
    wally_bzero(out, len);
    return WALLY_ERROR;
  }
  return WALLY_OK;
}
