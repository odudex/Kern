#pragma once
#include <wally_bip32.h>
#include <wally_bip39.h>

/* These operations require internal RAM for ALL their libwally allocations,
 * including temporary salt/word/key storage. Ordinary public-data operations
 * keep libwally's default allocator. Do not replace wally's malloc callback.
 *
 * libwally's free_fn stays libc free(), which releases any heap block, from
 * kern_secret_alloc or not. Kern relies on that: strings from libwally and
 * from strdup or kern_secret_strdup are released with either free() or
 * wally_free_string(). The secret operations below fail closed if free_fn
 * ever changes. */
int kern_bip32_key_from_seed_alloc(const unsigned char *seed, size_t len,
                                   uint32_t version, uint32_t flags,
                                   struct ext_key **out);
int kern_bip32_key_from_parent_path_alloc(const struct ext_key *parent,
                                          const uint32_t *path, size_t len,
                                          uint32_t flags, struct ext_key **out);
int kern_bip39_mnemonic_from_bytes(const struct words *words,
                                   const unsigned char *entropy, size_t len,
                                   char **out);
/* Both copy the mnemonic internally. From _to_bytes, WALLY_ENOMEM means no
 * internal RAM, not an invalid mnemonic; _validate returns WALLY_EINVAL for
 * both. */
int kern_bip39_mnemonic_validate(const struct words *words,
                                 const char *mnemonic);
int kern_bip39_mnemonic_to_bytes(const struct words *words,
                                 const char *mnemonic, unsigned char *out,
                                 size_t len, size_t *written);
int kern_bip39_mnemonic_to_seed512(const char *mnemonic, const char *passphrase,
                                   unsigned char *out, size_t len);
