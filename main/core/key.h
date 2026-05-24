#ifndef KEY_H
#define KEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_bip32.h>

bool key_init(void);
bool key_is_loaded(void);
bool key_load_from_mnemonic(const char *mnemonic, const char *passphrase,
                            bool is_testnet);
void key_unload(void);

/* Caller-provided buffer of BIP32_KEY_FINGERPRINT_LEN (4) bytes. */
bool key_get_fingerprint(unsigned char *fingerprint_out);
/* Caller-provided buffer of BIP32_KEY_FINGERPRINT_LEN*2 + 1 (9) bytes. */
bool key_get_fingerprint_hex(char *hex_out);
bool key_mnemonic_fingerprint_hex(const char *mnemonic, char *hex_out);

/* On success, *xpub_out is heap-allocated and must be freed by the caller
 * with wally_free_string(). Public-only -- safe to log. */
bool key_get_xpub(const char *path, char **xpub_out);
bool key_get_master_xpub(char **xpub_out);

/* On success, *mnemonic_out is a heap-allocated copy of the active mnemonic.
 * SENSITIVE: caller must wipe and free with SECURE_FREE_STRING(). */
bool key_get_mnemonic(char **mnemonic_out);

/* On success, *words_out is a heap-allocated array of *word_count_out
 * strdup'd words. SENSITIVE: caller must SECURE_FREE_STRING() each word, then
 * free() the array. */
bool key_get_mnemonic_words(char ***words_out, size_t *word_count_out);

/* On success, *key_out is a wally-allocated ext_key holding the derived
 * PRIVATE key material. Caller must free with bip32_key_free(), which
 * zeroizes the private bytes before releasing the allocation. */
bool key_get_derived_key(const char *path, struct ext_key **key_out);
bool key_get_derived_key_components(const uint32_t *path, size_t path_depth,
                                    struct ext_key **key_out);

void key_cleanup(void);

#endif // KEY_H
