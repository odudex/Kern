#ifndef BIP138_BACKUP_H
#define BIP138_BACKUP_H

#include "../utils/attributes.h"
#include "bip138_keys.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Largest backup the recovery path will read. */
#define BIP138_BACKUP_MAX_LEN (32 * 1024)
/* Distinct container derivation paths tried during recovery: one per key
 * expression of a descriptor, which is capped at 26 keys. */
#define BIP138_BACKUP_MAX_PATHS 32

/* BIP138 container holding the descriptor, addressed to the descriptor's own
 * root keys, with every key's origin path stored as a recovery hint and this
 * device's approval mark (an HMAC under a key only this seed can derive).
 * Refuses descriptors carrying private keys. *blob_out is malloc'd; the caller
 * frees it. */
KERN_WARN_UNUSED_RESULT bool bip138_backup_encrypt(const char *descriptor,
                                                   uint8_t **blob_out,
                                                   size_t *blob_len);

/* Recovers the descriptor with the loaded key, trying the container's paths
 * and then the BIP's common paths. *approved_out (optional) is true only when
 * the backup carries a valid approval mark from this seed, i.e. this device
 * wrote it after the user confirmed the descriptor; a backup from another
 * wallet, or one forged from a public xpub, decrypts with approved false.
 * *descriptor_out is malloc'd and NUL-terminated; free it with
 * SECURE_FREE_STRING. */
KERN_WARN_UNUSED_RESULT bool bip138_backup_decrypt(const uint8_t *blob,
                                                   size_t blob_len,
                                                   char **descriptor_out,
                                                   bool *approved_out);

/* Accepts either the binary container or its base64 text. */
KERN_WARN_UNUSED_RESULT bool bip138_backup_decrypt_any(const uint8_t *data,
                                                       size_t len,
                                                       char **descriptor_out,
                                                       bool *approved_out);

/* Same, trying only the paths the container itself stores, never the common
 * paths. A backup this device registered stores the origin of every key it
 * holds, so the boot scan needs nothing more, and a backup the loaded key
 * cannot open (another seed's, or every backup when the passphrase is not yet
 * applied) costs one derivation per stored path instead of a walk of all 140
 * common paths. */
KERN_WARN_UNUSED_RESULT bool
bip138_backup_decrypt_any_hinted(const uint8_t *data, size_t len,
                                 char **descriptor_out, bool *approved_out);

/* True for a binary container or its base64 text form. */
bool bip138_backup_detect(const uint8_t *data, size_t len);

/* Wipes the loaded key's cached common-path public keys. Called when the
 * wallet is unloaded, since they describe the seed that was loaded. */
void bip138_backup_forget_keys(void);

#ifdef BIP138_BACKUP_TESTING
bool bip138_backup_cache_is_empty(void);
#endif

#endif // BIP138_BACKUP_H
