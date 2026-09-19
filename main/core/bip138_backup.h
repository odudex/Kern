#ifndef BIP138_BACKUP_H
#define BIP138_BACKUP_H

#include "../utils/attributes.h"
#include "bip138_keys.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Largest backup the recovery path will read. */
#define BIP138_BACKUP_MAX_LEN (32 * 1024)
/* Distinct container derivation paths tried during recovery. */
#define BIP138_BACKUP_MAX_PATHS BIP138_KEYS_MAX

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

/* Base64 text form of bip138_backup_encrypt; *base64_out is malloc'd. */
KERN_WARN_UNUSED_RESULT bool bip138_backup_encrypt_text(const char *descriptor,
                                                        char **base64_out);

/* Accepts either the binary container or its base64 text. */
KERN_WARN_UNUSED_RESULT bool bip138_backup_decrypt_any(const uint8_t *data,
                                                       size_t len,
                                                       char **descriptor_out,
                                                       bool *approved_out);

bool bip138_backup_is_container(const uint8_t *data, size_t len);

/* True for a binary container or its base64 text form. */
bool bip138_backup_detect(const uint8_t *data, size_t len);

#endif // BIP138_BACKUP_H
