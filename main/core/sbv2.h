/*
 * Secure Boot v2 (RSA-3072) signature sector checks against a chosen key
 * digest, independent of eFuse state: lets the firmware confirm an image will
 * pass the ROM's boot check before that digest is burned.
 */

#ifndef SBV2_H
#define SBV2_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SBV2_SECTOR_SIZE 4096
#define SBV2_DIGEST_LEN 32

/* Offset of the signature sector that follows an image of image_len bytes */
size_t sbv2_sector_offset(size_t image_len);

/* True if a block in the signature sector covers image_digest, carries the
 * public key whose Secure Boot digest is key_digest, and its RSA-PSS
 * signature verifies. */
KERN_WARN_UNUSED_RESULT bool
sbv2_signed_by(const uint8_t sector[SBV2_SECTOR_SIZE],
               const uint8_t image_digest[SBV2_DIGEST_LEN],
               const uint8_t key_digest[SBV2_DIGEST_LEN]);

#endif // SBV2_H
