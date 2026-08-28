/*
 * PBKDF2-HMAC-SHA256 for the ESP32-P4.
 *
 * Two implementations behind one contract, selected by
 * CONFIG_KERN_PBKDF2_HW_SHA in crypto_pbkdf2_sha256(). Both take the same
 * arguments and return the same bytes; only the cost differs.
 */

#ifndef PBKDF2_H
#define PBKDF2_H

#include "../utils/attributes.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PSA reference. Builds a fresh HMAC per iteration, and mbedTLS's ESP port
 * takes the crypto mutex, enables the SHA bus clock and pulses the peripheral
 * reset around every hash update that crosses a block — roughly four
 * ~6800-cycle acquire/reset/release cycles wrapped around four ~1150-cycle
 * compressions.
 */
KERN_WARN_UNUSED_RESULT int
pbkdf2_psa_sha256(const uint8_t *password, size_t password_len,
                  const uint8_t *salt, size_t salt_len, uint32_t iterations,
                  uint8_t *key_out, size_t key_len);

/*
 * Accelerated. Holds the SHA peripheral across batches of iterations and
 * reloads precomputed HMAC ipad/opad midstates, so an iteration costs two
 * hardware block compressions and nothing else.
 *
 * Must not be called with the SHA/AES crypto lock already held: it acquires
 * that lock itself and the lock is not recursive.
 */
KERN_WARN_UNUSED_RESULT int
pbkdf2_hw_sha256(const uint8_t *password, size_t password_len,
                 const uint8_t *salt, size_t salt_len, uint32_t iterations,
                 uint8_t *key_out, size_t key_len);

#ifdef CONFIG_KERN_PBKDF2_SELFTEST
/*
 * Verify both implementations against known-answer vectors, diff them across
 * every boundary the accelerated path has, then time them. Prints to the
 * console; development builds only.
 */
void pbkdf2_selftest(void);
#endif

#endif /* PBKDF2_H */
