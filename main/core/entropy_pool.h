#ifndef ENTROPY_POOL_H
#define ENTROPY_POOL_H

#include <stddef.h>
#include <stdint.h>

/* Auxiliary entropy pool, folded into crypto_random_bytes() alongside the
 * hardware RNG.
 *
 * Defense in depth only. Timing-derived entropy cannot be quantified, so this
 * pool is never a reason to skip the hardware source - see the SAR ADC note in
 * crypto_random_bytes(). Because the pool is folded in by hashing it can only
 * add: a worthless pool leaves the output exactly as strong as the RNG alone.
 */

/* Seed from boot-time values. Call once, as early as possible. */
void entropy_pool_init(void);

/* Fold one sample plus the CPU cycle counter into the pool. A handful of
 * instructions, lock-free, safe from ISRs and driver callbacks. */
void entropy_pool_stir(uint32_t sample);

/* Fold the pool into buf, one hash per 32 bytes. Never weakens buf. */
void entropy_pool_mix(uint8_t *buf, size_t len);

#endif // ENTROPY_POOL_H
