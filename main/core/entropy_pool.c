#include "entropy_pool.h"

#include "../utils/secure_mem.h"
#include "crypto_utils.h"

#include <string.h>

#include <esp_cpu.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_timer.h>

#define POOL_WORDS 8

// The ratchet refills the whole pool from a single digest, so the two must be
// the same size; widening the pool without revisiting it would overread.
_Static_assert(sizeof(uint32_t) * POOL_WORDS == CRYPTO_SHA256_SIZE,
               "pool must be exactly one SHA-256 digest wide");

static uint32_t pool[POOL_WORDS];
static uint32_t pool_index;

// Relaxed atomics, not volatile: volatile grants neither atomicity nor freedom
// from data races, and the pool is written from camera callbacks while
// entropy_pool_mix() reads it. On this target these compile to the same plain
// load and store, so the guarantee costs nothing.
static inline uint32_t pool_load(size_t i) {
  return __atomic_load_n(&pool[i], __ATOMIC_RELAXED);
}

static inline void pool_store(size_t i, uint32_t word) {
  __atomic_store_n(&pool[i], word, __ATOMIC_RELAXED);
}

void entropy_pool_stir(uint32_t sample) {
  uint32_t i =
      __atomic_fetch_add(&pool_index, 1, __ATOMIC_RELAXED) % POOL_WORDS;
  uint32_t word = pool_load(i);
  // A racing stir can still only drop a sample, never corrupt the pool, so
  // callbacks stay lock-free.
  pool_store(i,
             ((word << 7) | (word >> 25)) ^ sample ^ esp_cpu_get_cycle_count());
}

void entropy_pool_init(void) {
  entropy_pool_stir((uint32_t)(uintptr_t)&pool);
  entropy_pool_stir((uint32_t)esp_reset_reason());
  entropy_pool_stir((uint32_t)esp_timer_get_time());

  // Whatever the RNG holds this early is still the bootloader's seeding.
  uint32_t boot[POOL_WORDS];
  esp_fill_random(boot, sizeof(boot));
  for (size_t i = 0; i < POOL_WORDS; i++)
    entropy_pool_stir(boot[i]);
  secure_memzero(boot, sizeof(boot));
}

void entropy_pool_mix(uint8_t *buf, size_t len) {
  if (!buf || len == 0)
    return;

  entropy_pool_stir((uint32_t)len);

  uint8_t input[sizeof(uint32_t) * POOL_WORDS + CRYPTO_SHA256_SIZE +
                sizeof(uint32_t)];
  uint8_t digest[CRYPTO_SHA256_SIZE];
  uint32_t counter = 0;

  for (size_t offset = 0; offset < len; offset += CRYPTO_SHA256_SIZE) {
    size_t chunk = len - offset;
    if (chunk > CRYPTO_SHA256_SIZE)
      chunk = CRYPTO_SHA256_SIZE;

    size_t n = 0;
    for (size_t i = 0; i < POOL_WORDS; i++) {
      uint32_t word = pool_load(i);
      memcpy(input + n, &word, sizeof(word));
      n += sizeof(word);
    }
    memcpy(input + n, buf + offset, chunk);
    n += chunk;
    memcpy(input + n, &counter, sizeof(counter));
    n += sizeof(counter);

    // On failure leave the raw RNG bytes in place - still full strength.
    if (crypto_sha256(input, n, digest) != CRYPTO_OK)
      break;

    memcpy(buf + offset, digest, chunk);
    counter++;
  }

  // Ratchet. Rotate-XOR is invertible, so without this a later read of the
  // pool would expose the state that produced the bytes just handed out.
  // Hashing here rather than in entropy_pool_stir() keeps the cost off the
  // camera path: extraction is rare, stirring runs on every frame.
  size_t n = 0;
  for (size_t i = 0; i < POOL_WORDS; i++) {
    uint32_t word = pool_load(i);
    memcpy(input + n, &word, sizeof(word));
    n += sizeof(word);
  }
  memcpy(input + n, &counter, sizeof(counter));
  n += sizeof(counter);

  if (crypto_sha256(input, n, digest) == CRYPTO_OK) {
    for (size_t i = 0; i < POOL_WORDS; i++) {
      uint32_t word;
      memcpy(&word, digest + i * sizeof(word), sizeof(word));
      pool_store(i, word);
    }
  }

  secure_memzero(input, sizeof(input));
  secure_memzero(digest, sizeof(digest));
}
