#ifndef QR_FRAME_POOL_H
#define QR_FRAME_POOL_H

#include <stdbool.h>

// Ownership of a set of frame buffers a producer fills and a consumer reads,
// each at its own pace, only the newest finished frame mattering: the scanner's
// preview frames, from the camera to LVGL. Exactly one party owns a buffer:
//   FREE     nobody; the producer may take it
//   WRITING  the producer and the PPA, from acquire until the pass ends
//   READY    a finished frame the consumer has not claimed: in nobody's hands,
//            but spoken for
//   CLAIMED  the consumer, which may read it at any time
// A pointer per role is not enough once a PPA pass is asynchronous: the frame
// last submitted and the frame last finished are then different buffers, and
// the finished one must stay reserved until the consumer claims it or a newer
// frame supersedes it.
//
// With one frame claimed and one ready at most, a third buffer is always free
// or being written: the producer never waits on the consumer.
//
// Nothing here locks. Tasks and the PPA interrupt all call in, so the caller
// must serialise every call.
#define FRAME_POOL_SIZE 3

typedef enum {
  FRAME_FREE = 0,
  FRAME_WRITING,
  FRAME_READY,
  FRAME_CLAIMED,
} frame_owner_t;

typedef struct {
  frame_owner_t owner[FRAME_POOL_SIZE];
} frame_pool_t;

static inline int frame_pool_find(const frame_pool_t *pool,
                                  frame_owner_t owner) {
  for (int i = 0; i < FRAME_POOL_SIZE; i++) {
    if (pool->owner[i] == owner)
      return i;
  }
  return -1;
}

// Producer: a buffer to write, or -1 if every other one is being written.
static inline int frame_pool_acquire(frame_pool_t *pool) {
  int index = frame_pool_find(pool, FRAME_FREE);
  if (index >= 0)
    pool->owner[index] = FRAME_WRITING;
  return index;
}

// Producer: the pass never started or failed, so there is no frame.
static inline void frame_pool_abandon(frame_pool_t *pool, int index) {
  if (index >= 0 && index < FRAME_POOL_SIZE &&
      pool->owner[index] == FRAME_WRITING)
    pool->owner[index] = FRAME_FREE;
}

// Producer or PPA interrupt: the pass ended. An older frame nobody claimed is
// superseded.
static inline void frame_pool_finish(frame_pool_t *pool, int index) {
  if (index < 0 || index >= FRAME_POOL_SIZE ||
      pool->owner[index] != FRAME_WRITING)
    return;
  int stale = frame_pool_find(pool, FRAME_READY);
  if (stale >= 0)
    pool->owner[stale] = FRAME_FREE;
  pool->owner[index] = FRAME_READY;
}

// Consumer: the newest finished frame, or -1. Claiming one gives back the one
// claimed before, so the consumer must be done reading that.
static inline int frame_pool_claim(frame_pool_t *pool) {
  int index = frame_pool_find(pool, FRAME_READY);
  if (index < 0)
    return -1;
  int previous = frame_pool_find(pool, FRAME_CLAIMED);
  if (previous >= 0)
    pool->owner[previous] = FRAME_FREE;
  pool->owner[index] = FRAME_CLAIMED;
  return index;
}

static inline bool frame_pool_is_writing(const frame_pool_t *pool) {
  return frame_pool_find(pool, FRAME_WRITING) >= 0;
}

#endif
