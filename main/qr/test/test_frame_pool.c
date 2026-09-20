#include "../frame_pool.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

// What is physically happening to the buffers, tracked apart from the pool's
// own bookkeeping so the two can be checked against each other.
typedef struct {
  frame_pool_t pool;
  int in_flight[FRAME_POOL_SIZE]; // buffers PPA passes are filling, in order
  int in_flight_count;
  int consumer_reading; // buffer the consumer has been given, or -1
  bool frame_intact[FRAME_POOL_SIZE]; // holds a whole, finished frame
} world_t;

static void check_invariants(const world_t *w) {
  int count[4] = {0};
  for (int i = 0; i < FRAME_POOL_SIZE; i++)
    count[w->pool.owner[i]]++;
  assert(count[FRAME_WRITING] == w->in_flight_count);
  assert(count[FRAME_READY] <= 1);
  assert(count[FRAME_CLAIMED] <= 1);
  assert(frame_pool_is_writing(&w->pool) == (w->in_flight_count > 0));

  // The PPA never writes what the consumer may be reading, nor one buffer
  // twice, and what the consumer reads stays a whole frame until it claims
  // the next.
  for (int i = 0; i < w->in_flight_count; i++) {
    assert(w->in_flight[i] != w->consumer_reading);
    for (int j = 0; j < i; j++)
      assert(w->in_flight[i] != w->in_flight[j]);
  }
  assert(w->consumer_reading < 0 || w->frame_intact[w->consumer_reading]);
}

typedef enum { SUBMIT, SUBMIT_FAILS, COMPLETE, CLAIM, EVENT_COUNT } event_t;

static void apply(world_t *w, event_t event) {
  switch (event) {
  case SUBMIT:
  case SUBMIT_FAILS: {
    // The firmware queues one pass per pool at a time, but the pool must hold
    // whatever the call order, so passes may pile up here.
    int index = frame_pool_acquire(&w->pool);
    // One claimed and one ready at most: with nothing in flight, one of three
    // is always free.
    assert(index >= 0 || w->in_flight_count > 0);
    if (index < 0)
      return;
    if (event == SUBMIT_FAILS) {
      frame_pool_abandon(&w->pool, index);
      return;
    }
    w->frame_intact[index] = false; // the PPA starts overwriting it
    w->in_flight[w->in_flight_count++] = index;
    return;
  }
  case COMPLETE: {
    // The PPA runs its passes in the order they were queued.
    if (w->in_flight_count == 0)
      return;
    int index = w->in_flight[0];
    for (int i = 1; i < w->in_flight_count; i++)
      w->in_flight[i - 1] = w->in_flight[i];
    w->in_flight_count--;
    w->frame_intact[index] = true;
    frame_pool_finish(&w->pool, index);
    return;
  }
  case CLAIM: {
    int index = frame_pool_claim(&w->pool);
    if (index < 0)
      return;
    // A claimed frame was never handed back out between finishing and now.
    assert(w->frame_intact[index]);
    w->consumer_reading = index;
    return;
  }
  default:
    return;
  }
}

static long explored;

static void explore(const world_t *w, int depth) {
  explored++;
  check_invariants(w);
  if (depth == 0)
    return;
  for (int event = 0; event < EVENT_COUNT; event++) {
    world_t next = *w;
    apply(&next, (event_t)event);
    explore(&next, depth - 1);
  }
}

static void test_every_interleaving(void) {
  world_t w = {.consumer_reading = -1};
  explore(&w, 10);
  assert(explored > 1000000);
}

// A claimed, B finished but unclaimed, C being written: B must not be handed
// out, or the consumer could claim it just before the PPA overwrites it.
static void test_unclaimed_frame_stays_reserved(void) {
  frame_pool_t pool = {0};
  int a = frame_pool_acquire(&pool);
  frame_pool_finish(&pool, a);
  assert(frame_pool_claim(&pool) == a);

  int b = frame_pool_acquire(&pool);
  frame_pool_finish(&pool, b);
  int c = frame_pool_acquire(&pool);
  assert(a != b && b != c && a != c);
  assert(pool.owner[a] == FRAME_CLAIMED && pool.owner[b] == FRAME_READY &&
         pool.owner[c] == FRAME_WRITING);

  assert(frame_pool_acquire(&pool) == -1);

  // C finishing supersedes B, which only then becomes writable again.
  frame_pool_finish(&pool, c);
  assert(pool.owner[b] == FRAME_FREE && pool.owner[c] == FRAME_READY);
  assert(frame_pool_claim(&pool) == c);
  assert(pool.owner[a] == FRAME_FREE && pool.owner[c] == FRAME_CLAIMED);
  assert(frame_pool_claim(&pool) == -1);
}

static void test_out_of_order_calls_change_nothing(void) {
  frame_pool_t pool = {0};
  frame_pool_t untouched = pool;
  frame_pool_finish(&pool, 0); // not being written
  frame_pool_abandon(&pool, 1);
  frame_pool_finish(&pool, -1);
  frame_pool_finish(&pool, FRAME_POOL_SIZE);
  frame_pool_abandon(&pool, FRAME_POOL_SIZE);
  assert(memcmp(&pool, &untouched, sizeof(pool)) == 0);

  int index = frame_pool_acquire(&pool);
  frame_pool_finish(&pool, index);
  frame_pool_abandon(&pool, index); // finished, no longer abandonable
  assert(pool.owner[index] == FRAME_READY);
}

int main(void) {
  test_unclaimed_frame_stays_reserved();
  test_out_of_order_calls_change_nothing();
  test_every_interleaving();
  puts("All frame pool tests passed.");
  return 0;
}
