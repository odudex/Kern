#ifndef WALLET_H
#define WALLET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  WALLET_NETWORK_MAINNET = 0,
  WALLET_NETWORK_TESTNET = 1,
} wallet_network_t;

/* Maximum descriptor/miniscript nesting depth accepted when parsing. The
 * descriptor-string parser is the one unbounded-recursion path, so every parse
 * bounds it (BIP-341 allows up to 128 taptree levels; real policies nest far
 * less). Tunable: raise if a legitimate descriptor ever fails to parse. */
#define KERN_DESCRIPTOR_MAX_DEPTH 32

struct wally_descriptor;
struct wally_map;

/* Parse an output descriptor with Kern's standard flags. Identical to
 * wally_descriptor_parse() except the recursion depth is capped at
 * KERN_DESCRIPTOR_MAX_DEPTH. Returns the libwally result code (WALLY_OK on
 * success); on success *output owns the descriptor (free with
 * wally_descriptor_free). */
int wallet_descriptor_parse(const char *descriptor,
                            const struct wally_map *vars_in, uint32_t network,
                            struct wally_descriptor **output);

bool wallet_init(wallet_network_t network);
bool wallet_is_initialized(void);
wallet_network_t wallet_get_network(void);
void wallet_cleanup(void);
void wallet_unload(void);

/* Watch-only session: a keyless mode for viewing a descriptor's addresses
 * without a loaded master key. Independent of wallet_is_initialized() (which
 * still implies a loaded key); only the addresses page honors it. */
void wallet_set_watch_only(wallet_network_t network);
bool wallet_is_watch_only(void);
void wallet_clear_watch_only(void);

#endif // WALLET_H
