#ifndef WALLET_H
#define WALLET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  WALLET_NETWORK_MAINNET = 0,
  WALLET_NETWORK_TESTNET = 1,
} wallet_network_t;

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
