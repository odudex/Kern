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

#endif // WALLET_H
