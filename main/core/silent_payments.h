#ifndef SILENT_PAYMENTS_H
#define SILENT_PAYMENTS_H

#include "../utils/attributes.h"
#include <stdbool.h>

#define SP_SECRET_LEN 32
#define SP_PUBKEY_LEN 33

// BIP352 account keys of the loaded seed, account 0'.
// SENSITIVE: wipe with sp_keys_wipe() once used.
struct sp_keys {
  unsigned char scan_secret[SP_SECRET_LEN];
  unsigned char spend_secret[SP_SECRET_LEN];
  unsigned char scan_pubkey[SP_PUBKEY_LEN];
  unsigned char spend_pubkey[SP_PUBKEY_LEN];
};

// Derives the scan key at m/352'/coin'/0'/1'/0 and the spend key at
// m/352'/coin'/0'/0'/0, coin being 1' on test networks and 0' on mainnet.
KERN_WARN_UNUSED_RESULT bool sp_keys_derive(bool is_testnet,
                                            struct sp_keys *out);
void sp_keys_wipe(struct sp_keys *keys);

// BIP392 sp([fingerprint/352'/coin'/0']spscan1...)#checksum carrying the scan
// secret and the spend public key, as bwk prints it.
// SENSITIVE: on success *out holds the scan secret; wipe and free it with
// SECURE_FREE_STRING().
KERN_WARN_UNUSED_RESULT bool sp_descriptor_alloc(bool is_testnet, char **out);

// The sp1/tsp1 address of a scan and spend public key pair.
// On success *out must be freed with free().
KERN_WARN_UNUSED_RESULT bool sp_address_alloc(const unsigned char *scan_pubkey,
                                              const unsigned char *spend_pubkey,
                                              bool is_testnet, char **out);

#endif // SILENT_PAYMENTS_H
