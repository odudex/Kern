#ifndef SILENT_PAYMENTS_H
#define SILENT_PAYMENTS_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SP_SECRET_LEN 32
#define SP_PUBKEY_LEN 33
#define SP_SCAN_BRANCH 1
#define SP_SPEND_BRANCH 0
// BIP352 reserves label m = 0 for change
#define SP_CHANGE_LABEL 0
#define SP_PATH_DEPTH 5
// BIP352 address HRPs: testnet and signet share tsp
#define SP_HRP_MAINNET "sp"
#define SP_HRP_TESTNET "tsp"
#define SP_HRP_REGTEST "sprt"

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

// The path of our account key on `branch`: m/352'/coin'/0'/branch'/0
void sp_account_key_path(bool is_testnet, uint32_t branch,
                         uint32_t path[SP_PATH_DEPTH]);

// The keys of our spend key's account with `scan_secret` as its scan key, or
// with ours when NULL.
// SENSITIVE: wipe with sp_keys_wipe() once used.
KERN_WARN_UNUSED_RESULT bool
sp_account_keys_derive(bool is_testnet, const unsigned char *scan_secret,
                       struct sp_keys *out);

typedef enum {
  SP_ACCOUNT_OURS,          // our spend key with our scan key
  SP_ACCOUNT_FOREIGN_SCAN,  // our spend key with a scan key we do not hold
  SP_ACCOUNT_OTHER_NETWORK, // our spend key under the other network's coin
  SP_ACCOUNT_NOT_OURS,      // another master key, spend key or scan path
  SP_ACCOUNT_BAD_SCAN_KEY,  // a scan key that is not a valid secret key
  SP_ACCOUNT_ERR_KEYS,      // our keys could not be derived
} sp_account_t;

// Whose BIP-352 account the keys of master key `fingerprint` are: the spend
// key at `spend_path`, the scan key at `scan_path`, or `scan_key` (32 bytes)
// when not NULL. Our spend key is the one at index 0 of the spend branch.
sp_account_t sp_account_classify(const unsigned char *fingerprint,
                                 const uint32_t *spend_path, size_t spend_len,
                                 const uint32_t *scan_path, size_t scan_len,
                                 const unsigned char *scan_key,
                                 bool is_testnet);

// True when `path` is m/352'/coin'/0'/branch'/x, for any x.
bool sp_path_on_branch(const uint32_t *path, size_t len, bool is_testnet,
                       uint32_t branch);

// BIP392 sp([fingerprint/352'/coin'/0']spscan1...)#checksum carrying the scan
// secret and the spend public key, as bwk prints it.
// SENSITIVE: on success *out holds the scan secret; wipe and free it with
// SECURE_FREE_STRING().
KERN_WARN_UNUSED_RESULT bool sp_descriptor_alloc(bool is_testnet, char **out);

// True for a BIP392 sp() descriptor.
bool sp_descriptor_is_sp(const char *descriptor);

// True when `descriptor` is the loaded seed's own sp() descriptor, the one
// sp_descriptor_alloc() builds, its checksum aside.
bool sp_descriptor_is_ours(const char *descriptor, bool is_testnet);

// The HRP of our network's silent payment addresses, sp or tsp.
const char *sp_address_hrp(bool is_testnet);

// The address of a scan and spend public key pair under `hrp` (SP_HRP_*).
// On success *out must be freed with free().
KERN_WARN_UNUSED_RESULT bool sp_address_alloc(const unsigned char *scan_pubkey,
                                              const unsigned char *spend_pubkey,
                                              const char *hrp, char **out);

// The spend public key labelled with m: spend_pubkey + hash(scan_secret || m)*G
// (BIP352 labels).
KERN_WARN_UNUSED_RESULT bool
sp_labeled_spend_pubkey(const unsigned char *scan_secret,
                        const unsigned char *spend_pubkey, uint32_t m,
                        unsigned char *out);

typedef enum {
  SP_ADDRESS_OK,
  SP_ADDRESS_ERR_LABEL, // the label path is neither empty nor one step m >= 1
  SP_ADDRESS_ERR_KEY,   // the scan secret or the spend key is invalid
  SP_ADDRESS_ERR_ALLOC, // the address could not be allocated
} sp_address_result_t;

// The address of the account of `scan_secret` and `spend_pubkey` at
// `label_path`: empty for the base address, one step m for the address
// labelled m, encoded under `hrp` (SP_HRP_*). Label 0 is change, so it is
// refused.
// On SP_ADDRESS_OK *out must be freed with free().
KERN_WARN_UNUSED_RESULT sp_address_result_t sp_account_address_alloc(
    const unsigned char *scan_secret, const unsigned char *spend_pubkey,
    const uint32_t *label_path, size_t label_path_len, const char *hrp,
    char **out);

#endif // SILENT_PAYMENTS_H
