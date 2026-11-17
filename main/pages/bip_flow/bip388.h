#ifndef BIP388_H
#define BIP388_H

#include <stdbool.h>
#include <stddef.h>

// True when every @N of the BIP-388 wallet policy names one of its keys
bool bip388_policy_is_valid(const char *policy, const char *const *keys,
                            size_t key_count);

// The BIP-380 descriptor of a BIP-388 wallet policy: each @N becomes keys[N]
// and each /** becomes /<0;1>/*. NULL when the policy is not valid or out of
// memory.
char *bip388_descriptor_alloc(const char *policy, const char *const *keys,
                              size_t key_count);

#endif /* BIP388_H */
