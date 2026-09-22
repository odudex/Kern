#ifndef ADDRESS_CHECKER_H
#define ADDRESS_CHECKER_H

#include "../../ui/wallet_source_picker.h"
#include <stdbool.h>

/**
 * Validate and search for a Bitcoin address in the wallet.
 * Strips BIP21 prefix, validates, and sweeps receive/change addresses.
 *
 * @param raw_content  Raw scanned content (may include "bitcoin:" prefix)
 * @param found_cb     Called when address is found (user dismisses dialog)
 * @param not_found_cb Called when user cancels search or address not found
 * @param initial      Preselected picker source, or NULL to keep the last one
 */
void address_checker_check(const char *raw_content, void (*found_cb)(void),
                           void (*not_found_cb)(void),
                           const wallet_source_t *initial);

/**
 * Expand the search by 50 more addresses and continue sweeping.
 * Call from the "search more?" confirm callback when user accepts.
 */
void address_checker_search_more(void);

/**
 * Free address checker state.
 */
void address_checker_destroy(void);

#endif // ADDRESS_CHECKER_H
