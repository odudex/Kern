#ifndef PSBT_SIGN_POLICY_H
#define PSBT_SIGN_POLICY_H

#include "../../ui/dialog.h"
#include <stdbool.h>

struct wally_psbt;

/* load_descriptor_cb, when non-NULL, turns the expected-owned rejection into a
 * confirm offering to load a wallet descriptor on the fly; declining falls
 * back to the plain rejection dialog. NULL keeps the old behavior. */
bool psbt_sign_policy_allows_review(struct wally_psbt *psbt, bool is_testnet,
                                    dialog_callback_t dismissed_cb,
                                    void (*load_descriptor_cb)(void));

#endif
