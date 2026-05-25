#ifndef PSBT_SIGN_POLICY_H
#define PSBT_SIGN_POLICY_H

#include "../../ui/dialog.h"
#include <stdbool.h>

struct wally_psbt;

bool psbt_sign_policy_allows_review(struct wally_psbt *psbt, bool is_testnet,
                                    dialog_callback_t dismissed_cb);

#endif
