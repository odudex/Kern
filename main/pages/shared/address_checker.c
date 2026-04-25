// Address Checker — shared address verification via sweep

#include "address_checker.h"
#include "../../core/wallet.h"
#include "../../ui/dialog.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_address.h>
#include <wally_core.h>

#define SEARCH_BATCH 100

static char *checked_address = NULL;
static uint32_t search_start = 0;
static uint32_t search_limit = SEARCH_BATCH;
static void (*on_found)(void) = NULL;
static void (*on_not_found)(void) = NULL;
static lv_obj_t *progress_dialog = NULL;

static void perform_sweep(void);
static void perform_sweep_deferred(lv_timer_t *timer);

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_delete(progress_dialog);
    progress_dialog = NULL;
  }
}

static void invalid_address_cb(void) {
  if (on_not_found)
    on_not_found();
}

static void found_info_cb(void *user_data) {
  (void)user_data;
  if (on_found)
    on_found();
}

static void not_found_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    address_checker_search_more();
    return;
  }
  if (on_not_found)
    on_not_found();
}

// Sweeping up to SEARCH_BATCH receive + change addresses derives many keys
// (especially for multisig) and blocks the LVGL loop. Show a progress overlay
// first, then defer the work via a one-shot timer so LVGL can render it.
static void perform_sweep(void) {
  progress_dialog = dialog_show_progress("Verifying", "Checking addresses...",
                                         DIALOG_STYLE_FULLSCREEN);
  lv_timer_t *t = lv_timer_create(perform_sweep_deferred, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

static void perform_sweep_deferred(lv_timer_t *timer) {
  (void)timer;
  wallet_policy_t policy = wallet_get_policy();

  // Search receive addresses
  for (uint32_t i = search_start; i < search_limit; i++) {
    char *address = NULL;
    bool success;

    if (policy == WALLET_POLICY_MULTISIG)
      success = wallet_get_multisig_receive_address(i, &address);
    else
      success = wallet_get_receive_address(i, &address);

    if (!success || !address)
      continue;

    if (strcasecmp(address, checked_address) == 0) {
      wally_free_string(address);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Receive #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    wally_free_string(address);
  }

  // Search change addresses
  for (uint32_t i = search_start; i < search_limit; i++) {
    char *address = NULL;
    bool success;

    if (policy == WALLET_POLICY_MULTISIG)
      success = wallet_get_multisig_change_address(i, &address);
    else
      success = wallet_get_change_address(i, &address);

    if (!success || !address)
      continue;

    if (strcasecmp(address, checked_address) == 0) {
      wally_free_string(address);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Change #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    wally_free_string(address);
  }

  dismiss_progress();

  // Not found
  char msg[192];
  snprintf(msg, sizeof(msg),
           "Address not found in first %u addresses.\n\n"
           "(Check if loaded wallet settings match coordinator's)\n\n"
           "Search %u more?",
           search_limit, SEARCH_BATCH);
  dialog_show_confirm(msg, not_found_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

void address_checker_check(const char *raw_content, void (*found_cb)(void),
                           void (*not_found_cb)(void)) {
  address_checker_destroy();

  if (!raw_content)
    return;

  char *content = strdup(raw_content);
  if (!content)
    return;

  // Strip BIP21 "bitcoin:" URI prefix if present
  if (strncasecmp(content, "bitcoin:", 8) == 0) {
    char *query = strchr(content + 8, '?');
    size_t addr_len =
        query ? (size_t)(query - content - 8) : strlen(content + 8);
    memmove(content, content + 8, addr_len);
    content[addr_len] = '\0';
  }

  // Validate address using libwally
  const char *hrp =
      (wallet_get_network() == WALLET_NETWORK_MAINNET) ? "bc" : "tb";
  uint32_t wally_net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                           ? WALLY_NETWORK_BITCOIN_MAINNET
                           : WALLY_NETWORK_BITCOIN_TESTNET;
  unsigned char script[128];
  size_t written = 0;
  bool valid =
      (wally_addr_segwit_to_bytes(content, hrp, 0, script, sizeof(script),
                                  &written) == WALLY_OK) ||
      (wally_address_to_scriptpubkey(content, wally_net, script, sizeof(script),
                                     &written) == WALLY_OK);
  if (!valid) {
    free(content);
    dialog_show_error("Invalid address", invalid_address_cb, 0);
    return;
  }

  checked_address = content;
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = found_cb;
  on_not_found = not_found_cb;
  perform_sweep();
}

void address_checker_search_more(void) {
  search_start = search_limit;
  search_limit += SEARCH_BATCH;
  perform_sweep();
}

void address_checker_destroy(void) {
  dismiss_progress();
  if (checked_address) {
    free(checked_address);
    checked_address = NULL;
  }
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = NULL;
  on_not_found = NULL;
}
