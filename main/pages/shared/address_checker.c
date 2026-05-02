// Address Checker — shared address verification via sweep

#include "address_checker.h"
#include "../../core/registry.h"
#include "../../core/ss_whitelist.h"
#include "../../core/wallet.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include "wallet_source_picker.h"
#include <lvgl.h>
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

// Source picker state — persists between invocations (page-scoped)
static wallet_source_t ac_source = {0, 0};

static lv_obj_t *ac_overlay = NULL;
static wallet_source_picker_t *ac_picker = NULL;

static void perform_sweep(void);
static void perform_sweep_deferred(lv_timer_t *timer);
static void show_source_picker(void);
static void destroy_source_picker(void);

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_delete(progress_dialog);
    progress_dialog = NULL;
  }
}

static void ac_picker_changed_cb(const wallet_source_t *src, void *user_data) {
  (void)user_data;
  ac_source = *src;
}

static void destroy_source_picker(void) {
  wallet_source_picker_destroy(ac_picker);
  ac_picker = NULL;
  if (ac_overlay) {
    lv_obj_del(ac_overlay);
    ac_overlay = NULL;
  }
}

static void ac_verify_btn_cb(lv_event_t *e) {
  (void)e;
  destroy_source_picker();
  search_start = 0;
  search_limit = SEARCH_BATCH;
  perform_sweep();
}

static void show_source_picker(void) {
  ac_overlay = lv_obj_create(lv_screen_active());
  lv_obj_set_size(ac_overlay, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(ac_overlay);
  lv_obj_set_style_pad_all(ac_overlay, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(ac_overlay, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(ac_overlay, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(ac_overlay, theme_get_default_padding(), 0);

  lv_obj_t *picker_row = lv_obj_create(ac_overlay);
  lv_obj_set_size(picker_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(picker_row);
  lv_obj_set_flex_flow(picker_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(picker_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  ac_picker = wallet_source_picker_create(
      picker_row, WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS, &ac_source,
      ac_picker_changed_cb, NULL);

  lv_obj_t *verify_btn = lv_btn_create(ac_overlay);
  lv_obj_set_size(verify_btn, LV_PCT(60), LV_SIZE_CONTENT);
  theme_apply_touch_button(verify_btn, false);
  lv_obj_t *verify_lbl = lv_label_create(verify_btn);
  lv_label_set_text(verify_lbl, "Verify");
  lv_obj_center(verify_lbl);
  theme_apply_button_label(verify_lbl, false);
  lv_obj_add_event_cb(verify_btn, ac_verify_btn_cb, LV_EVENT_CLICKED, NULL);
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
  bool is_testnet = (wallet_get_network() == WALLET_NETWORK_TESTNET);
  const registry_entry_t *reg_entry = NULL;

  if (ac_source.source >= 4) {
    reg_entry = registry_get((size_t)(ac_source.source - 4));
    if (!reg_entry) {
      dismiss_progress();
      if (on_not_found)
        on_not_found();
      return;
    }
  }

  // Search receive addresses (chain = 0)
  for (uint32_t i = search_start; i < search_limit; i++) {
    char addr_buf[SS_ADDRESS_MAX_LEN];
    char *dyn = NULL;
    bool success = false;

    if (reg_entry) {
      uint32_t mp = 0;
      int ret = wally_descriptor_to_address(reg_entry->desc, 0, mp, i, 0, &dyn);
      success = (ret == WALLY_OK) && dyn;
    } else {
      // Fixed account: user selected it in the picker; do not iterate accounts.
      ss_script_type_t script =
          wallet_source_picker_script_type(ac_source.source);
      success = ss_address(script, ac_source.account, 0, i, is_testnet,
                           addr_buf, sizeof(addr_buf));
    }
    if (!success)
      continue;

    const char *addr = dyn ? dyn : addr_buf;
    if (strcasecmp(addr, checked_address) == 0) {
      if (dyn)
        wally_free_string(dyn);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Receive #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    if (dyn) {
      wally_free_string(dyn);
      dyn = NULL;
    }
  }

  // Search change addresses (chain = 1)
  for (uint32_t i = search_start; i < search_limit; i++) {
    char addr_buf[SS_ADDRESS_MAX_LEN];
    char *dyn = NULL;
    bool success = false;

    if (reg_entry) {
      uint32_t mp = (reg_entry->num_paths <= 1) ? 0 : 1;
      int ret = wally_descriptor_to_address(reg_entry->desc, 0, mp, i, 0, &dyn);
      success = (ret == WALLY_OK) && dyn;
    } else {
      // Fixed account: same rationale as receive loop above.
      ss_script_type_t script =
          wallet_source_picker_script_type(ac_source.source);
      success = ss_address(script, ac_source.account, 1, i, is_testnet,
                           addr_buf, sizeof(addr_buf));
    }
    if (!success)
      continue;

    const char *addr = dyn ? dyn : addr_buf;
    if (strcasecmp(addr, checked_address) == 0) {
      if (dyn)
        wally_free_string(dyn);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Change #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    if (dyn) {
      wally_free_string(dyn);
      dyn = NULL;
    }
  }

  dismiss_progress();

  // Not found — offer to search another batch
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
  show_source_picker();
}

void address_checker_search_more(void) {
  search_start = search_limit;
  search_limit += SEARCH_BATCH;
  perform_sweep();
}

void address_checker_destroy(void) {
  dismiss_progress();
  destroy_source_picker();
  if (checked_address) {
    free(checked_address);
    checked_address = NULL;
  }
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = NULL;
  on_not_found = NULL;
  // ac_source intentionally NOT reset — persist session selection
}
