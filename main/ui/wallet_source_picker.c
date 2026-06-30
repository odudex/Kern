// Wallet source picker — see header for shape.

#include "wallet_source_picker.h"
#include "../core/registry.h"
#include "numeric_keypad.h"
#include "theme_widgets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct wallet_source_picker_s {
  wallet_picker_mode_t mode;
  wallet_source_t state;
  wallet_source_changed_cb on_change;
  void *user_data;

  lv_obj_t *dropdown;
  lv_obj_t *account_btn;
  lv_obj_t *account_value_label;

  ui_numeric_keypad_t *account_keypad;
};

static const ss_script_type_t SINGLESIG_SCRIPT_MAP[4] = {
    SS_SCRIPT_P2WPKH,      /* 0 Native SegWit  */
    SS_SCRIPT_P2TR,        /* 1 Taproot        */
    SS_SCRIPT_P2PKH,       /* 2 Legacy         */
    SS_SCRIPT_P2SH_P2WPKH, /* 3 Nested SegWit  */
};

static const wallet_bip48_script_t BIP48_SCRIPT_MAP[2] = {
    WALLET_BIP48_P2WSH,      /* 0 Native SegWit (BIP48 subscript 2') */
    WALLET_BIP48_P2SH_P2WSH, /* 1 Nested SegWit (BIP48 subscript 1') */
};

ss_script_type_t wallet_source_picker_script_type(uint16_t source) {
  return SINGLESIG_SCRIPT_MAP[source];
}

wallet_bip48_script_t wallet_source_picker_bip48_script(uint16_t source) {
  return BIP48_SCRIPT_MAP[source];
}

static void emit_change(wallet_source_picker_t *p) {
  if (p->on_change)
    p->on_change(&p->state, p->user_data);
}

static bool source_has_account(const wallet_source_picker_t *p) {
  switch (p->mode) {
  case WALLET_PICKER_SINGLESIG:
    return true;
  case WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS:
    return p->state.source < 4;
  case WALLET_PICKER_MULTISIG_BIP48:
    return true;
  case WALLET_PICKER_MINISCRIPT:
    return false; // custom derivation comes from the page's path button
  case WALLET_PICKER_DESCRIPTORS_ONLY:
    return false; // descriptors carry their own derivation
  }
  return false;
}

static void update_account_visibility(wallet_source_picker_t *p) {
  if (!p->account_btn)
    return;
  if (source_has_account(p))
    lv_obj_clear_flag(p->account_btn, LV_OBJ_FLAG_HIDDEN);
  else
    lv_obj_add_flag(p->account_btn, LV_OBJ_FLAG_HIDDEN);
}

static void update_account_display(wallet_source_picker_t *p) {
  if (!p->account_value_label)
    return;
  char buf[16];
  snprintf(buf, sizeof(buf), "acc:%u", p->state.account);
  lv_label_set_text(p->account_value_label, buf);
}

static void account_submit_cb(uint32_t value, void *user_data) {
  wallet_source_picker_t *p = user_data;
  p->state.account = value;
  update_account_display(p);
  emit_change(p);
}

static void account_btn_cb(lv_event_t *e) {
  wallet_source_picker_t *p = lv_event_get_user_data(e);
  ui_numeric_keypad_config_t config = {
      .title = "Account",
      .initial_value = p->state.account,
      .max_value = SS_MAX_ACCOUNT - 1,
      .max_digits = 2,
      .invalid_message = NULL,
      .submit_cb = account_submit_cb,
      .user_data = p,
  };
  ui_numeric_keypad_open(&p->account_keypad, &config);
}

static void dropdown_cb(lv_event_t *e) {
  wallet_source_picker_t *p = lv_event_get_user_data(e);
  p->state.source = lv_dropdown_get_selected(p->dropdown);
  update_account_visibility(p);
  emit_change(p);
}

static void build_options(wallet_picker_mode_t mode, char *out, size_t out_sz) {
  switch (mode) {
  case WALLET_PICKER_SINGLESIG:
    snprintf(out, out_sz, "Native SegWit\nTaproot\nLegacy\nNested SegWit");
    return;
  case WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS: {
    size_t written = (size_t)snprintf(
        out, out_sz, "Native SegWit\nTaproot\nLegacy\nNested SegWit");
    size_t reg_count = registry_count();
    for (size_t ri = 0; ri < reg_count && written < out_sz - 1; ri++) {
      const registry_entry_t *entry = registry_get(ri);
      const char *label = entry->label[0] ? entry->label : entry->id;
      int n = snprintf(out + written, out_sz - written, "\n%s", label);
      if (n > 0)
        written += (size_t)n;
    }
    return;
  }
  case WALLET_PICKER_MULTISIG_BIP48:
    snprintf(out, out_sz, "Native SegWit\nNested SegWit");
    return;
  case WALLET_PICKER_MINISCRIPT:
    snprintf(out, out_sz, "Native SegWit\nTaproot");
    return;
  case WALLET_PICKER_DESCRIPTORS_ONLY: {
    size_t written = 0;
    size_t reg_count = registry_count();
    for (size_t ri = 0; ri < reg_count && written < out_sz - 1; ri++) {
      const registry_entry_t *entry = registry_get(ri);
      const char *label = entry->label[0] ? entry->label : entry->id;
      int n = snprintf(out + written, out_sz - written, ri == 0 ? "%s" : "\n%s",
                       label);
      if (n > 0)
        written += (size_t)n;
    }
    if (written == 0)
      snprintf(out, out_sz, " ");
    return;
  }
  }
}

wallet_source_picker_t *wallet_source_picker_create(
    lv_obj_t *parent, wallet_picker_mode_t mode, const wallet_source_t *initial,
    wallet_source_changed_cb on_change, void *user_data) {
  if (!parent)
    return NULL;

  wallet_source_picker_t *p = calloc(1, sizeof(*p));
  if (!p)
    return NULL;

  p->mode = mode;
  p->state.source = initial ? initial->source : 0;
  p->state.account = initial ? initial->account : 0;
  p->on_change = on_change;
  p->user_data = user_data;

  char source_opts[600];
  build_options(mode, source_opts, sizeof(source_opts));

  p->dropdown = theme_create_dropdown(parent, source_opts);
  lv_obj_set_width(p->dropdown, LV_PCT(72));
  if (p->state.source > 0)
    lv_dropdown_set_selected(p->dropdown, p->state.source);
  lv_obj_add_event_cb(p->dropdown, dropdown_cb, LV_EVENT_VALUE_CHANGED, p);

  p->account_btn = lv_btn_create(parent);
  theme_apply_touch_button(p->account_btn, false);
  // Match the dropdown height so the row stays as short as the dropdown
  // alone; the button's own padded content would be slightly taller.
  lv_obj_update_layout(p->dropdown);
  lv_obj_set_size(p->account_btn, LV_PCT(25), lv_obj_get_height(p->dropdown));
  p->account_value_label = lv_label_create(p->account_btn);
  lv_obj_set_style_text_font(p->account_value_label, theme_font_small(), 0);
  lv_obj_center(p->account_value_label);
  lv_obj_add_event_cb(p->account_btn, account_btn_cb, LV_EVENT_CLICKED, p);
  update_account_display(p);
  update_account_visibility(p);

  return p;
}

void wallet_source_picker_get(const wallet_source_picker_t *picker,
                              wallet_source_t *out) {
  if (!picker || !out)
    return;
  *out = picker->state;
}

void wallet_source_picker_destroy(wallet_source_picker_t *picker) {
  if (!picker)
    return;
  ui_numeric_keypad_close(&picker->account_keypad);
  // Explicitly delete the widgets so callers can recreate the picker into the
  // same parent row (e.g. the public-key page's multisig toggle). Otherwise
  // the new dropdown / account button would stack on top of the old ones.
  if (picker->dropdown)
    lv_obj_del(picker->dropdown);
  if (picker->account_btn)
    lv_obj_del(picker->account_btn);
  free(picker);
}
