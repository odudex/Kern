// Wallet source picker — script-type dropdown + account button + numpad
// overlay.
//
// Embedded inside a row container provided by the caller. The numpad overlay
// is created on-demand on top of the active screen and torn down by
// wallet_source_picker_destroy().

#pragma once

#include "../../core/ss_whitelist.h"
#include <lvgl.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
  WALLET_PICKER_SINGLESIG,
  WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS,
  WALLET_PICKER_MULTISIG_BIP48,
} wallet_picker_mode_t;

typedef enum {
  WALLET_BIP48_P2WSH,      // m/48'/coin'/account'/2'
  WALLET_BIP48_P2SH_P2WSH, // m/48'/coin'/account'/1'
} wallet_bip48_script_t;

typedef struct {
  uint16_t source;  // dropdown index — interpretation depends on picker mode
  uint32_t account; // unhardened account number (bounded by SS_MAX_ACCOUNT)
} wallet_source_t;

typedef void (*wallet_source_changed_cb)(const wallet_source_t *source,
                                         void *user_data);

typedef struct wallet_source_picker_s wallet_source_picker_t;

wallet_source_picker_t *wallet_source_picker_create(
    lv_obj_t *parent, wallet_picker_mode_t mode, const wallet_source_t *initial,
    wallet_source_changed_cb on_change, void *user_data);

void wallet_source_picker_get(const wallet_source_picker_t *picker,
                              wallet_source_t *out);

// Maps source<4 to its ss_script_type (singlesig modes only).
ss_script_type_t wallet_source_picker_script_type(uint16_t source);

// Maps source<2 to its BIP48 script subscript (multisig mode only).
wallet_bip48_script_t wallet_source_picker_bip48_script(uint16_t source);

void wallet_source_picker_destroy(wallet_source_picker_t *picker);
