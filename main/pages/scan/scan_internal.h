/*
 * Shared state and cross-file entry points of the scan page. Private to
 * main/pages/scan; the public page API is scan.h.
 */

#ifndef SCAN_INTERNAL_H
#define SCAN_INTERNAL_H

#include "../../core/bip322.h"
#include "../../core/message_sign.h"
#include "../../ui/menu.h"
#include "../../ui/sankey.h"
#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_psbt.h>

#define ADDRESS_INDENT_PX 20

typedef struct {
  lv_obj_t *screen;
  lv_obj_t *info_container;
  sankey_diagram_t *tx_diagram;
  void (*return_cb)(void);
  /* Invoked instead of return_cb when a signing flow runs to completion
   * (signed PSBT exported, message signature shown): lets a file-browser
   * caller send back-outs to the browser but completed flows back to home. */
  void (*complete_cb)(void);
  void (*saved_return_cb)(void);
  lv_obj_t *progress_dialog;

  struct wally_psbt *psbt;
  char *psbt_base64;
  char *signed_psbt_base64;
  bool is_testnet;
  int qr_format;
  /* Signed-PSBT export context, reset at the start of each ingest: the folder
   * a saved file is written to (where the PSBT was loaded from on SD, else the
   * card root), whether to mirror a base64 source encoding, and the original
   * SD file name (empty for QR sources) used to name "signed-<name>.<ext>". */
  char export_dir[512];
  bool source_base64;
  char source_name[128];
  ui_menu_t *export_menu;

  parsed_sign_message_t message;
  bool is_message_sign;
  bip322_request_t bip322;
  bool is_bip322;

  char *scanned_mnemonic;
} scan_ctx_t;

extern scan_ctx_t scan_ctx;

/* scan.c */
void scan_dismiss_progress(void);
void scan_defer_with_progress(const char *title, const char *text,
                              lv_timer_cb_t cb);

/* scan_review_widgets.c */
void scan_create_sign_action_row(lv_obj_t *parent, lv_event_cb_t sign_cb);
lv_obj_t *scan_create_address_label(lv_obj_t *parent, const char *address,
                                    lv_color_t highlight, int32_t pad_left);
lv_obj_t *scan_create_btc_value_row(lv_obj_t *parent, const char *prefix,
                                    uint64_t sats, lv_color_t color);
void scan_create_review_note(lv_obj_t *parent, const char *text,
                             lv_color_t color);

/* scan_psbt_review.c */
bool scan_psbt_parse_base64(const char *base64_data);
void scan_psbt_cleanup(void);
bool scan_psbt_check_mismatch(void);
void scan_psbt_resume_review(bool offer_descriptor);

/* scan_psbt_sign.c */
void scan_psbt_sign_button_cb(lv_event_t *e);
void scan_qr_viewer_return_cb(void);
void scan_export_destroy_menu(void);

/* scan_message_sign.c */
void scan_message_create_display(void);
void scan_bip322_create_display(void);

/* scan_handlers.c */
void scan_handle_descriptor(const char *descriptor_str);
void scan_handle_address(const char *content);
void scan_handle_mnemonic(const char *data, size_t len);

#endif // SCAN_INTERNAL_H
