#ifndef TEXT_INPUT_SCAN_H
#define TEXT_INPUT_SCAN_H

#include "../../ui/input_helpers.h"

typedef struct {
  ui_text_input_t *input;
  void (*hide_page)(void);
  void (*show_page)(void);
  void (*loaded_cb)(void);
} text_input_scan_cfg_t;

// Hides the page, runs the QR scanner and on success replaces the textarea
// content with the scanned text. Errors are shown with a timed dialog; cancel
// just restores the page. One scan at a time.
void text_input_scan_start(const text_input_scan_cfg_t *cfg);

#endif
