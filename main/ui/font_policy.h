#ifndef FONT_POLICY_H
#define FONT_POLICY_H

#include <stdint.h>

typedef struct {
  uint16_t small_px;
  uint16_t medium_px;
} ui_font_policy_t;

ui_font_policy_t ui_font_policy_for_display(uint32_t width, uint32_t height);

#endif // FONT_POLICY_H
