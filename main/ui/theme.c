#include "theme.h"
#include "font_policy.h"
#if !defined(ICONS_16) || ICONS_16
#include "assets/icons_16.h"
#endif
#if !defined(ICONS_24) || ICONS_24
#include "assets/icons_24.h"
#endif
#if !defined(ICONS_36) || ICONS_36
#include "assets/icons_36.h"
#endif
#include "theme_palette.h"

// Mutable font copies with icon fallbacks
static lv_font_t font_small;
static lv_font_t font_medium;

// Cached screen dimensions and derived sizes (set once in theme_init)
static int32_t scr_w;
static int32_t scr_h;
static int32_t scr_min_dim;
static int sz_button_width;
static int sz_button_height;
static int sz_button_spacing;
static int sz_default_padding;
static int sz_min_touch;
static int sz_corner_button_width;
static int sz_corner_button_height;
static int sz_small_padding;
static int sz_logo;

typedef struct {
  const lv_font_t *text;
  const lv_font_t *icon;
} theme_font_pair_t;

static theme_font_pair_t font_pair_for_size(uint16_t size) {
  switch (size) {
#if LV_FONT_MONTSERRAT_16 && (!defined(ICONS_16) || ICONS_16)
  case 16:
    return (theme_font_pair_t){&lv_font_montserrat_16, &icons_16};
#endif
#if LV_FONT_MONTSERRAT_24 && (!defined(ICONS_24) || ICONS_24)
  case 24:
    return (theme_font_pair_t){&lv_font_montserrat_24, &icons_24};
#endif
#if LV_FONT_MONTSERRAT_36 && (!defined(ICONS_36) || ICONS_36)
  case 36:
    return (theme_font_pair_t){&lv_font_montserrat_36, &icons_36};
#endif
  default:
#if LV_FONT_MONTSERRAT_24 && (!defined(ICONS_24) || ICONS_24)
    return (theme_font_pair_t){&lv_font_montserrat_24, &icons_24};
#else
#error "theme requires LV_FONT_MONTSERRAT_24 and icons_24"
#endif
  }
}

void theme_init(void) {
  scr_w = lv_disp_get_hor_res(NULL);
  scr_h = lv_disp_get_ver_res(NULL);
  scr_min_dim = scr_w < scr_h ? scr_w : scr_h;

  // All sizes scale with min_dim, the shorter axis: in portrait it is the width
  // (so portrait boards keep their sizes), while on landscape it caps paddings
  // and controls to the short side rather than letting the wide axis bloat
  // them.
  sz_button_width = scr_min_dim * 5 / 24;    // 150
  sz_button_height = scr_min_dim * 5 / 36;   // 100
  sz_button_spacing = scr_min_dim / 36;      //  20
  sz_default_padding = scr_min_dim / 24;     //  30
  sz_min_touch = scr_min_dim / 8;            //  90
  sz_corner_button_width = scr_min_dim / 6;  // 120
  sz_corner_button_height = scr_min_dim / 8; //  90
  sz_small_padding = scr_min_dim / 72;       //  10
  sz_logo = scr_min_dim * 5 / 18;            // 200

  ui_font_policy_t policy = ui_font_policy_for_display(scr_w, scr_h);
  theme_font_pair_t small = font_pair_for_size(policy.small_px);
  theme_font_pair_t medium = font_pair_for_size(policy.medium_px);

  font_small = *small.text;
  font_small.fallback = small.icon;

  font_medium = *medium.text;
  font_medium.fallback = medium.icon;
}

lv_color_t bg_color(void) { return COLOR_BG; }

lv_color_t primary_color(void) { return COLOR_WHITE; }

lv_color_t secondary_color(void) { return COLOR_GRAY; }

lv_color_t highlight_color(void) { return COLOR_ORANGE; }

lv_color_t disabled_color(void) { return COLOR_SURFACE; }

lv_color_t panel_color(void) { return COLOR_PANEL; }

lv_color_t error_color(void) { return COLOR_RED; }

// Action-choice colors: green encourages a choice, red discourages it. The
// label ("Yes"/"No") is independent of which choice is encouraged — e.g. a
// danger dialog encourages "No" and discourages "Yes".
lv_color_t encourage_color(void) { return COLOR_GREEN; }

lv_color_t discourage_color(void) { return COLOR_RED; }

// State/value colors: green for a good value, red for a bad one (battery level,
// password strength, change outputs, etc.).
lv_color_t good_color(void) { return COLOR_GREEN; }

lv_color_t bad_color(void) { return COLOR_RED; }

lv_color_t accent_color(void) { return COLOR_CYAN; }

// Theme fonts
const lv_font_t *theme_font_small(void) { return &font_small; }

const lv_font_t *theme_font_medium(void) { return &font_medium; }

int theme_screen_width(void) { return scr_w; }
int theme_screen_height(void) { return scr_h; }
int theme_min_dim(void) { return scr_min_dim; }
bool theme_is_landscape(void) { return scr_w >= scr_h; }

int theme_button_width(void) { return sz_button_width; }
int theme_button_height(void) { return sz_button_height; }
int theme_button_spacing(void) { return sz_button_spacing; }
int theme_default_padding(void) { return sz_default_padding; }
int theme_min_touch_size(void) { return sz_min_touch; }
int theme_corner_button_width(void) { return sz_corner_button_width; }
int theme_corner_button_height(void) { return sz_corner_button_height; }
int theme_small_padding(void) { return sz_small_padding; }
int theme_logo_size(void) { return sz_logo; }
