#include "kern_card_style.h"
#include "assets/icons.h"
#include "kern_theme.h"
#include "theme.h"

typedef struct {
  bool initialized;
  lv_style_t card_prominent; // resting, orange border (Scan / Load)
  lv_style_t card_muted;     // resting, grey border (New Mnemonic / Settings)
  lv_style_t card_glow;      // hover / focus
  lv_style_t card_pressed;   // pressed
  lv_style_transition_dsc_t trans_in;    // -> glow,    150 ms ease-out
  lv_style_transition_dsc_t trans_out;   // -> resting, 200 ms ease-out
  lv_style_transition_dsc_t trans_press; // -> pressed,  80 ms ease-out
} kern_card_styles_t;

static kern_card_styles_t styles;

static const lv_style_prop_t card_transition_props[] = {
    LV_STYLE_BORDER_COLOR, LV_STYLE_SHADOW_OPA,    LV_STYLE_SHADOW_WIDTH,
    LV_STYLE_BG_COLOR,     LV_STYLE_BG_GRAD_COLOR, (lv_style_prop_t)0,
};

// Shared resting properties: black fill, no gray anywhere. Only border color
// differs between the prominent/muted variants.
static void init_card_base(lv_style_t *style) {
  lv_style_init(style);
  lv_style_set_radius(style, KERN_RADIUS_CARD);
  lv_style_set_bg_color(style, KERN_COLOR_CARD_BG);
  lv_style_set_bg_opa(style, LV_OPA_COVER);
  lv_style_set_bg_grad_dir(style, LV_GRAD_DIR_NONE);
  lv_style_set_border_width(style, KERN_BORDER_W);
  lv_style_set_border_opa(style, LV_OPA_COVER);
  // Shadow color pre-set so only width/opa need to animate in on hover.
  lv_style_set_shadow_color(style, KERN_COLOR_ORANGE);
  lv_style_set_shadow_width(style, 0);
  lv_style_set_shadow_opa(style, LV_OPA_TRANSP);
  lv_style_set_pad_all(style, KERN_PAD_CARD);
  // Governs the ease-out back to resting once hover/focus/press ends.
  lv_style_set_transition(style, &styles.trans_out);
}

void kern_card_styles_init(void) {
  if (styles.initialized)
    return;

  lv_style_transition_dsc_init(&styles.trans_in, card_transition_props,
                               lv_anim_path_ease_out, 150, 0, NULL);
  lv_style_transition_dsc_init(&styles.trans_out, card_transition_props,
                               lv_anim_path_ease_out, 200, 0, NULL);
  lv_style_transition_dsc_init(&styles.trans_press, card_transition_props,
                               lv_anim_path_ease_out, 80, 0, NULL);

  // ---------- resting ----------
  init_card_base(&styles.card_prominent);
  lv_style_set_border_color(&styles.card_prominent, KERN_COLOR_ORANGE);

  init_card_base(&styles.card_muted);
  lv_style_set_border_color(&styles.card_muted, KERN_COLOR_HAIRLINE);

  // ---------- hover / focus glow ----------
  lv_style_init(&styles.card_glow);
  lv_style_set_border_color(&styles.card_glow, KERN_COLOR_ORANGE);

  // Outer bloom, biased to the top edge.
  lv_style_set_shadow_color(&styles.card_glow, KERN_COLOR_ORANGE);
  lv_style_set_shadow_width(&styles.card_glow, 24);
  lv_style_set_shadow_spread(&styles.card_glow, 0);
  lv_style_set_shadow_offset_x(&styles.card_glow, 0);
  lv_style_set_shadow_offset_y(&styles.card_glow, -3);
  lv_style_set_shadow_opa(&styles.card_glow, LV_OPA_50);

  // Interior warm wash: dies out about 40% down the card. Static storage --
  // LVGL keeps a pointer to this descriptor, so it must outlive the style.
  static lv_grad_dsc_t glow_grad;
  glow_grad.dir = LV_GRAD_DIR_VER;
  glow_grad.stops_count = 2;
  glow_grad.stops[0].color = KERN_COLOR_WARM_TINT;
  glow_grad.stops[0].opa = LV_OPA_COVER;
  glow_grad.stops[0].frac = 0;
  glow_grad.stops[1].color = KERN_COLOR_CARD_BG;
  glow_grad.stops[1].opa = LV_OPA_COVER;
  glow_grad.stops[1].frac = 102;
  lv_style_set_bg_grad(&styles.card_glow, &glow_grad);

  lv_style_set_transition(&styles.card_glow, &styles.trans_in);

  // ---------- pressed: tighter + brighter ----------
  lv_style_init(&styles.card_pressed);
  lv_style_set_border_color(&styles.card_pressed, KERN_COLOR_ORANGE_HOT);
  lv_style_set_shadow_color(&styles.card_pressed, KERN_COLOR_ORANGE);
  lv_style_set_shadow_width(&styles.card_pressed, 14);
  lv_style_set_shadow_offset_y(&styles.card_pressed, -2);
  lv_style_set_shadow_opa(&styles.card_pressed, LV_OPA_70);

  static lv_grad_dsc_t pressed_grad;
  pressed_grad.dir = LV_GRAD_DIR_VER;
  pressed_grad.stops_count = 2;
  pressed_grad.stops[0].color = KERN_COLOR_WARM_TINT_PRESS;
  pressed_grad.stops[0].opa = LV_OPA_COVER;
  pressed_grad.stops[0].frac = 0;
  pressed_grad.stops[1].color = KERN_COLOR_CARD_BG;
  pressed_grad.stops[1].opa = LV_OPA_COVER;
  pressed_grad.stops[1].frac = 102;
  lv_style_set_bg_grad(&styles.card_pressed, &pressed_grad);

  lv_style_set_transition(&styles.card_pressed, &styles.trans_press);

  styles.initialized = true;
}

lv_obj_t *kern_card_create(lv_obj_t *parent, const char *icon_symbol,
                           const char *label_text, bool prominent) {
  if (!parent)
    return NULL;

  lv_obj_t *card = lv_button_create(parent);
  lv_obj_remove_style_all(card);

  lv_obj_add_style(card,
                   prominent ? &styles.card_prominent : &styles.card_muted,
                   LV_STATE_DEFAULT);
  lv_obj_add_style(card, &styles.card_glow, LV_STATE_HOVERED);
  lv_obj_add_style(card, &styles.card_glow, LV_STATE_FOCUS_KEY);
  lv_obj_add_style(card, &styles.card_pressed, LV_STATE_PRESSED);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(card, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);

  lv_obj_t *icon = lv_label_create(card);
  lv_label_set_text(icon, icon_symbol);
  lv_obj_set_style_text_color(icon, KERN_COLOR_ORANGE, 0);
  lv_obj_set_style_text_font(icon, theme_font_medium(), 0);

  lv_obj_t *label = lv_label_create(card);
  lv_label_set_text(label, label_text);
  lv_obj_set_style_text_color(label, lv_color_white(), 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_pad_top(label, theme_small_padding(), 0);

  return card;
}

lv_obj_t *kern_info_button_create(lv_obj_t *parent, lv_event_cb_t click_cb) {
  if (!parent)
    return NULL;

  lv_obj_t *btn = lv_button_create(parent);
  lv_obj_remove_style_all(btn);
  // Square = theme_corner_button_height(), matching the nav band's height so
  // this button's vertical center lines up with the KERN title/logo row
  // (corner_button_width != corner_button_height in this theme, so sizing to
  // width here previously threw the two out of alignment).
  int32_t size = theme_corner_button_height();
  lv_obj_set_size(btn, size, size);
  lv_obj_set_style_radius(btn, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(btn, KERN_COLOR_ORANGE, 0);
  lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_opa(btn, LV_OPA_20,
                          LV_STATE_HOVERED | LV_STATE_FOCUS_KEY);
  lv_obj_set_style_bg_opa(btn, LV_OPA_30, LV_STATE_PRESSED);

  lv_obj_t *icon = lv_label_create(btn);
  lv_label_set_text(icon, ICON_INFO);
  lv_obj_set_style_text_font(icon, theme_font_medium(), 0);
  lv_obj_set_style_text_color(icon, KERN_COLOR_ORANGE, 0);
  lv_obj_center(icon);

  if (click_cb)
    lv_obj_add_event_cb(btn, click_cb, LV_EVENT_CLICKED, NULL);

  return btn;
}
