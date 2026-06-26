# Kern UI Design Notes

A light guide to the UI conventions used in Kern. The project is still evolving, so treat these as defaults that keep things consistent — not hard rules. When in doubt, look at how `main/ui/theme.c` and `main/ui/dialog.c` do it.

---

## Colors

Colors live in `main/ui/theme.c` and are reached through accessor functions in `main/ui/theme.h`. Prefer the accessor over a raw hex value so the palette stays in one place.

| Function            | Color   | Used for                                   |
|---------------------|---------|--------------------------------------------|
| `bg_color()`        | black   | Screen and overlay backgrounds             |
| `panel_color()`     | dark gray | Dialog/card backgrounds                  |
| `primary_color()`   | white   | Primary text, button and dialog body labels |
| `secondary_color()` | gray    | Page titles, hints, quiet secondary text   |
| `highlight_color()` | orange  | Titles, button press, dropdown borders     |
| `disabled_color()`  | gray    | Disabled text, btnmatrix/dropdown item fills |
| `accent_color()`    | cyan    | Self-transfer outputs, owned-address emphasis |
| `error_color()`     | red     | Error text, danger dialog border and icon  |
| `encourage_color()` | green   | The encouraged choice in a confirm dialog  |
| `discourage_color()`| red     | The discouraged choice in a confirm dialog |
| `good_color()`      | green   | A good value/state (battery, key strength) |
| `bad_color()`       | red     | A bad value/state                          |

The palette assumes a black background. Action colors describe whether a choice is encouraged or discouraged, independent of its "Yes"/"No" label — so a danger dialog encourages "No" (green) and discourages "Yes" (red), keeping the safe choice prominent.

## Icons

Kern compiles small icon fonts from Font Awesome 7 via `scripts/bake_icons.sh`. The available glyphs are defined as `ICON_*` macros in `main/ui/assets/icons.h` (e.g. `ICON_QR_CODE`, `ICON_KEY`, `ICON_FINGERPRINT`, `ICON_BITCOIN`). Use the macro, not the raw codepoint.

The icon fonts are set as the Montserrat fonts' `.fallback`, so any label using `theme_font_small()` or `theme_font_medium()` can show an icon just by including the macro in its text. The helpers `ui_menu_add_entry_with_icon()` and `ui_icon_text_row_create()` cover the common cases. To add a glyph, append it to the `ICONS` list in `tools/bake_icons.py` and re-run the bake script.

Today only the danger dialog draws a dialog icon (`LV_SYMBOL_WARNING`, an LVGL built-in symbol).

## Typography

Two text sizes — `theme_font_small()` and `theme_font_medium()` — are resolved once in `theme_init()` from the display, via a sublinear curve so larger panels render proportionally more content. Use these rather than referencing `lv_font_montserrat_*` directly. Dialog titles and bodies use the medium font; page titles and hints use the small font.

Font sizes are **derived, not hand-picked**. `tools/derive_font_sizes.py` holds the curve (medium `22→40`, small `= 0.72 × medium`) and each board's panel spec; running it with `--apply` regenerates the whole chain. The following are **generated — do not hand-edit**:

- `main/ui/font_policy.def` — diagonal → (small, medium) bands
- the `CONFIG_LV_FONT_MONTSERRAT_*` lines in each `sdkconfig.defaults.<board>`
- `tools/bake_icons.py`'s `SIZES`, and the baked `main/ui/assets/icons_*.{c,h}`, `icons.h`, and `icons_fonts.h`

| board | small / medium |
|-------|----------------|
| wave_35 | 16 / 22 |
| wave_43 | 22 / 30 |
| wave_4b | 24 / 32 |
| crowpanel | 24 / 34 |
| wave_5 | 28 / 40 |

To retune: edit the targets/specs in `derive_font_sizes.py`, run `python3 tools/derive_font_sizes.py --apply`, then `scripts/bake_icons.sh`, then rebuild.

## Dialogs

`main/ui/dialog.h` provides a few dialog helpers. Pick by intent:

- `dialog_show_confirm()` — a safe, reversible Yes/No choice.
- `dialog_show_danger_confirm()` — a destructive/irreversible choice (red border, warning icon, swapped button colors).
- `dialog_show_info()` — neutral info with an OK button.
- `dialog_show_error_timeout()` — report a failure; auto-dismisses after a timeout.
- `dialog_show_progress()` — a buttonless "in progress" dialog; the caller deletes the returned object when done.
- `dialog_show_message()` — legacy fixed-size modal; prefer `dialog_show_info()` for new code.

Overlay dialogs are ~90% of screen width, height-fitted to their content and capped at 80% of screen height.

## Layout & Sizing

Sizing constants scale with the shorter screen axis (`min_dim`) so controls stay compact and tappable in either orientation. Reach for the theme getters instead of hardcoding pixels:

- `theme_button_width()` / `theme_button_height()` / `theme_button_spacing()`
- `theme_default_padding()` / `theme_small_padding()`
- `theme_min_touch_size()` — keep interactive elements at least this big
- `theme_corner_button_width()` / `theme_corner_button_height()`
- `theme_logo_size()`

See `theme_init()` in `main/ui/theme.c` for the exact formulas.
