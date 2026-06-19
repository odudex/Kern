#!/usr/bin/env python3
import argparse
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as err:
    raise SystemExit(
        "Pillow is required to bake icons. Install it with: python3 -m pip install Pillow"
    ) from err


ICONS = [
    ("ICON_XPUB", 0xE001, "custom-xpub-key-badge"),
    ("ICON_BITCOIN", 0xE0B4, "bitcoin-sign"),
    ("ICON_QR_CODE", 0xF029, "qrcode"),
    ("ICON_HELP", 0xF059, "circle-question"),
    ("ICON_INFO", 0xF05A, "circle-info"),
    ("ICON_KEY", 0xF084, "key"),
    ("ICON_DERIVATION", 0xF126, "code-branch"),
    ("ICON_BOX_ARCHIVE", 0xF187, "box-archive"),
    ("ICON_TOOLBOX", 0xF552, "toolbox"),
    ("ICON_FINGERPRINT", 0xF577, "fingerprint"),
    ("ICON_DICE", 0xF522, "dice"),
    ("ICON_SD_CARD", 0xF7C2, "sd-card"),
]


def utf8_c_escape(codepoint):
    return "".join(f"\\x{byte:02X}" for byte in chr(codepoint).encode("utf-8"))


def pack_bitmap(image):
    pixels = list(image.getdata())
    packed = []
    for pos in range(0, len(pixels), 2):
        hi = (pixels[pos] + 8) // 17
        lo = (pixels[pos + 1] + 8) // 17 if pos + 1 < len(pixels) else 0
        packed.append((hi << 4) | lo)
    return packed


def load_text_font(size):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/msttcorefonts/Arial_Bold.ttf",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default(size=size)


def render_xpub_badge(font, size):
    key = chr(0xF084)
    image = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(image)

    key_size = max(1, int(size * 0.74))
    key_font = font.font_variant(size=key_size)
    left, top, right, bottom = key_font.getbbox(key, anchor="ls")
    key_h = bottom - top
    key_x = max(0, int(size * 0.01) - left)
    key_y = max(key_h - bottom, int(size * 0.55))
    draw.text((key_x, key_y), key, font=key_font, fill=255, anchor="ls")

    badge_text = "pub"
    badge_font_size = max(6, int(size * 0.38))
    badge_font = load_text_font(badge_font_size)
    text_left, text_top, text_right, text_bottom = badge_font.getbbox(badge_text)
    text_w = text_right - text_left
    text_h = text_bottom - text_top

    draw.text(
        (
            max(0, size - text_w - text_left),
            max(0, size - text_h - text_top),
        ),
        badge_text,
        font=badge_font,
        fill=255,
    )

    bottom_padding = max(1, size // 12)
    return {
        "bitmap": pack_bitmap(image),
        "bitmap_index": 0,
        "adv_w": size * 16,
        "box_w": size,
        "box_h": size,
        "ofs_x": 0,
        "ofs_y": -bottom_padding,
        "bottom": bottom_padding,
    }


def render_glyph(font, codepoint):
    if codepoint == 0xE001:
        return render_xpub_badge(font, font.size)

    char = chr(codepoint)
    left, top, right, bottom = font.getbbox(char, anchor="ls")
    width = max(0, right - left)
    height = max(0, bottom - top)
    advance = int(round(font.getlength(char)))

    if width == 0 or height == 0:
        return {
            "bitmap": [],
            "bitmap_index": 0,
            "adv_w": advance * 16,
            "box_w": 0,
            "box_h": 0,
            "ofs_x": 0,
            "ofs_y": 0,
            "bottom": 0,
        }

    image = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(image)
    draw.text((-left, -top), char, font=font, fill=255, anchor="ls")

    return {
        "bitmap": pack_bitmap(image),
        "bitmap_index": 0,
        "adv_w": advance * 16,
        "box_w": width,
        "box_h": height,
        "ofs_x": left,
        "ofs_y": -bottom,
        "bottom": bottom,
    }


def comma_hex(values, indent="    "):
    if not values:
        return indent + "0x0"

    lines = []
    line = indent
    for value in values:
        text = f"0x{value:x}, "
        if len(line) + len(text) > 100:
            lines.append(line.rstrip())
            line = indent
        line += text
    if line.strip():
        lines.append(line.rstrip().rstrip(","))
    return "\n".join(lines)


def write_font(path, font_path, size):
    font_name = f"icons_{size}"
    font = ImageFont.truetype(str(font_path), size=size)

    glyphs = []
    bitmap = []
    max_above = 0
    max_below = 0
    # The SPARSE_TINY cmap is binary-searched by LVGL, so the glyphs must be
    # emitted with strictly ascending codepoints regardless of the ICONS order.
    for _, codepoint, _ in sorted(ICONS, key=lambda entry: entry[1]):
        glyph = render_glyph(font, codepoint)
        glyph["bitmap_index"] = len(bitmap)
        glyphs.append((codepoint, glyph))
        bitmap.extend(glyph["bitmap"])
        max_above = max(max_above, glyph["box_h"] + glyph["ofs_y"])
        max_below = max(max_below, -glyph["ofs_y"])

    base_line = max_below
    line_height = max(size, max_above + max_below)
    range_start = min(codepoint for codepoint, _ in glyphs)
    offsets = [codepoint - range_start for codepoint, _ in glyphs]
    range_length = max(offsets) + 1

    text = f"""/*******************************************************************************
 * Size: {size} px
 * Bpp: 4
 * Generated locally from Font Awesome 7 Free-Solid-900:
 *   scripts/bake_icons.sh
 ******************************************************************************/

#ifdef __has_include
#if __has_include("lvgl.h")
#ifndef LV_LVGL_H_INCLUDE_SIMPLE
#define LV_LVGL_H_INCLUDE_SIMPLE
#endif
#endif
#endif

#ifdef LV_LVGL_H_INCLUDE_SIMPLE
#include "lvgl.h"
#else
#include "lvgl/lvgl.h"
#endif

#ifndef {font_name.upper()}
#define {font_name.upper()} 1
#endif

#if {font_name.upper()}

/*-----------------
 *    BITMAPS
 *----------------*/

static LV_ATTRIBUTE_LARGE_CONST const uint8_t glyph_bitmap[] = {{
{comma_hex(bitmap)}
}};

/*---------------------
 *  GLYPH DESCRIPTION
 *--------------------*/

static const lv_font_fmt_txt_glyph_dsc_t glyph_dsc[] = {{
    {{.bitmap_index = 0,
     .adv_w = 0,
     .box_w = 0,
     .box_h = 0,
     .ofs_x = 0,
     .ofs_y = 0}} /* id = 0 reserved */,
"""

    for idx, (_, glyph) in enumerate(glyphs, start=1):
        suffix = "," if idx < len(glyphs) else ""
        text += f"""    {{.bitmap_index = {glyph["bitmap_index"]},
     .adv_w = {glyph["adv_w"]},
     .box_w = {glyph["box_w"]},
     .box_h = {glyph["box_h"]},
     .ofs_x = {glyph["ofs_x"]},
     .ofs_y = {glyph["ofs_y"]}}}{suffix}
"""

    text += f"""}};

/*---------------------
 *  CHARACTER MAPPING
 *--------------------*/

static const uint16_t unicode_list_0[] = {{{", ".join(f"0x{value:x}" for value in offsets)}}};

static const lv_font_fmt_txt_cmap_t cmaps[] = {{
    {{.range_start = {range_start},
     .range_length = {range_length},
     .glyph_id_start = 1,
     .unicode_list = unicode_list_0,
     .glyph_id_ofs_list = NULL,
     .list_length = sizeof(unicode_list_0) / sizeof(unicode_list_0[0]),
     .type = LV_FONT_FMT_TXT_CMAP_SPARSE_TINY}}}};

/*--------------------
 *  ALL CUSTOM DATA
 *--------------------*/

#if LVGL_VERSION_MAJOR == 8
static lv_font_fmt_txt_glyph_cache_t cache;
#endif

#if LVGL_VERSION_MAJOR >= 8
static const lv_font_fmt_txt_dsc_t font_dsc = {{
#else
static lv_font_fmt_txt_dsc_t font_dsc = {{
#endif
    .glyph_bitmap = glyph_bitmap,
    .glyph_dsc = glyph_dsc,
    .cmaps = cmaps,
    .kern_dsc = NULL,
    .kern_scale = 0,
    .cmap_num = 1,
    .bpp = 4,
    .kern_classes = 0,
    .bitmap_format = 0,
#if LVGL_VERSION_MAJOR == 8
    .cache = &cache
#endif
}};

/*-----------------
 *  PUBLIC FONT
 *----------------*/

#if LVGL_VERSION_MAJOR >= 8
const lv_font_t {font_name} = {{
#else
lv_font_t {font_name} = {{
#endif
    .get_glyph_dsc = lv_font_get_glyph_dsc_fmt_txt,
    .get_glyph_bitmap = lv_font_get_bitmap_fmt_txt,
    .line_height = {line_height},
    .base_line = {base_line},
#if !(LVGL_VERSION_MAJOR == 6 && LVGL_VERSION_MINOR == 0)
    .subpx = LV_FONT_SUBPX_NONE,
#endif
#if LV_VERSION_CHECK(7, 4, 0) || LVGL_VERSION_MAJOR >= 8
    .underline_position = -{max(1, size // 12)},
    .underline_thickness = {max(1, size // 24)},
#endif
    .dsc = &font_dsc,
#if LV_VERSION_CHECK(8, 2, 0) || LVGL_VERSION_MAJOR >= 9
    .fallback = NULL,
#endif
    .user_data = NULL,
}};

#endif /*#if {font_name.upper()}*/
"""

    path.write_text(text)


def write_header(path):
    lines = [
        "#ifndef ICONS_H",
        "#define ICONS_H",
        "",
        "// Font Awesome symbol definitions (UTF-8 encoded).",
        "// The generated 16/24/36 px icon fonts must include these codepoints.",
    ]
    for name, codepoint, label in ICONS:
        source = "Custom" if label.startswith("custom-") else "FontAwesome"
        lines.append(
            f'#define {name} "{utf8_c_escape(codepoint)}" // {source} U+{codepoint:04X} = {label}'
        )
    lines.extend(
        [
            "",
            "// Backward-compatible aliases for call sites that used size-named symbols.",
            "#define ICON_QRCODE_36 ICON_QR_CODE",
            "#define ICON_HELP_36 ICON_HELP",
            "#define ICON_FINGERPRINT_36 ICON_FINGERPRINT",
            "",
            "#endif // ICONS_H",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--font", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for size in (16, 24, 36):
        write_font(args.output_dir / f"icons_{size}.c", args.font, size)
    write_header(args.output_dir / "icons.h")


if __name__ == "__main__":
    main()
