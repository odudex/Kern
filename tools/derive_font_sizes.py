#!/usr/bin/env python3
"""Derive per-board UI font sizes from display specs via a sublinear curve.

Single source of truth for the (small, medium) font each board gets. Font size
grows *sublinearly* with screen size, so larger panels render proportionally
smaller text and therefore show MORE content (less scrolling).

The curve is a power law

    font(x) = y0 * (x / x0) ** b

anchored at the smallest and largest boards: b and the coefficient are solved so
the extremes land exactly on the configured target sizes. Because b < 1 the
font / screen ratio shrinks as the screen grows -- that is the non-linearity.

This is a DESIGN/BUILD-TIME tool. It emits the artifacts that already exist in
the tree (font_policy.def rows, the bake_icons SIZES tuple, per-board sdkconfig
font lines); the firmware keeps plain integer font constants, no float math.

Usage:
    python3 tools/derive_font_sizes.py            # dry run: print report + artifacts
    python3 tools/derive_font_sizes.py --apply    # also rewrite the tree
"""
import argparse
import math
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# --- Boards -------------------------------------------------------------------
# Native panel resolution (orientation-agnostic) and physical diagonal. diag_in
# only feeds the DPI report column; it does not affect the pixel-based curve.
BOARDS = [
    {"name": "wave_35", "sdkconfig": "sdkconfig.defaults.wave_35", "w": 320, "h": 480, "diag_in": 3.5},
    {"name": "wave_43", "sdkconfig": "sdkconfig.defaults.wave_43", "w": 480, "h": 800, "diag_in": 4.3},
    {"name": "wave_4b", "sdkconfig": "sdkconfig.defaults.wave_4b", "w": 720, "h": 720, "diag_in": 4.0},
    {"name": "crowpanel", "sdkconfig": "sdkconfig.defaults.crowpanel", "w": 1024, "h": 600, "diag_in": 7.0},
    {"name": "wave_5", "sdkconfig": "sdkconfig.defaults.wave_5", "w": 720, "h": 1280, "diag_in": 5.0},
]

# --- Curve knobs (adjust these) ----------------------------------------------
# Medium (title/emphasis) font px at the smallest and largest board. The power
# law is solved through these two anchors; b < 1 makes it sublinear, so the
# font / screen ratio shrinks as the screen grows. Raise MEDIUM_MAX for a wider
# spread, lower it for a flatter ramp.
MEDIUM_MIN_PX = 22  # medium font on the smallest panel (wave_35)
MEDIUM_MAX_PX = 40  # medium font on the largest panel (wave_5)
# Body font is kept proportional to medium (no independent curve), so the
# title/body balance stays constant across boards. Rounded to an even size.
SMALL_RATIO = 0.72  # small = SMALL_RATIO * medium

# Size metric driving the curve. "diagonal" matches the runtime font policy
# (font_policy.c keys on w*w + h*h), so the generated bands need no C change.
# "area" (w*h) or "short" (min(w,h)) are available if a different feel is wanted;
# note the runtime still routes by diagonal, so a non-diagonal metric must stay
# monotonic in diagonal (the script checks this before emitting policy rows).
METRIC = "diagonal"

MIN_FONT_PX = 12  # clamp floor
MAX_FONT_PX = 48  # clamp ceiling (largest baked Montserrat)


def screen_metric(board):
    w, h = board["w"], board["h"]
    if METRIC == "diagonal":
        return math.hypot(w, h)
    if METRIC == "area":
        return math.sqrt(w * h)
    if METRIC == "short":
        return min(w, h)
    raise SystemExit(f"Unknown METRIC: {METRIC!r}")


def diagonal_px(board):
    return math.hypot(board["w"], board["h"])


def round_even(value):
    even = int(2 * round(value / 2.0))
    return max(MIN_FONT_PX, min(MAX_FONT_PX, even))


def solve_power_law(x0, y0, x1, y1):
    """Return (coeff, exponent) for y = coeff * x**exponent through both points."""
    exponent = math.log(y1 / y0) / math.log(x1 / x0)
    coeff = y0 / (x0 ** exponent)
    return coeff, exponent


def build_curve(target_min, target_max):
    metrics = [screen_metric(b) for b in BOARDS]
    x0, x1 = min(metrics), max(metrics)
    coeff, exponent = solve_power_law(x0, y0=target_min, x1=x1, y1=target_max)
    return coeff, exponent


def font_for(board, coeff, exponent):
    return round_even(coeff * (screen_metric(board) ** exponent))


def compute():
    med_coeff, med_exp = build_curve(MEDIUM_MIN_PX, MEDIUM_MAX_PX)
    rows = []
    for b in BOARDS:
        medium = font_for(b, med_coeff, med_exp)
        small = min(round_even(medium * SMALL_RATIO), medium)
        rows.append({**b, "small": small, "medium": medium})
    return rows, med_exp


def policy_bands(rows):
    """Emit (max_diagonal_px, small, medium) bands keyed on diagonal (runtime
    metric), merging adjacent boards that resolve to the same font pair. The last
    band is the catch-all (max_diagonal 0)."""
    ordered = sorted(rows, key=diagonal_px)
    pairs = [(r["small"], r["medium"]) for r in ordered]
    monotonic = all(pairs[i] <= pairs[i + 1] for i in range(len(pairs) - 1))
    bands = []
    i = 0
    while i < len(ordered):
        small, medium = ordered[i]["small"], ordered[i]["medium"]
        j = i
        while j + 1 < len(ordered) and (ordered[j + 1]["small"], ordered[j + 1]["medium"]) == (small, medium):
            j += 1
        if j + 1 < len(ordered):
            threshold = int(round((diagonal_px(ordered[j]) + diagonal_px(ordered[j + 1])) / 2.0))
        else:
            threshold = 0
        bands.append((threshold, small, medium))
        i = j + 1
    return bands, monotonic


def render_policy_def(bands):
    lines = [
        "/*",
        " * UI font policy rows:",
        " *   UI_FONT_POLICY_ENTRY(max_diagonal_px, small_font_px, medium_font_px)",
        " *",
        " * max_diagonal_px is exclusive. Use 0 for the catch-all row.",
        " * Generated by tools/derive_font_sizes.py -- edit the curve there, not here.",
        " */",
    ]
    for threshold, small, medium in bands:
        lines.append(f"UI_FONT_POLICY_ENTRY({threshold}, {small}, {medium})")
    return "\n".join(lines) + "\n"


def all_sizes(rows):
    sizes = set()
    for r in rows:
        sizes.add(r["small"])
        sizes.add(r["medium"])
    return tuple(sorted(sizes))


def print_report(rows, med_exp, bands, monotonic):
    print("Per-board font sizes")
    print(f"  metric={METRIC}  medium {MEDIUM_MIN_PX}->{MEDIUM_MAX_PX} (b={med_exp:.3f})"
          f"  small = {SMALL_RATIO:.2f} x medium")
    print()
    header = f"{'board':<11}{'WxH':>10}{'diag_px':>9}{'DPI':>6}{'small':>7}{'medium':>8}{'m/s':>6}{'med/diag':>10}"
    print(header)
    print("-" * len(header))
    for r in sorted(rows, key=diagonal_px):
        diag = diagonal_px(r)
        dpi = diag / r["diag_in"]
        wxh = f'{r["w"]}x{r["h"]}'
        print(f'{r["name"]:<11}{wxh:>10}{diag:>9.0f}{dpi:>6.0f}'
              f'{r["small"]:>7}{r["medium"]:>8}{r["medium"] / r["small"]:>6.2f}{r["medium"] / diag:>10.4f}')
    print()
    if not monotonic:
        print("WARNING: font pairs are not monotonic in diagonal; the diagonal-keyed")
        print("         policy table cannot reproduce this assignment. Pick METRIC")
        print("         = 'diagonal' or change the runtime policy metric.")
        print()

    print(f"Sizes to bake (tools/bake_icons.py SIZES): {all_sizes(rows)}")
    print()
    print("main/ui/font_policy.def:")
    print(render_policy_def(bands))
    print("Per-board sdkconfig font lines:")
    for r in sorted(rows, key=diagonal_px):
        sizes = sorted({r["small"], r["medium"]})
        lines = " ".join(f"CONFIG_LV_FONT_MONTSERRAT_{s}=y" for s in sizes)
        print(f'  {r["sdkconfig"]}: {lines}')


def apply_changes(rows, bands):
    # font_policy.def
    (REPO_ROOT / "main/ui/font_policy.def").write_text(render_policy_def(bands))

    # bake_icons SIZES
    bake = REPO_ROOT / "tools/bake_icons.py"
    text = bake.read_text()
    sizes = ", ".join(str(s) for s in all_sizes(rows))
    text, n = re.subn(r"^SIZES = \([^)]*\)", f"SIZES = ({sizes})", text, flags=re.MULTILINE)
    if n != 1:
        raise SystemExit("Could not locate SIZES in tools/bake_icons.py")
    bake.write_text(text)

    # per-board sdkconfig font lines
    font_re = re.compile(r"^CONFIG_LV_FONT_MONTSERRAT_\d+=y\n", flags=re.MULTILINE)
    board_re = re.compile(r"^(CONFIG_KERN_BOARD_\w+=y\n)", flags=re.MULTILINE)
    for r in rows:
        path = REPO_ROOT / r["sdkconfig"]
        content = font_re.sub("", path.read_text())
        sizes = sorted({r["small"], r["medium"]})
        block = "".join(f"CONFIG_LV_FONT_MONTSERRAT_{s}=y\n" for s in sizes)
        content, n = board_re.subn(lambda m: m.group(1) + block, content, count=1)
        if n != 1:
            raise SystemExit(f"Could not locate board select line in {r['sdkconfig']}")
        path.write_text(content)

    print("Applied. Next: scripts/bake_icons.sh, then rebuild each board.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="rewrite font_policy.def, bake_icons SIZES, and per-board sdkconfig")
    args = parser.parse_args()

    rows, med_exp = compute()
    bands, monotonic = policy_bands(rows)
    print_report(rows, med_exp, bands, monotonic)
    if args.apply:
        if not monotonic:
            raise SystemExit("Refusing to apply a non-diagonal-monotonic assignment.")
        print()
        apply_changes(rows, bands)


if __name__ == "__main__":
    main()
