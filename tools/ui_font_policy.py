#!/usr/bin/env python3
"""Mirror the C UI font policy for build-time icon pruning.

Firmware CMake runs this script while configuring the main component, passing
the selected board display size and consuming the emitted ICONS_* definitions.
It can also be run by hand to inspect the shared policy table results.
"""

import argparse
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "main/ui/font_policy.def"
ICON_FONT_SIZES = (16, 24, 36)
ICON_FONT_SIZE_SET = set(ICON_FONT_SIZES)


def read_policy(path):
    rows = []
    pattern = re.compile(
        r"UI_FONT_POLICY_ENTRY\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)"
    )
    for line in path.read_text().splitlines():
        match = pattern.search(line)
        if not match:
            continue
        max_diagonal, small, medium = (int(value) for value in match.groups())
        rows.append((max_diagonal, small, medium))
    if not rows:
        raise SystemExit(f"No UI font policy rows found in {path}")
    if rows[-1][0] != 0:
        raise SystemExit(f"Last UI font policy row must be a catch-all in {path}")
    return rows


def select_policy(rows, width, height):
    if width <= 0 or height <= 0:
        raise SystemExit("Display width and height must be positive")

    diagonal_sq = width * width + height * height
    for max_diagonal, small, medium in rows:
        if max_diagonal == 0 or diagonal_sq < max_diagonal * max_diagonal:
            return small, medium
    return rows[-1][1], rows[-1][2]


def emit_cmake_icon_defs(selected_sizes):
    selected = set(selected_sizes)
    unknown = selected - ICON_FONT_SIZE_SET
    if unknown:
        sizes = ", ".join(str(size) for size in sorted(unknown))
        raise SystemExit(f"Unsupported icon font size in policy: {sizes}")

    return ";".join(
        f"ICONS_{size}=0" for size in ICON_FONT_SIZES if size not in selected
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--width", required=True, type=int)
    parser.add_argument("--height", required=True, type=int)
    parser.add_argument(
        "--emit",
        choices=("tiers", "cmake-icon-defs"),
        default="tiers",
    )
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    args = parser.parse_args()

    rows = read_policy(args.policy)
    small, medium = select_policy(rows, args.width, args.height)
    if args.emit == "tiers":
        print(f"{small} {medium}")
    elif args.emit == "cmake-icon-defs":
        print(emit_cmake_icon_defs((small, medium)))


if __name__ == "__main__":
    main()
