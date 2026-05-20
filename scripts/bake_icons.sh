#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_DIR="$ROOT_DIR/main/ui/assets"
FONT_NAME="Font Awesome 7 Free-Solid-900"

resolve_font() {
  if [[ -n "${FONT_AWESOME_FONT:-}" ]]; then
    printf '%s\n' "$FONT_AWESOME_FONT"
    return
  fi

  local candidates=(
    "$ROOT_DIR/tools/fonts/$FONT_NAME.otf"
  )

  local font
  for font in "${candidates[@]}"; do
    if [[ -f "$font" ]]; then
      printf '%s\n' "$font"
      return
    fi
  done

  cat >&2 <<EOF
Could not find a Font Awesome font.

Place the desktop font at:
  tools/fonts/$FONT_NAME.otf

or set:
  FONT_AWESOME_FONT=/path/to/fontawesome-solid-font.otf scripts/bake_icons.sh
EOF
  exit 1
}

main() {
  local font
  font="$(resolve_font)"

  python3 "$ROOT_DIR/tools/bake_icons.py" \
    --font "$font" \
    --output-dir "$ASSET_DIR"
}

main "$@"
