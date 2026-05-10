# Font Assets

The icon baker can use either:

- `tools/fonts/Font Awesome 7 Free-Solid-900.otf`
- a custom path set with `FONT_AWESOME_FONT=/path/to/font`

Font Awesome Free font files are licensed under SIL OFL 1.1. This directory
keeps the upstream license text alongside the vendored OTF.

## Baking Icons

The baker uses Python and Pillow:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install Pillow
scripts/bake_icons.sh
```

If Pillow is already available in your Python environment, you can run
`scripts/bake_icons.sh` directly.
