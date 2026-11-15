#!/bin/bash
# Kern bootloader freeze, step 1 of 3 — runs on the build machine.
#
# Builds the secure-boot bootloader (sdkconfig.release + sdkconfig.secure) for
# every device, groups the unsigned images into variants (chip revision range
# and flash mode) and stages one per variant in release/bootloader-<N>/, with
# the BOOTLOADERS manifest, the public keys and freeze_bootloader.sh. N is
# CONFIG_BOOTLOADER_PROJECT_VER.
#
# A variant whose frozen image in kern_secure_boot/bootloaders/ still matches
# the build is staged with that signature and is not signed again.
#
# Move the folder to the air-gapped signing PC, run freeze_bootloader.sh there,
# then bring it back and run `just bootloader-import release/bootloader-<N>`.
#
# The tree must be committed: a frozen bootloader has to be reproducible from
# the commit the manifest names. ALLOW_DIRTY=1 skips that for a trial run.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KERN_SB_DIR="${KERN_SB_DIR:-$REPO_ROOT/kern_secure_boot}"
BOARDS="wave_4b wave_35 wave_5 wave_43 crowpanel wave_7b p4_pico"
# Each board twice: ESP32-P4 chip revision v1.x, then v3.x (<board>_v3)
DEVICES="$BOARDS $(printf '%s_v3 ' $BOARDS)"

cd "$REPO_ROOT"

if [ -n "$(git status --porcelain)" ] && [ -z "$ALLOW_DIRTY" ]; then
    echo "Error: uncommitted changes. Commit first, or set ALLOW_DIRTY=1 for a trial run." >&2
    exit 1
fi
COMMIT="$(git rev-parse HEAD)"

command -v idf.py >/dev/null || source "${IDF_PATH:-$HOME/esp/esp-idf}/export.sh"

BUILT="$(mktemp)"
trap 'rm -f "$BUILT"' EXIT

for DEVICE in $DEVICES; do
    echo "========================================"
    echo "Building the bootloader for ${DEVICE}..."
    echo "========================================"
    just build-secure "$DEVICE" bootloader

    BUILD_DIR="build_secure_${DEVICE}"
    CONFIG="$BUILD_DIR/sdkconfig"
    VARIANT="$("$SCRIPT_DIR/bootloader_variant.sh" "$CONFIG")"
    FREEZE="$(sed -n 's/^CONFIG_BOOTLOADER_PROJECT_VER=//p' "$CONFIG")"
    IDF_VER="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["git_revision"])' "$BUILD_DIR/project_description.json")"
    SHA="$(sha256sum "$BUILD_DIR/bootloader/bootloader-unsigned.bin" | cut -d' ' -f1)"
    echo "$VARIANT $DEVICE $FREEZE $IDF_VER $SHA" >> "$BUILT"
done

python3 - "$BUILT" "$REPO_ROOT" "$KERN_SB_DIR" "$COMMIT" "$SCRIPT_DIR/freeze_bootloader.sh" <<'EOF'
import os, shutil, sys

built, repo, sb_dir, commit, freeze_script = sys.argv[1:6]
SECTOR = 4096

variants = {}
for line in open(built):
    variant, device, freeze, idf_ver, sha = line.split()
    v = variants.setdefault(variant, {"freeze": freeze, "idf": idf_ver, "sha": sha, "devices": []})
    if (v["freeze"], v["idf"], v["sha"]) != (freeze, idf_ver, sha):
        sys.exit(f"Error: {device} builds a different {variant} bootloader than {v['devices'][0]} "
                 f"({sha[:16]} against {v['sha'][:16]}): it needs a variant of its own")
    v["devices"].append(device)

freezes = {v["freeze"] for v in variants.values()}
if len(freezes) != 1:
    sys.exit(f"Error: boards disagree on CONFIG_BOOTLOADER_PROJECT_VER: {sorted(freezes)}")
freeze = freezes.pop()

frozen_manifest = {}
manifest_path = os.path.join(sb_dir, "bootloaders", "BOOTLOADERS")
if os.path.exists(manifest_path):
    for line in open(manifest_path):
        if line.strip() and not line.startswith("#"):
            frozen_manifest[line.split()[0]] = line.rstrip("\n")

out = os.path.join(repo, "release", f"bootloader-{freeze}")
if os.path.exists(out):
    sys.exit(f"Error: {out} already exists. Import it (just bootloader-import) or remove it: "
             "it may hold signatures that cannot be made again.")

lines, to_sign = [], []
for variant in sorted(variants):
    v = variants[variant]
    unsigned = os.path.join(repo, f"build_secure_{v['devices'][0]}", "bootloader", "bootloader-unsigned.bin")
    line = f"{variant} {freeze} bootloader-{freeze} {commit} {v['idf']} {v['sha']} {','.join(v['devices'])}"
    frozen = os.path.join(sb_dir, "bootloaders", variant, "bootloader-signed.bin")
    keep = False
    if os.path.exists(frozen):
        u = open(unsigned, "rb").read()
        keep = open(frozen, "rb").read()[:-SECTOR] == u + b"\xff" * (-len(u) % SECTOR)
        if not keep and (variant not in frozen_manifest or frozen_manifest[variant].split()[1] == freeze):
            sys.exit(f"Error: the {variant} bootloader built here differs from the frozen one. "
                     "To freeze a new one, raise CONFIG_BOOTLOADER_PROJECT_VER in sdkconfig.secure.")
    os.makedirs(os.path.join(out, variant))
    shutil.copy(unsigned, os.path.join(out, variant, "bootloader-unsigned.bin"))
    if keep:
        shutil.copy(frozen, os.path.join(out, variant, "bootloader-signed.bin"))
        # The commit and boards of the original freeze stay unless this build widens them
        if variant in frozen_manifest and frozen_manifest[variant].split()[5] == v["sha"]:
            old = frozen_manifest[variant].split()
            line = " ".join(old[:6] + [",".join(v["devices"])])
    else:
        to_sign.append(variant)
    lines.append(line)

with open(os.path.join(out, "BOOTLOADERS"), "w") as f:
    f.write("# Frozen bootloaders, one line per variant (docs/secure-boot.md, section 4a)\n")
    f.write("# variant freeze tag commit esp-idf unsigned-sha256 boards\n")
    f.write("\n".join(lines) + "\n")
for n in range(3):
    for name in (f"kern-sb-key{n}-pub.pem", f"kern-sb-digest{n}.bin"):
        shutil.copy(os.path.join(sb_dir, name), out)
shutil.copy(freeze_script, out)

print("========================================")
print(f"Bootloader freeze {freeze} staged in {out}")
for line in lines:
    variant, _, _, _, idf_ver, sha, boards = line.split()
    state = "to sign" if variant in to_sign else "already frozen, signature kept"
    print(f"  {variant}  {sha[:16]}  {state}  ({boards})")
print()
if to_sign:
    print("On the air-gapped PC, from that folder:")
    print("  bash freeze_bootloader.sh <key0.pem> <key1.pem> <key2.pem>")
print(f"Then: just bootloader-import release/bootloader-{freeze}")
EOF
