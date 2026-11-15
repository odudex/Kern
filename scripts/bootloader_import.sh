#!/bin/bash
# Kern bootloader freeze, step 3 of 3 — runs on the build machine.
#
# Verifies a release/bootloader-<N> folder that came back from the air-gapped
# signing PC against the public keys in kern_secure_boot/ (not the copies in
# the folder), then copies each signed bootloader and its manifest line into
# kern_secure_boot/bootloaders/. Needs no private key.
#
# Usage: bootloader_import.sh <folder>      (or: just bootloader-import <folder>)
#
# A frozen bootloader is never replaced by different bytes under the same
# freeze number. SHA256SUMS, its GPG signature, the commit and the
# bootloader-<N> tag are left to the developer; the commands are printed.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KERN_SB_DIR="${KERN_SB_DIR:-$REPO_ROOT/kern_secure_boot}"
DIR="$1"

if [ -z "$DIR" ] || [ ! -f "$DIR/BOOTLOADERS" ]; then
    echo "Usage: $0 <release/bootloader-N folder>" >&2
    exit 1
fi

# espsecure comes with ESP-IDF here (matches justfile)
command -v espsecure >/dev/null || source "${IDF_PATH:-$HOME/esp/esp-idf}/export.sh" >/dev/null 2>&1

bash "$SCRIPT_DIR/freeze_bootloader.sh" --verify "$DIR" "$KERN_SB_DIR"

python3 - "$DIR" "$KERN_SB_DIR/bootloaders" <<'EOF'
import os, shutil, sys

src, dest = sys.argv[1:3]
HEADER = ("# Frozen bootloaders, one line per variant (docs/secure-boot.md, section 4a)\n"
          "# variant freeze tag commit esp-idf unsigned-sha256 boards\n")

def read(path):
    lines = {}
    if os.path.exists(path):
        for line in open(path):
            if line.strip() and not line.startswith("#"):
                lines[line.split()[0]] = line.rstrip("\n")
    return lines

frozen, staged = read(os.path.join(dest, "BOOTLOADERS")), read(os.path.join(src, "BOOTLOADERS"))
imported, pending, tags = [], [], set()
for variant, line in sorted(staged.items()):
    signed = os.path.join(src, variant, "bootloader-signed.bin")
    if not os.path.exists(signed):
        pending.append(variant)
        continue
    target = os.path.join(dest, variant, "bootloader-signed.bin")
    if os.path.exists(target) and open(target, "rb").read() != open(signed, "rb").read():
        same_freeze = variant not in frozen or frozen[variant].split()[1] == line.split()[1]
        if same_freeze:
            sys.exit(f"Error: {variant} is already frozen with other bytes under this freeze number. "
                     "Devices may be locked with it; nothing was imported.")
    imported.append((variant, signed, target, line))

for variant, signed, target, line in imported:
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copy(signed, target)
    frozen[variant] = line
    tags.add((line.split()[2], line.split()[3]))
    print(f"  {variant}: imported")
for variant in pending:
    print(f"  {variant}: NOT signed, not imported")

if imported:
    with open(os.path.join(dest, "BOOTLOADERS"), "w") as f:
        f.write(HEADER + "\n".join(frozen[v] for v in sorted(frozen)) + "\n")
if pending:
    print("\nSign the rest with freeze_bootloader.sh on the air-gapped PC, then import this folder again.")
elif imported:
    print(f"\nFrozen bootloaders are in {dest}. Left to do by hand:")
    print("  cd kern_secure_boot")
    print("  sha256sum kern-sb-key?-pub.pem kern-sb-digest?.bin bootloaders/BOOTLOADERS "
          "bootloaders/*/bootloader-signed.bin > SHA256SUMS")
    print("  gpg --detach-sign --armor -o SHA256SUMS.sig SHA256SUMS")
    print("  git add . && git commit")
    for tag, commit in sorted(tags):
        print(f"  git tag {tag} {commit}")
EOF
