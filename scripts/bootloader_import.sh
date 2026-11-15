#!/bin/bash
# Kern bootloader freeze, step 3 of 3 — runs on the build machine.
#
# Verifies a release/bootloader-<N> folder that came back from the air-gapped
# signing PC against the public keys in kern_secure_boot/ (not the copies in
# the folder), then copies each signed bootloader and its manifest line into
# kern_secure_boot/bootloaders/. The folder's SHA256SUMS and GPG signature
# replace the ones in kern_secure_boot/ once they check out against the
# result. Needs no private key.
#
# Usage: bootloader_import.sh <folder>      (or: just bootloader-import <folder>)
#
# A frozen bootloader is never replaced by different bytes under the same
# freeze number. The commit and the bootloader-<N> tag are left to the
# developer; the commands are printed.

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

python3 - "$DIR" "$KERN_SB_DIR" <<'EOF'
import glob, hashlib, os, shutil, subprocess, sys

src, sb_dir = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
dest = os.path.join(sb_dir, "bootloaders")
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
    sys.exit(0)
if not imported:
    sys.exit(0)

# SHA256SUMS must describe kern_secure_boot/ exactly as it is now
sums, sig = os.path.join(src, "SHA256SUMS"), os.path.join(src, "SHA256SUMS.sig")
by_hand = []
if os.path.exists(sums) and os.path.exists(sig):
    listed = dict(reversed(line.split(maxsplit=1)) for line in open(sums).read().splitlines() if line)
    os.chdir(sb_dir)
    expected = set(glob.glob("kern-sb-key?-pub.pem") + glob.glob("kern-sb-digest?.bin") +
                   glob.glob("bootloaders/*/bootloader-signed.bin") + ["bootloaders/BOOTLOADERS"])
    if set(listed) != expected:
        sys.exit(f"Error: SHA256SUMS lists other files than kern_secure_boot/ holds: "
                 f"{sorted(set(listed) ^ expected)}. It was not installed.")
    for path, want in listed.items():
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != want:
            sys.exit(f"Error: {path} does not match SHA256SUMS. It was not installed.")
    if subprocess.run(["gpg", "--verify", sig, sums], capture_output=True).returncode != 0:
        sys.exit("Error: gpg does not verify SHA256SUMS.sig. It was not installed.")
    shutil.copy(sums, "SHA256SUMS")
    shutil.copy(sig, "SHA256SUMS.sig")
    print("  SHA256SUMS and its GPG signature: verified and installed")
else:
    by_hand = ["cd kern_secure_boot",
               "sha256sum kern-sb-key?-pub.pem kern-sb-digest?.bin bootloaders/BOOTLOADERS "
               "bootloaders/*/bootloader-signed.bin > SHA256SUMS",
               "gpg --detach-sign --armor -o SHA256SUMS.sig SHA256SUMS"]

print(f"\nFrozen bootloaders are in {dest}. Left to do by hand:")
for line in by_hand + ["git add kern_secure_boot && git commit"]:
    print(f"  {line}")
for tag, commit in sorted(tags):
    print(f"  git tag {tag} {commit}")
EOF
