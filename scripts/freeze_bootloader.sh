#!/bin/bash
# Kern bootloader freeze, step 2 of 3 — runs on the AIR-GAPPED signing PC.
#
# For each bootloader variant staged by bootloader_stage.sh, this script:
#   1. checks the unsigned image against the SHA-256 in the BOOTLOADERS manifest
#   2. signs it with the three Secure Boot v2 RSA-3072 keys (key 0, then keys 1
#      and 2 appended), unless the variant already carries its frozen signature
#   3. verifies the result against the three public keys in the folder
# and finally writes SHA256SUMS for kern_secure_boot/ (public keys, manifest
# and signed bootloaders, under the paths they have there) and signs it with
# GPG. KERN_GPG_KEY picks a key other than the default one.
#
# Usage (from inside the release/bootloader-<N> folder on the SD card):
#
#   bash freeze_bootloader.sh <key0.pem> <key1.pem> <key2.pem> [folder]
#
# folder defaults to the directory this script sits in. Each private key is
# checked against its published digest before anything is signed, so a key in
# the wrong position stops the run.
#
# Without private keys it only verifies, which is what bootloader_import.sh and
# anyone checking the published bootloaders use:
#
#   bash freeze_bootloader.sh --verify [folder] [public-key-folder]
#
# Requirements: bash, python3, sha256sum, gpg and the esptool pip package
# (provides espsecure; python3 -m espsecure is used if the CLI is not on PATH).
#
# Input per variant:  <variant>/bootloader-unsigned.bin
# Output per variant: <variant>/bootloader-signed.bin
# Plus:               SHA256SUMS, SHA256SUMS.sig
#
# A signature cannot be reproduced: signing the same image again gives different
# bytes. A variant that already has bootloader-signed.bin is never signed again.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECTOR=4096

if [ "$1" = "--verify" ]; then
    VERIFY_ONLY=1
    DIR="${2:-$SCRIPT_DIR}"
    PUB_DIR="${3:-$DIR}"
else
    VERIFY_ONLY=
    KEYS=("$1" "$2" "$3")
    DIR="${4:-$SCRIPT_DIR}"
    PUB_DIR="$DIR"
    for n in 0 1 2; do
        if [ -z "${KEYS[$n]}" ] || [ ! -f "${KEYS[$n]}" ]; then
            echo "Usage: $0 <key0.pem> <key1.pem> <key2.pem> [folder]" >&2
            echo "       $0 --verify [folder] [public-key-folder]" >&2
            echo "Error: signing key $n not found: '${KEYS[$n]}'" >&2
            exit 1
        fi
    done
fi

MANIFEST="$DIR/BOOTLOADERS"
if [ ! -f "$MANIFEST" ]; then
    echo "Error: no BOOTLOADERS manifest in $DIR" >&2
    exit 1
fi

if command -v espsecure >/dev/null 2>&1; then
    ESPSECURE="espsecure"
elif python3 -c "import espsecure" >/dev/null 2>&1; then
    ESPSECURE="python3 -m espsecure"
else
    echo "Error: espsecure not found. Install esptool (pip install esptool)." >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -z "$VERIFY_ONLY" ]; then
    for n in 0 1 2; do
        $ESPSECURE digest-sbv2-public-key --keyfile "${KEYS[$n]}" \
            --output "$TMP/digest$n.bin" >/dev/null
        if ! cmp -s "$TMP/digest$n.bin" "$PUB_DIR/kern-sb-digest$n.bin"; then
            echo "Error: '${KEYS[$n]}' is not key $n (kern-sb-digest$n.bin differs)" >&2
            exit 1
        fi
    done
    echo "The three private keys match the published digests"
fi

# The signed image is the unsigned one padded to a sector, then the signature
# sector. Without the unsigned file, the manifest hash stands in for it.
check_body() {
    python3 - "$1" "$2" "$3" "$SECTOR" <<'EOF'
import hashlib, os, sys
signed, unsigned, want, sector = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = open(signed, "rb").read()
if len(s) % sector or len(s) < 2 * sector:
    sys.exit("signed image is not a whole number of sectors")
body = s[:-sector]
if os.path.exists(unsigned):
    u = open(unsigned, "rb").read()
    ok = body == u + b"\xff" * (-len(u) % sector)
else:
    n, ok = len(body), False
    while True:
        if hashlib.sha256(body[:n]).hexdigest() == want:
            ok = True
            break
        if len(body) - n >= sector - 1 or body[n - 1] != 0xFF:
            break
        n -= 1
sys.exit(0 if ok else "signed image does not hold the manifest's unsigned image")
EOF
}

# Every input is checked before the first signature is made
while read -r VARIANT FREEZE TAG COMMIT IDF_VER SHA BOARDS; do
    case "$VARIANT" in '' | '#'*) continue ;; esac
    UNSIGNED="$DIR/$VARIANT/bootloader-unsigned.bin"
    if [ -f "$UNSIGNED" ]; then
        HAVE="$(sha256sum "$UNSIGNED" | cut -d' ' -f1)"
        if [ "$HAVE" != "$SHA" ]; then
            echo "Error: $UNSIGNED is $HAVE, the manifest says $SHA" >&2
            exit 1
        fi
    elif [ -z "$VERIFY_ONLY" ] && [ ! -f "$DIR/$VARIANT/bootloader-signed.bin" ]; then
        echo "Error: $UNSIGNED is missing" >&2
        exit 1
    fi
done < "$MANIFEST"

SIGNED=0
PENDING=0
while read -r VARIANT FREEZE TAG COMMIT IDF_VER SHA BOARDS; do
    case "$VARIANT" in '' | '#'*) continue ;; esac
    UNSIGNED="$DIR/$VARIANT/bootloader-unsigned.bin"
    OUT="$DIR/$VARIANT/bootloader-signed.bin"

    if [ -f "$OUT" ]; then
        STATE="${VERIFY_ONLY:+signed}"
        STATE="${STATE:-already signed, left as it is}"
    elif [ -n "$VERIFY_ONLY" ]; then
        echo "── $VARIANT: not signed yet ──"
        PENDING=$((PENDING + 1))
        continue
    else
        echo "── $VARIANT (freeze $FREEZE, $BOARDS): signing ${SHA:0:16} ──"
        $ESPSECURE sign-data --version 2 --keyfile "${KEYS[0]}" \
            --output "$TMP/1sig.bin" "$UNSIGNED" >/dev/null
        $ESPSECURE sign-data --version 2 --keyfile "${KEYS[1]}" --append-signatures \
            --output "$TMP/2sig.bin" "$TMP/1sig.bin" >/dev/null
        $ESPSECURE sign-data --version 2 --keyfile "${KEYS[2]}" --append-signatures \
            --output "$TMP/3sig.bin" "$TMP/2sig.bin" >/dev/null
        cp "$TMP/3sig.bin" "$OUT"
        STATE="signed"
    fi

    check_body "$OUT" "$UNSIGNED" "$SHA"
    for n in 0 1 2; do
        if ! $ESPSECURE verify-signature --version 2 \
            --keyfile "$PUB_DIR/kern-sb-key$n-pub.pem" "$OUT" >/dev/null 2>&1; then
            echo "Error: $OUT is not signed by key $n" >&2
            exit 1
        fi
    done
    echo "── $VARIANT: $STATE, verified against keys 0, 1 and 2 ($(sha256sum "$OUT" | cut -c1-16)) ──"
    SIGNED=$((SIGNED + 1))
done < "$MANIFEST"

echo
echo "$SIGNED variant(s) signed and verified, $PENDING not signed"
[ -z "$VERIFY_ONLY" ] || exit 0

sum_line() {
    printf '%s  %s\n' "$(sha256sum "$1" | cut -d' ' -f1)" "$2"
}
{
    for n in 0 1 2; do sum_line "$DIR/kern-sb-key$n-pub.pem" "kern-sb-key$n-pub.pem"; done
    for n in 0 1 2; do sum_line "$DIR/kern-sb-digest$n.bin" "kern-sb-digest$n.bin"; done
    sum_line "$MANIFEST" "bootloaders/BOOTLOADERS"
    while read -r VARIANT REST; do
        case "$VARIANT" in '' | '#'*) continue ;; esac
        sum_line "$DIR/$VARIANT/bootloader-signed.bin" "bootloaders/$VARIANT/bootloader-signed.bin"
    done < "$MANIFEST"
} > "$TMP/SHA256SUMS"

# An unchanged, already signed SHA256SUMS is left alone
if ! cmp -s "$TMP/SHA256SUMS" "$DIR/SHA256SUMS" || [ ! -f "$DIR/SHA256SUMS.sig" ]; then
    cp "$TMP/SHA256SUMS" "$DIR/SHA256SUMS"
    rm -f "$DIR/SHA256SUMS.sig"
    echo "── SHA256SUMS written, signing it with GPG ──"
    if ! command -v gpg >/dev/null 2>&1 ||
        ! gpg ${KERN_GPG_KEY:+--local-user "$KERN_GPG_KEY"} --detach-sign --armor \
            --output "$DIR/SHA256SUMS.sig" "$DIR/SHA256SUMS"; then
        echo "SHA256SUMS is NOT signed. The bootloaders are; sign it by hand with:" >&2
        echo "  gpg --detach-sign --armor -o SHA256SUMS.sig SHA256SUMS" >&2
    fi
fi

echo "Next: take the folder back to the build machine and run"
echo "  just bootloader-import <folder>"
