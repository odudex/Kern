#!/bin/bash
# Checks on the frozen bootloaders in kern_secure_boot/bootloaders/. None needs
# a private key (docs/secure-boot.md, section 4d).
#
#   check_bootloaders.sh              every frozen bootloader is signed by the
#                                     three public keys and holds the unsigned
#                                     image its manifest line names; SHA256SUMS
#                                     matches the files
#   check_bootloaders.sh --drift      also builds each variant's bootloader from
#                                     this tree and warns when it differs from
#                                     the frozen one: its sources, config or
#                                     ESP-IDF moved since the freeze
#   check_bootloaders.sh --reproduce  also builds each variant's bootloader from
#                                     the commit its manifest line names and
#                                     fails unless it is the frozen image byte
#                                     for byte. Skipped when this ESP-IDF is not
#                                     the manifest's version.
#
# The builds are bootloader-only and mirror `just build-secure <board>
# bootloader`. --reproduce checks each freeze commit out into a temporary
# worktree with its submodules, which takes network access.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KERN_SB_DIR="${KERN_SB_DIR:-$REPO_ROOT/kern_secure_boot}"
MANIFEST="$KERN_SB_DIR/bootloaders/BOOTLOADERS"
MODE="$1"

case "$MODE" in '' | --drift | --reproduce) ;; *)
    echo "Usage: $0 [--drift | --reproduce]" >&2
    exit 1
    ;;
esac

if [ ! -f "$MANIFEST" ]; then
    echo "No frozen bootloaders in $KERN_SB_DIR, nothing to check"
    exit 0
fi

command -v idf.py >/dev/null || source "${IDF_PATH:-$HOME/esp/esp-idf}/export.sh" >/dev/null 2>&1

warn() {
    if [ -n "$GITHUB_ACTIONS" ]; then echo "::warning::$1"; else echo "WARNING: $1"; fi
}

bash "$SCRIPT_DIR/freeze_bootloader.sh" --verify "$KERN_SB_DIR/bootloaders" "$KERN_SB_DIR"
(cd "$KERN_SB_DIR" && sha256sum -c --quiet SHA256SUMS)
LISTED="$(grep -c 'bootloaders/.*/bootloader-signed.bin' "$KERN_SB_DIR/SHA256SUMS" || true)"
FROZEN="$(find "$KERN_SB_DIR/bootloaders" -name bootloader-signed.bin | wc -l)"
if [ "$LISTED" != "$FROZEN" ]; then
    echo "Error: SHA256SUMS lists $LISTED frozen bootloaders, $FROZEN exist" >&2
    exit 1
fi
echo "SHA256SUMS matches the public keys, the manifest and $FROZEN frozen bootloaders"

[ -n "$MODE" ] || exit 0

# Prints the SHA-256 of the unsigned bootloader that source tree $1 builds for device $2
build_bootloader() {
    local src="$1" device="$2" board="${2%_v3}"
    local defaults="sdkconfig.defaults;sdkconfig.defaults.$board"
    [ "$device" = "$board" ] || defaults="$defaults;sdkconfig.rev3"
    local dir="build_secure_$device"
    (
        cd "$src"
        rm -f "$dir/sdkconfig"
        idf.py -B "$dir" -D SDKCONFIG="$dir/sdkconfig" \
            -D "SDKCONFIG_DEFAULTS=$defaults;sdkconfig.release;sdkconfig.secure" bootloader >&2
    )
    sha256sum "$src/$dir/bootloader/bootloader-unsigned.bin" | cut -d' ' -f1
}

IDF_VER="$(idf.py --version | sed 's/^ESP-IDF //')"
FAILED=0

if [ "$MODE" = "--drift" ]; then
    while read -r VARIANT FREEZE TAG COMMIT MANIFEST_IDF SHA BOARDS; do
        case "$VARIANT" in '' | '#'*) continue ;; esac
        DEVICE="${BOARDS%%,*}"
        echo "── $VARIANT: building the bootloader for $DEVICE from this tree ──"
        BUILT="$(build_bootloader "$REPO_ROOT" "$DEVICE" < /dev/null)"
        if [ "$BUILT" = "$SHA" ]; then
            echo "── $VARIANT: this tree still builds the frozen bootloader ──"
        else
            warn "$VARIANT: this tree builds bootloader ${BUILT:0:16}, the frozen one (freeze $FREEZE, ESP-IDF $MANIFEST_IDF) is ${SHA:0:16}. Releases keep shipping the frozen one; check that this app still boots on it."
        fi
    done < "$MANIFEST"
    exit 0
fi

WORK="$(mktemp -d)"
cleanup() {
    for tree in "$WORK"/*/; do
        [ -d "$tree" ] && git -C "$REPO_ROOT" worktree remove --force "$tree" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

while read -r VARIANT FREEZE TAG COMMIT MANIFEST_IDF SHA BOARDS; do
    case "$VARIANT" in '' | '#'*) continue ;; esac
    if [ "$IDF_VER" != "$MANIFEST_IDF" ]; then
        echo "── $VARIANT: skipped, it was frozen on ESP-IDF $MANIFEST_IDF and this is $IDF_VER ──"
        continue
    fi
    TREE="$WORK/$COMMIT"
    if [ ! -d "$TREE" ]; then
        echo "── checking out freeze commit ${COMMIT:0:7} ($TAG) ──"
        git -C "$REPO_ROOT" worktree add --quiet --detach "$TREE" "$COMMIT"
        git -C "$TREE" submodule update --quiet --init --recursive
    fi
    DEVICE="${BOARDS%%,*}"
    echo "── $VARIANT: building the bootloader for $DEVICE from ${COMMIT:0:7} ──"
    BUILT="$(build_bootloader "$TREE" "$DEVICE" < /dev/null)"
    if [ "$BUILT" = "$SHA" ]; then
        echo "── $VARIANT: reproduces from ${COMMIT:0:7} ($SHA) ──"
    else
        echo "Error: $VARIANT built from ${COMMIT:0:7} is $BUILT, the manifest says $SHA" >&2
        FAILED=1
    fi
done < "$MANIFEST"

exit $FAILED
