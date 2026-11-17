# Kern Secure Boot Guide (Phase 6)

> **Warning**: Secure boot burns eFuses permanently. Practice every step on a development board before touching a production device. There is no undo.

This document covers ESP32-P4 Secure Boot v2 as applied to the Kern signing device — key generation, firmware signing, digest burning, and the various user scenarios for locking down a device.

For the broader security roadmap, see [security-plan.md](security-plan.md).

> **Signature scheme note (ESP32-P4):** Kern uses **RSA-3072 (RSA-PSS)**, not ECDSA. ECDSA-based Secure Boot v2 is **not functional on current ESP32-P4 silicon** — see [Section 2](#2-algorithm-choice). Every command in this document uses RSA-3072.

> **Tooling note (ESP-IDF v6.0 / esptool v5):** The `esptool`, `espefuse`, and `espsecure` commands are the v5 console scripts — the old `esptool.py` / `espefuse.py` / `espsecure.py` forms and underscore subcommands (`burn_key`) still work but print deprecation warnings. This guide uses the v5 spelling (no `.py`, hyphenated subcommands).

---

## Table of Contents

1. [How Secure Boot v2 Works](#1-how-secure-boot-v2-works)
2. [Algorithm Choice](#2-algorithm-choice)
3. [Key Management](#3-key-management)
4. [Developer Workflow](#4-developer-workflow)
5. [User Scenarios](#5-user-scenarios)
6. [Key Rotation & Revocation](#6-key-rotation--revocation)
7. [Anti-Rollback](#7-anti-rollback)
8. [sdkconfig.secure Overlay](#8-sdkconfigsecure-overlay)
9. [eFuse Burn Order Summary](#9-efuse-burn-order-summary)
10. [Testing Checklist](#10-testing-checklist)
11. [Security Considerations](#11-security-considerations)
12. [References](#12-references)

---

## 1. How Secure Boot v2 Works

### Signing (build time)

```
Firmware image (all code + data)
    │
    ▼  SHA-256
Image hash (32 bytes)
    │
    ▼  RSA-3072 PSS sign with private key
Signature block (appended to image):
    ├── Public key (3072-bit modulus + exponent + precomputed values)
    └── RSA-PSS signature over image hash
```

The signature covers the SHA-256 hash of the **entire image content** — header, code, and data. An attacker cannot modify any byte of the firmware without invalidating the signature.

### Verification (every boot)

On every boot the ROM bootloader performs these steps for both the second-stage bootloader and the application image (each verified independently):

1. **Hash the full image** — compute SHA-256 over the entire image content (everything except the appended signature block).
2. **Read the signature block** — extract the public key and RSA-PSS signature appended to the image.
3. **Verify the signature** — use the public key to verify the RSA-PSS signature against the image hash from step 1. This proves the image is unmodified since signing.
4. **Verify the public key** — compute SHA-256 of the public key and compare against the digest(s) stored in eFuse key blocks. This proves the signature came from a trusted key.
5. If both checks pass, execution proceeds. Otherwise the chip refuses to boot.

This two-step verification prevents forgery: even if an attacker replaces the signature block with their own key and signature, step 4 will fail because their public key's digest won't match any eFuse slot.

Both the second-stage bootloader and the application image are verified independently — each carries its own signature. An image may carry **up to three appended signatures**; the boot succeeds if any one of them verifies against a non-revoked eFuse digest.

### Digest Slots

The ESP32-P4 provides six eFuse key blocks (BLOCK_KEY0–KEY5). Secure Boot v2 supports up to **three** public-key digest slots. Kern allocates all three:

| eFuse Block | Purpose | Notes |
|-------------|---------|-------|
| KEY0 (BLOCK_KEY0) | Secure Boot Digest 0 — primary signing key | Day-to-day firmware signing |
| KEY1 (BLOCK_KEY1) | Secure Boot Digest 1 — first rotation/backup key | Available for rotation #1 |
| KEY2 (BLOCK_KEY2) | Secure Boot Digest 2 — second rotation/backup key | Available for rotation #2 |

KEY4 holds the NVS-encryption HMAC (Phase 3) and KEY5 the anti-phishing HMAC (Phase 2). KEY3 is unused: Kern does not use flash encryption (see [security-plan.md](security-plan.md#phase-5-flash-encryption-dropped)). Because **all three secure-boot digest slots are populated**, there is no free digest slot for an attacker to inject a rogue signing key.

### Revocation

Each digest slot has a corresponding revocation bit:

- `SECURE_BOOT_KEY_REVOKE0` — revokes KEY0
- `SECURE_BOOT_KEY_REVOKE1` — revokes KEY1
- `SECURE_BOOT_KEY_REVOKE2` — revokes KEY2

Once a revocation bit is set, the ROM bootloader will no longer accept signatures verified by that slot's digest. Revocation is irreversible, and **at least one digest must remain non-revoked** or the device can no longer boot. With three slots, up to two rotations are possible.

> **Do not enable aggressive key revocation** (`CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE`) on Kern. It revokes a digest slot on the *first* failed verification, which would let a single corrupted image permanently burn a good key. For a wallet, the bricking risk outweighs the benefit; this option is left at its default (off).

### Point of No Return

Setting the `SECURE_BOOT_EN` eFuse bit permanently enables secure boot. From that moment:

- Only firmware signed with a key whose digest matches a non-revoked eFuse slot will boot.
- Unsigned firmware written over serial no longer starts, and ROM download mode is restricted to secure download mode (no flash readout).
- The device can only be updated with signed images: the app over SD card (in place since Phase 4), or a signed release over USB.
- The second-stage bootloader on the device stays as it is. SD updates never write it, and replacing it over USB needs another bootloader signed by a non-revoked key. This is why Kern ships a **frozen bootloader** ([Section 4a](#4a-the-frozen-bootloader)).

---

## 2. Algorithm Choice

**Required on ESP32-P4: RSA-3072 (RSA-PSS).**

> **ECDSA is broken on ESP32-P4.** Per Espressif's chip errata and the ESP-IDF v6.1 documentation, "the ECDSA based Secure Boot V2 scheme is not functional for certain input vectors and is therefore not recommended" on ESP32-P4. Enabling it at all requires `CONFIG_SECURE_BOOT_INSECURE` + `CONFIG_SECURE_BOOT_V2_FORCE_ENABLE_ECDSA` — unacceptable for a signing device. A fix is expected in a future silicon ECO revision. Until Kern can gate on a fixed chip revision, **all builds use RSA-3072.**

| Factor | RSA-3072 (RSA-PSS) | ECDSA-P256 |
|--------|--------------------|-----------|
| Functional on ESP32-P4 | **Yes** | **No** (errata; requires INSECURE override) |
| Signature size | 384 bytes | 64 bytes |
| Public key size | 384 bytes | 64 bytes |
| Hardware accel. on ESP32-P4 | Yes (RSA/MPI accelerator) | Yes (ECDSA peripheral) |
| Boot verification speed | ~14.8 ms | ~61.1 ms |
| Ecosystem confusion risk | None | None (P-256 != secp256k1) |

RSA-3072 is not a compromise on ESP32-P4 — it is both the only functional option and the faster one, because the chip's RSA/MPI accelerator verifies RSA-3072 in roughly a quarter of the time of ECDSA-P256. The larger signature block (~384 bytes vs 64) is negligible for a firmware image. There is no risk of confusion with Bitcoin's secp256k1 — RSA and P-256 are entirely different from the curve used for Bitcoin signing.

> Distinct from the ECDSA *signing* peripheral limitation noted in [security-plan.md](security-plan.md) ("ECDSA peripheral — secp256k1 not supported"): that is about on-device Bitcoin signing. The issue here is in the boot-ROM ECDSA *verification* path. Both point to the same conclusion for Kern — do not rely on ECDSA.

---

## 3. Key Management

### 3a. Key Generation

Generate three RSA-3072 signing keys: a primary key and two backup keys for rotation.

```bash
# Primary signing key
espsecure generate-signing-key \
    --version 2 \
    --scheme rsa3072 \
    kern-sb-key0.pem

# First rotation/backup signing key
espsecure generate-signing-key \
    --version 2 \
    --scheme rsa3072 \
    kern-sb-key1.pem

# Second rotation/backup signing key
espsecure generate-signing-key \
    --version 2 \
    --scheme rsa3072 \
    kern-sb-key2.pem
```

**Environment requirements:**

- Air-gapped machine (no network connection) — strongly preferred.
- At minimum: full-disk-encrypted laptop, offline, in a private space.
- Verify the generated key:

```bash
openssl rsa -in kern-sb-key0.pem -text -noout | head -1
# Should show: Private-Key: (3072 bit, 2 primes)
```

### 3b. Key Backup

Private keys are the most critical secret in the secure boot system. If lost, no new firmware can be signed. If leaked, an attacker can sign malicious firmware.

**Storage:** Keep at least 2 encrypted copies of each of the three keys on separate media, stored in physically separate locations. Never store private keys unencrypted or in online services.

### 3c. Public Key Extraction & Distribution

Users who want to burn the developer's digest need the public key digest files. These are safe to publish — they contain no private key material.

**Extract public keys:**

```bash
for n in 0 1 2; do
    espsecure extract-public-key \
        --version 2 \
        --keyfile kern-sb-key${n}.pem \
        kern-sb-key${n}-pub.pem
done
```

**Compute digests:**

```bash
for n in 0 1 2; do
    espsecure digest-sbv2-public-key \
        --keyfile kern-sb-key${n}.pem \
        --output kern-sb-digest${n}.bin
done
```

**Publish in GitHub Releases:**

Each release should include:

```
kern-sb-key0-pub.pem       # Public key 0 (primary)
kern-sb-key1-pub.pem       # Public key 1 (rotation #1)
kern-sb-key2-pub.pem       # Public key 2 (rotation #2)
kern-sb-digest0.bin        # SHA-256 digest of key 0 (32 bytes, for eFuse)
kern-sb-digest1.bin        # SHA-256 digest of key 1 (32 bytes, for eFuse)
kern-sb-digest2.bin        # SHA-256 digest of key 2 (32 bytes, for eFuse)
bootloaders/               # Frozen bootloaders and their manifest (Section 4a)
SHA256SUMS                 # Checksums of all release artifacts
SHA256SUMS.sig             # GPG or SSH signature of SHA256SUMS
```

Include the hex representation of digests in the release notes for visual verification:

```bash
xxd -p kern-sb-digest0.bin | tr -d '\n'
# Example: a1b2c3d4e5f6...  (64 hex chars = 32 bytes)
```

**Generate SHA256SUMS and sign it:**

These files live in `kern_secure_boot/` so users can verify the public keys and digests.

```bash
# Compute checksums of the public key artifacts
sha256sum \
    kern-sb-key0-pub.pem \
    kern-sb-key1-pub.pem \
    kern-sb-key2-pub.pem \
    kern-sb-digest0.bin \
    kern-sb-digest1.bin \
    kern-sb-digest2.bin \
    bootloaders/BOOTLOADERS \
    bootloaders/*/bootloader-signed.bin \
    > SHA256SUMS

# Sign the checksums file with GPG
gpg --detach-sign --armor -o SHA256SUMS.sig SHA256SUMS
```

Users verify with:

```bash
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

**Trust anchor:** The GitHub repository itself, plus the GPG/SSH signature on `SHA256SUMS`. Users verify the signature against the developer's published GPG key or SSH signing key.

### 3d. Embedded Public Key Digests

The public key digests (SHA-256 of the public keys) are not secret — they are derived from the public keys and are safe to distribute. Kern embeds them directly in the firmware binary so that devices can activate secure boot without requiring external files.

**Embedded at build time:** `main/core/sb_digests.cmake` reads `kern_secure_boot/kern-sb-digest{0,1,2}.bin` when CMake configures the build and writes `kern_sb_digests.h` (`KERN_SB_DIGESTS[3][32]`) into the build tree. Only the `.bin` files are checked in, and `SHA256SUMS.sig` already covers them, so the firmware cannot drift from the published digests. Each file must equal `espsecure digest-sbv2-public-key` of the matching public key.

**Self-sovereign builds:** replace the three `.bin` files with the digests of your own public keys (`espsecure digest-sbv2-public-key --keyfile my-keyN-pub.pem -o kern_secure_boot/kern-sb-digestN.bin`) and rebuild; the lockdown menu (Section 5a) then checks the app and bootloader against those keys and burns those digests instead. See Section 5b for the bootloader such a build needs.

### 3e. Key Ceremony Checklist

Use this template when generating signing keys. Fill it in and store alongside the key backups.

```
=== Kern Secure Boot Key Ceremony ===

Date:           ____-__-__
Location:       ___________________________
Performed by:   ___________________________
Machine:        ___________________________ (air-gapped: yes/no)
OS:             ___________________________
ESP-IDF ver:    ___________________________
Scheme:         RSA-3072 (RSA-PSS)

Keys generated:
  [ ] kern-sb-key0.pem  (primary)
  [ ] kern-sb-key1.pem  (rotation #1)
  [ ] kern-sb-key2.pem  (rotation #2)

Verification (openssl rsa -text -noout — confirm 3072 bit):
  Key0 fingerprint (first 8 hex of SHA-256 of PEM):  ________
  Key1 fingerprint (first 8 hex of SHA-256 of PEM):  ________
  Key2 fingerprint (first 8 hex of SHA-256 of PEM):  ________

Public keys extracted:
  [ ] kern-sb-key0-pub.pem
  [ ] kern-sb-key1-pub.pem
  [ ] kern-sb-key2-pub.pem

Digests computed:
  Digest0 (hex): ________________________________________________
  Digest1 (hex): ________________________________________________
  Digest2 (hex): ________________________________________________

Backups (per key):
  [ ] Encrypted USB #1 — location: _______________
  [ ] Encrypted USB #2 — location: _______________
  [ ] Paper backup (optional) — location: _______________

Private key material wiped from ceremony machine:
  [ ] Confirmed (shred -u kern-sb-key*.pem on non-backup machine)

Signed by: ___________________________ (date: ____-__-__)
```

---

## 4. Developer Workflow

### 4a. The Frozen Bootloader

A locked device keeps the bootloader it was locked with. SD updates only write the app slot, and after lockdown the ROM accepts a bootloader only if a non-revoked key signed it. That bootloader also has to carry signatures from **all three** keys, or a later revocation could leave it with none that count (Section 6), and the lockdown menu refuses anything less (Section 5a).

Signing a bootloader with all three keys means taking keys 1 and 2 out of cold storage. Doing that for every release would defeat the reason they are cold. So the bootloader is built, signed once in a key ceremony, and committed; every release after that ships those same bytes. Only the app is built and signed per release, with key 0.

> **Status:** the bootloader component (`bootloader_components/secure_boot_opt_in`), the `sdkconfig.secure` overlay, the dry run, the freeze tooling (`just bootloader-stage`, `scripts/freeze_bootloader.sh`, `just bootloader-import`) and the release-script changes exist, and freeze 1 is published for all four variants (tag `bootloader-1`). The web flasher handles a locked device, verified on a v1.x chip; v3.1 and v3.2 chips are an open question (below). The CI checks described below are planned and not implemented yet.

**Variants.** The bootloader does not depend on the display, touch or camera, so most boards share one. Two settings split it: the chip revision range (v1.x and v3.x need different builds, and the v3 bootloader runs a different CPU clock) and the flash mode (wave_35 uses DIO, the rest QIO). That gives four:

| Variant | Boards |
|---------|--------|
| `v1-qio` | wave_4b, wave_5, wave_43, wave_7b, crowpanel, p4_pico |
| `v1-dio` | wave_35 |
| `v3-qio` | the `_v3` builds of the `v1-qio` boards |
| `v3-dio` | wave_35_v3 |

Measured so far: the release bootloaders of wave_4b, wave_5 and crowpanel are byte-identical, and wave_35's differs. The other rows follow from the board configs and get confirmed when the staging recipe builds every board and groups them by hash. A new board joins an existing variant when its unsigned bootloader matches; otherwise it needs a freeze of its own.

**What a freeze fixes.** These are properties of the bootloader, so on a locked device they change only through a new freeze and a USB reflash:

- The ESP-IDF version the bootloader is built from, and its bugs.
- `secure_boot_opt_in`, which keeps the bootloader from enabling secure boot by itself (Section 5a).
- Anti-rollback: the boot-time refusal of an older app is bootloader code (Section 7).
- The log level and other `sdkconfig.release` settings that reach the bootloader.
- The partition table offset and the bootloader's size limit (56 KB).

Each freeze gets a number in `CONFIG_BOOTLOADER_PROJECT_VER` (`sdkconfig.secure`), which lands in the bootloader's description block. The app can read it (`esp_ota_get_bootloader_description()`), so the Secure Boot page and bug reports can say which freeze a device runs.

**Compatibility rule.** Every release must boot on every frozen bootloader still in the field. An app-side change that needs a newer bootloader is a breaking change for locked devices and needs a re-freeze plus a USB reflash by the user.

**Where it lives.**

```
kern_secure_boot/bootloaders/
    BOOTLOADERS                      # manifest
    v1-qio/bootloader-signed.bin
    v1-dio/bootloader-signed.bin
    v3-qio/bootloader-signed.bin
    v3-dio/bootloader-signed.bin
```

`BOOTLOADERS` has one line per variant: freeze number, git tag and commit, ESP-IDF version, the SHA-256 of the unsigned image, and the boards it serves. `SHA256SUMS` covers the manifest and the binaries, so the existing `SHA256SUMS.sig` vouches for them together with the public keys.

**Anyone can check it.** A secure build writes `bootloader/bootloader-unsigned.bin`, and that file comes out identical across build directories. Building the freeze tag with the manifest's ESP-IDF version must reproduce every byte of the frozen image up to its signature sector, and `espsecure verify-signature` checks the sector against each public key. `bash scripts/freeze_bootloader.sh --verify kern_secure_boot/bootloaders kern_secure_boot` runs both checks on every published variant, without any private key.

**The freeze.**

1. On the build machine, at the commit to freeze: `just bootloader-stage` builds only the bootloader (`sdkconfig.release` + `sdkconfig.secure`) for every board, groups the unsigned images into variants, and stages one per variant in `release/bootloader-<N>/` with the manifest, the public keys and `freeze_bootloader.sh`. It stops if two boards of one variant build different bootloaders. A variant whose frozen image still matches the build is staged with that signature and is not signed again: a signature cannot be reproduced, and devices are locked with those bytes.
2. On the air-gapped signing machine, from that folder, with all three private keys: `bash freeze_bootloader.sh <key0.pem> <key1.pem> <key2.pem>`. It checks each private key against its published digest, so a key in the wrong position stops the run, checks each unsigned image against the manifest, signs it with key 0, appends key 1 and key 2, and verifies the result against the three public keys. It then writes `SHA256SUMS` for `kern_secure_boot/` and signs it with GPG, so the GPG key can stay on that machine too. By hand the signing is:

```bash
espsecure sign-data --version 2 --keyfile kern-sb-key0.pem \
    --output bl-1sig.bin bootloader-unsigned.bin
espsecure sign-data --version 2 --keyfile kern-sb-key1.pem --append-signatures \
    --output bl-2sig.bin bl-1sig.bin
espsecure sign-data --version 2 --keyfile kern-sb-key2.pem --append-signatures \
    --output bootloader-signed.bin bl-2sig.bin

for n in 0 1 2; do
    espsecure verify-signature --version 2 \
        --keyfile kern-sb-key${n}-pub.pem bootloader-signed.bin
done
```

3. Back on the build machine: `just bootloader-import release/bootloader-<N>` verifies the folder against the public keys in `kern_secure_boot/` and copies the signed images and their manifest lines into `kern_secure_boot/bootloaders/`. It refuses to replace a frozen image with different bytes under the same freeze number. It installs the folder's `SHA256SUMS` and `SHA256SUMS.sig` once every listed hash matches the result and GPG verifies the signature. Then commit, and tag the manifest's commit `bootloader-<N>`; the recipe prints those commands.

Fill this in at each freeze and keep it with the key ceremony record (Section 3e):

```
=== Kern Bootloader Freeze ===

Date:            ____-__-__
Freeze number:   ____            (CONFIG_BOOTLOADER_PROJECT_VER)
Git commit/tag:  ___________________________
ESP-IDF version: ___________________________
Anti-rollback:   on / off

Before the ceremony:
  [ ] Dry run passed on this commit (Section 8)
  [ ] An image from this commit was locked for real on a sacrificial board
  [ ] That board took an SD update and a USB reflash after the lock

Per variant (unsigned SHA-256, first 16 hex):
  v1-qio  ________________    [ ] key0  [ ] key1  [ ] key2  [ ] verified
  v1-dio  ________________    [ ] key0  [ ] key1  [ ] key2  [ ] verified
  v3-qio  ________________    [ ] key0  [ ] key1  [ ] key2  [ ] verified
  v3-dio  ________________    [ ] key0  [ ] key1  [ ] key2  [ ] verified

After:
  [ ] Keys 1 and 2 returned to cold storage
  [ ] SHA256SUMS regenerated and signed
  [ ] Committed and tagged bootloader-<N>

Signed by: ___________________________
```

**Re-freeze.** Reasons to do it again: a bootloader bug or security fix, turning anti-rollback on, a new chip revision or flash mode, or an ESP-IDF update whose apps no longer boot on the old bootloader. A re-freeze is the same ceremony with the next number and whichever keys are not revoked. It reaches a device only when its owner reflashes over USB; devices that never do keep the old bootloader, which is why the compatibility rule above holds for as long as an old freeze is in use.

### 4b. Signing a Release

Per release, only the app is signed, and only with key 0. `scripts/release.sh` builds every board with `sdkconfig.release` + `sdkconfig.secure`; `scripts/sign_release.sh` runs on the air-gapped machine:

```bash
espsecure sign-data \
    --version 2 \
    --keyfile kern-sb-key0.pem \
    --output firmware-signed.bin \
    kern-unsigned.bin

espsecure verify-signature \
    --version 2 \
    --keyfile kern-sb-key0-pub.pem \
    firmware-signed.bin
```

The bootloader in each release zip is the frozen one for that board's variant, not the one the release build produced:

- `release.sh` first verifies every frozen bootloader against the three public keys. It then picks each board's variant from the generated sdkconfig (chip revision range and flash mode) and packages `kern_secure_boot/bootloaders/<variant>/bootloader-signed.bin`, and stops if a board has no frozen bootloader.
- It compares the freshly built `bootloader-unsigned.bin` with the frozen image and warns when they differ. A difference means the bootloader sources, their config or ESP-IDF moved since the freeze. The release still ships the frozen one; the warning is the prompt to ask whether a re-freeze is due.
- `sign_release.sh` refuses to package a bootloader that does not verify against all three public keys, which travel in the release folder, and checks every device before it signs anything. It needs no private key for that.

Before publishing, boot the new app on each frozen variant, and install it over SD on the locked reference board.

**Installing a lockable release.** The frozen bootloader reaches a device only over USB, with the web flasher or `esptool`. A device that was installed from an earlier release and kept up to date over SD still has its old bootloader, which does not verify apps at boot; the lockdown menu says so and refuses. One USB install of a release zip fixes that. It does not erase the device: the release image leaves NVS and storage alone.

**USB flashing a locked device.** Secure download mode still writes flash; it refuses to read it. So a locked device can take a new signed app or a newer frozen bootloader over USB. Two things have to hold in the flasher:

- It must write the bootloader unmodified. Rewriting the flash mode, frequency or size in the image header changes the signed bytes and the ROM then rejects the bootloader. esptool leaves image headers alone once it sees secure boot or secure download mode ("Security features enabled, so not changing any flash settings"); any other flasher has to do the same.
- It must tell the ROM the flash size. Secure download mode cannot detect it, and with esptool's `--flash-size keep` the ROM then refuses any write that reaches past 2 MB ("Failed to enter flash download mode", result `0106`), which the app does. So on a locked device: `esptool --chip esp32p4 --no-stub write-flash --flash-mode keep --flash-freq keep --flash-size 16MB 0x2000 bootloader.bin 0x10000 partition-table.bin 0x1e000 ota_data_initial.bin 0x20000 firmware-signed.bin`. The write runs without the stub at about 80 kbit/s (over three minutes for the app) and is not read back, so the boot log is the check: `RSA-PSS secure boot verification succeeded`.
- It must work without the commands secure download mode removes (register reads, the flasher stub). The ROM there also refuses compressed data and blocks larger than 1 KiB.

The web flasher (`site/flash/index.html`) does all of this when it finds the chip in secure download mode. It skips the chip-revision read and asks the user to confirm the revision range the bundle was built for. It turns the CI builds off, since they are not signed with the release keys, and warns when a bundle's bootloader is not signed by all three release keys or its app by none of them. It never rewrites an image header, on any device. It then sets the flash size and writes uncompressed in 1 KiB blocks, about four minutes for a release.

> **Chip revisions v3.1 and later cannot be locked yet.** There the flash is unpowered in download mode and esptool powers it by writing registers, which secure download mode refuses. Measured on a v3.2 chip: a write through the ROM with no register access hangs at the erase, and the same write succeeds once the flash is powered. A locked chip of those revisions could therefore never be flashed over USB again, bootloader included, so the Secure Boot page refuses them (`core/secure_boot.c`, `NO_LOCKED_USB_FLASH_REV`). The eFuse `DOWNLOAD_MODE_XPD_ON` makes the ROM of a v3.2 chip power the flash itself and is the candidate fix; it is untested, and ESP-IDF's eFuse table does not define it.

### 4c. Build Profiles

| Build | Overlays | Bootloader | Use |
|-------|----------|-----------|-----|
| `just build <board>` | board defaults | Plain. Never verifies apps, cannot be locked | Daily development |
| `just build-release <board>` | + `sdkconfig.release` | Plain | Release log and panic settings, for reproducing release behaviour |
| `just build-secure <board>` | + `sdkconfig.release` + `sdkconfig.secure` | Built here, dev-key signed; `bootloader/bootloader-unsigned.bin` is the image a freeze signs | One board's lockable image, for a freeze or a lockdown test |
| `scripts/release.sh` | + `sdkconfig.release` + `sdkconfig.secure` | Frozen, from `kern_secure_boot/bootloaders/` | Published releases |
| `just sbtest-flash <board>` | + `sdkconfig.secure` + `sdkconfig.sbtest` | Test-key signed, virtual eFuses | Dry run of the lockdown (Section 8) |

`sdkconfig.secure` is described in [Section 8](#8-sdkconfigsecure-overlay). Development builds stay without it: `idf.py flash` skips the bootloader when secure boot is configured, and a secure-boot bootloader has no place on a board that is reflashed all day.

### 4d. CI Pipeline

CI builds and never signs; private keys stay off every networked machine.

```
CI:
  1. Build firmware for every board
  2. Check the frozen bootloaders (below)

Developer (air-gapped):
  3. Sign each app with key 0 (scripts/sign_release.sh)
  4. Verify signatures with the public keys
  5. Publish the signed release
```

Checks on the frozen bootloaders, none of which needs a secret:

- Every `bootloader-signed.bin` verifies against all three public keys, and the image before its signature sector hashes to the manifest value.
- When CI's ESP-IDF version equals the manifest's, the bootloader built from the freeze tag matches the frozen one byte for byte. This is what ties the committed binaries to source.
- On every build with `sdkconfig.secure`, a mismatch between the built and the frozen bootloader is reported, as in `release.sh`.

Signing in CI with a key held as a repository secret would be more convenient and is not an option here: a compromised pipeline or account could then sign firmware.

---

## 5. User Scenarios

### 5a. User Burns Developer Digest (Recommended)

The most common scenario: the user trusts the Kern developer's signing keys and burns their digests into their device. After lockdown, only firmware signed by the developer will boot.

The developer's public key digests are embedded in the firmware binary (see [Section 3d](#3d-embedded-public-key-digests)), so the device can activate secure boot entirely through the on-device menu — no external tools, SD card, or terminal commands required.

#### Primary Method: On-Device Lockdown Menu

**Prerequisites:**

- A PIN is set up (it seals KEY4 and KEY5, which must be read-protected before secure boot).
- The device was installed **over USB** from a release that ships the frozen bootloader (Section 4a). SD updates do not replace the bootloader, so a device that only ever updated over SD since an older release needs one USB install first.
- The user has verified the release artifacts with GPG before flashing:

```bash
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

**Steps:**

1. Install the release over USB, with the web flasher or with `esptool` from the unpacked release zip:

```bash
esptool --chip esp32p4 write-flash --flash-mode keep --flash-freq keep --flash-size keep \
    0x2000 bootloader.bin \
    0x10000 partition-table.bin \
    0x1e000 ota_data_initial.bin \
    0x20000 firmware-signed.bin
```

> The ESP32-P4 second-stage bootloader lives at flash offset **0x2000** — not 0x0 or 0x1000 as on older chips. `bootloader.bin` in a release zip is the frozen, triple-signed bootloader for that board. The `keep` options matter: letting esptool rewrite the header would change the signed bytes.

2. Boot into Kern and navigate to **Settings → Security → Secure Boot** (the pre-login Settings).
3. The device displays:
   - The hex representation of Digest 0, Digest 1, and Digest 2 (from the embedded constants).
   - A warning that this action is **irreversible**.
   - The user can compare the displayed digests against those published in the release notes or repository.
4. Confirm by entering the device PIN.
5. The firmware:
   - Verifies that `SECURE_BOOT_EN` is not already set.
   - Verifies the chip revision is below v3.1: later revisions could not be flashed over USB once locked (Section 4b).
   - Verifies that KEY0, KEY1, and KEY2 eFuse blocks are empty — or already contain exactly the three embedded digests, in which case it offers to **resume** an interrupted lockdown (see power-cut note below).
   - Verifies the running app carries a valid signature **and** that the signing key's digest matches one of the embedded digests — a valid signature from a non-matching key would still brick on reboot.
   - Verifies the bootloader image in flash (offset 0x2000): each of the three embedded keys must have a valid signature on it. This is a cryptographic check against the embedded keys, not a comparison of displayed hashes, and it is what ties the device to the frozen bootloader: a bootloader signed by fewer keys, by other keys, or built without secure boot support is refused.
   - Writes `KERN_SB_DIGEST0` to `BLOCK_KEY0` with purpose `SECURE_BOOT_DIGEST0`.
   - Writes `KERN_SB_DIGEST1` to `BLOCK_KEY1` with purpose `SECURE_BOOT_DIGEST1`.
   - Writes `KERN_SB_DIGEST2` to `BLOCK_KEY2` with purpose `SECURE_BOOT_DIGEST2`.
   - Burns the hardening eFuses the stock bootloader would burn alongside secure boot: `DIS_DIRECT_BOOT`, the JTAG-disable set (`DIS_PAD_JTAG`, `DIS_USB_JTAG`, `SOFT_DIS_JTAG`), and secure ROM download mode.
   - Burns the `SECURE_BOOT_EN` eFuse bit.
   - Write-protects `RD_DIS` — otherwise an attacker could later *read-protect* a digest block, blinding the ROM verifier: a permanent brick.
   - Displays confirmation with the final eFuse state.
6. Device reboots. From this point, only firmware signed with `kern-sb-key0.pem`, `kern-sb-key1.pem`, or `kern-sb-key2.pem` will boot.

**Implementation notes:**

`main/core/secure_boot.c` implements the checks and burns; `main/pages/login/secure_boot_page.c` is the menu. The page shows one of four states: not enabled, partially set up (digests burned, `SECURE_BOOT_EN` clear), enabled with the hardening set incomplete, or enabled with the burned digests. When a check fails it names the first one. The burn runs in two eFuse commits, so a power cut can never leave `SECURE_BOOT_EN` set without its digests:

1. The empty digest slots (`esp_efuse_write_key`, batched), then a read-back of all three against the embedded digests. Anything but an exact match stops here.
2. One BLK0 commit: `DIS_DIRECT_BOOT`, `DIS_PAD_JTAG`, `DIS_USB_JTAG`, `SOFT_DIS_JTAG` up to all three bits, secure download mode, `SECURE_BOOT_EN`, and the `RD_DIS` write-protect. Each write is a no-op on a bit that is already burned, so the step can be repeated.

The signature checks use `main/core/sbv2.c`, not IDF's verifier: before lockdown IDF trusts the running app's own keys, so it cannot say whether each *embedded* key signed an image. `sbv2.c` checks a signature sector block by block against a chosen digest (magic, RSA scheme, CRC, image digest, key digest, RSA-PSS), over the image hashed up to its 4 KiB-aligned signature sector as the ROM does; `main/core/test/test_sbv2.c` runs it against espsecure-signed fixtures.

> **The bootloader waits for the menu.** After lockdown the second-stage bootloader must verify every app against the eFuse digests, and IDF only compiles that check with `CONFIG_SECURE_BOOT=y`. A stock `CONFIG_SECURE_BOOT=y` bootloader, however, calls `esp_secure_boot_v2_permanently_enable()` on every boot, and on a chip without `SECURE_BOOT_EN` it burns the digests of its own signature blocks and the hardening set by itself: flashing it would *be* the lockdown, with no PIN, no warning, and possibly before KEY4/KEY5 are sealed. `bootloader_components/secure_boot_opt_in` links that call to a wrapper (`--wrap`) that returns without touching eFuses while `SECURE_BOOT_EN` is clear and runs the stock code once it is set (which then returns at once). Every bootloader-side eFuse write sits behind that one function. Until secure boot is on, the bootloader still checks each app against the app's own signature, so an unsigned image will not boot even then. A bootloader built without `CONFIG_SECURE_BOOT` would pass the ROM after lockdown but boot any app, so the menu refuses on firmware built without it, and a freeze must only ever sign bootloaders built with it (Section 4a).

> **Why secure download mode, not full disable:** flash is not encrypted, so an open ROM download mode would allow flash readout over serial. Secure download mode refuses read commands and keeps USB reflashing of *signed* images, which is the recovery path and the only way to replace a frozen bootloader. Kern does not plan to disable download mode entirely.

**Power-cut resume:** the digest batch and `SECURE_BOOT_EN` are separate eFuse writes. A power cut between them leaves KEY0–KEY2 occupied with secure boot still off. The menu must detect this state (all three blocks match the embedded digests, `SECURE_BOOT_EN` clear) and offer to *complete* the lockdown — a plain "blocks not empty → refuse" guard would make lockdown permanently uncompletable on such a device.

The menu system must enforce:

- PIN entry before anything is burned (status and digests show without it).
- Display of all three digest hex values for visual verification.
- An explicit confirmation prompt warning of irreversibility.
- Verification that the running app **and** the flashed bootloader are signed by keys matching the embedded digests before proceeding (a device that locks down with a mismatched or unsigned image will brick on next boot).
- The power-cut resume path above; refuse only when the key blocks hold *unexpected* data.

#### Alternative Method: Manual Lockdown via espefuse

For advanced users who prefer command-line tools, or for development/testing:

**Prerequisites:**

- `kern-sb-digest0.bin`, `kern-sb-digest1.bin`, and `kern-sb-digest2.bin` downloaded from a GitHub Release.
- `SHA256SUMS` and `SHA256SUMS.sig` from the same release.
- Developer's GPG public key for signature verification.

**Steps:**

```bash
# 1. Verify the release artifacts
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

# 2. Install the release over USB as in step 1 of the on-device method.
#    The bootloader must be the frozen one: after step 5 the ROM rejects
#    any bootloader these keys did not sign.

# 3. Burn the three signing key digests into KEY0, KEY1, KEY2
espefuse --chip esp32p4 burn-key \
    BLOCK_KEY0 kern-sb-digest0.bin SECURE_BOOT_DIGEST0 \
    BLOCK_KEY1 kern-sb-digest1.bin SECURE_BOOT_DIGEST1 \
    BLOCK_KEY2 kern-sb-digest2.bin SECURE_BOOT_DIGEST2

# 4. Burn the hardening eFuses the stock bootloader would burn alongside
#    secure boot (JTAG off, direct boot off). Secure download mode is
#    step 7.
espefuse --chip esp32p4 burn-efuse DIS_DIRECT_BOOT 1
espefuse --chip esp32p4 burn-efuse DIS_PAD_JTAG 1
espefuse --chip esp32p4 burn-efuse DIS_USB_JTAG 1
espefuse --chip esp32p4 burn-efuse SOFT_DIS_JTAG 7

# 5. Enable secure boot — POINT OF NO RETURN
espefuse --chip esp32p4 burn-efuse SECURE_BOOT_EN

# 6. Prevent post-hoc read-protection of the digest blocks
espefuse --chip esp32p4 write-protect-efuse RD_DIS

# 7. Secure download mode, LAST: espefuse needs register reads, and the
#    ROM refuses them from the next reset on, so no espefuse command
#    works after this one.
espefuse --chip esp32p4 burn-efuse ENABLE_SECURITY_DOWNLOAD 1

# 8. Check what is still readable
esptool --chip esp32p4 --no-stub get-security-info
```

After step 5, only firmware signed with `kern-sb-key0.pem`, `kern-sb-key1.pem`, or `kern-sb-key2.pem` will boot on this device.

### 5b. User Builds from Source (Self-Sovereign)

The user generates their own signing keys, replaces the embedded digests, and builds, signs and flashes both the app and the bootloader. They take full responsibility for key management and firmware signing. The frozen bootloaders in `kern_secure_boot/bootloaders/` are of no use here: they carry the developer's signatures, and the lockdown menu of a build with other digests refuses them.

```bash
# Generate own keys
for n in 0 1 2; do
    espsecure generate-signing-key --version 2 --scheme rsa3072 my-key${n}.pem
done

# Replace the embedded digests with your own
for n in 0 1 2; do
    espsecure digest-sbv2-public-key --keyfile my-key${n}.pem \
        -o kern_secure_boot/kern-sb-digest${n}.bin
done

# Build with secure boot support (wave_4b shown)
idf.py -B build_secure -D SDKCONFIG=build_secure/sdkconfig \
    -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_4b;sdkconfig.release;sdkconfig.secure" build

# Sign the app with key 0
espsecure sign-data --version 2 --keyfile my-key0.pem \
    -o firmware-signed.bin build_secure/kern-unsigned.bin

# Sign the bootloader with all three keys
espsecure sign-data --version 2 --keyfile my-key0.pem \
    -o bl-1sig.bin build_secure/bootloader/bootloader-unsigned.bin
espsecure sign-data --version 2 --keyfile my-key1.pem --append-signatures \
    -o bl-2sig.bin bl-1sig.bin
espsecure sign-data --version 2 --keyfile my-key2.pem --append-signatures \
    -o bootloader-signed.bin bl-2sig.bin

# Flash
esptool --chip esp32p4 write-flash --flash-mode keep --flash-freq keep --flash-size keep \
    0x2000 bootloader-signed.bin \
    0x10000 build_secure/partition_table/partition-table.bin \
    0x1e000 build_secure/ota_data_initial.bin \
    0x20000 firmware-signed.bin
```

After flashing, the user activates secure boot from the on-device menu (**Settings → Security → Secure Boot**). The flow is the one in 5a: the firmware does not distinguish "developer" from "user" keys. It checks the running app and the flashed bootloader against whatever the three `.bin` files held at build time, shows those digests, and burns them. That bootloader is this user's own frozen bootloader: keep the signed file, since later app builds have to keep booting on it, and replacing it means signing a new one with the same keys.

Alternatively, the user can burn digests manually with `espefuse` as described in the 5a alternative method, using their own digest `.bin` files.

This is the most sovereign option. The user does not need to trust the Kern developer for firmware integrity — they verify the source code and build it themselves.

### 5c. Hybrid (Developer Key + Own Key)

With three digest slots the user has room to mix trust anchors. Two common layouts:

- **Two developer + one own** (KEY0 = dev0, KEY1 = dev1, KEY2 = own): boots official releases and self-built firmware, but leaves no free slot for rotation.
- **One developer + one own + one spare** (KEY0 = dev0, KEY1 = own, KEY2 = own-rotation): boots official and self-built firmware and keeps a rotation slot for the user's own key.

This scenario **cannot use the on-device menu** in its default form, because the menu burns all three slots from the embedded constants. Instead, the user burns a custom mix with `espefuse`:

```bash
# Example: developer primary + user key + user rotation spare
espefuse --chip esp32p4 burn-key \
    BLOCK_KEY0 kern-sb-digest0.bin SECURE_BOOT_DIGEST0 \
    BLOCK_KEY1 my-digest0.bin      SECURE_BOOT_DIGEST1 \
    BLOCK_KEY2 my-digest1.bin      SECURE_BOOT_DIGEST2

# Then steps 4-7 of the 5a manual method, in that order: the hardening
# eFuses, SECURE_BOOT_EN, the RD_DIS write-protect, and secure download
# mode last
espefuse --chip esp32p4 burn-efuse SECURE_BOOT_EN
```

> The bootloader needs a valid signature from a burned, non-revoked key at all times. The published frozen bootloader is signed by the three developer keys only, so with one developer slot it survives only while that slot is not revoked; a user who wants independence from that signs their own bootloader with their own keys as in 5b.

> If any digest slot is intentionally left **empty**, revoke it before enabling secure boot (`espefuse burn-efuse SECURE_BOOT_KEY_REVOKE2`), so an attacker with physical access cannot later burn their own digest into the free slot.

> **Future work:** An advanced lockdown menu option could allow the user to load one custom digest from SD card and burn it alongside the embedded developer digests. This would support the hybrid scenario without requiring `espefuse`.

**Trust implications:**

- The device will boot firmware signed by **any** burned key. If one key is compromised, the attacker can sign malicious firmware until that slot is revoked.
- The user must trust every party whose key is burned (themselves for their keys, the developer for developer keys).
- Each slot spent on a second trust anchor is a slot not available for rotation. A layout that burns all three slots on trust anchors leaves no rotation headroom.

---

## 6. Key Rotation & Revocation

Kern burns three digests (KEY0/KEY1/KEY2), which enables **up to two key rotations** — one more than a two-slot scheme. Keep at least one non-revoked digest at all times, or the device can no longer boot.

> **Before secure boot is enabled (Phase 4–5 window):** the SD update path trusts only the public keys embedded in the *running* app's signature blocks, so switching signing keys already requires the same dual-signed transition release (steps 1–2 below) — there is just no revocation step, since no eFuses are involved. Once Phase 6 burns all three digests, a release signed with any non-revoked key verifies directly against eFuse, and dual-signing is only needed again as part of an actual revocation (step 3), never for simply starting to sign with a successor key.

### Rotation Procedure

```
Timeline:
  KEY0 = key currently in daily use
  KEY1, KEY2 = successor keys (already burned as digests, not yet used to sign releases)

Step 1: Sign transitional firmware with BOTH the outgoing and incoming key
  espsecure sign-data --version 2 --keyfile kern-sb-key0.pem --output temp.bin build/kern.bin
  espsecure sign-data --version 2 --keyfile kern-sb-key1.pem --append-signatures --output kern-transition.bin temp.bin

Step 2: Release the dual-signed firmware
  Users install it via SD card update (Phase 4)
  Device boots — ROM verifies against KEY0 (outgoing), succeeds

Step 3: After all users have updated, revoke the outgoing key
  espefuse --chip esp32p4 burn-efuse SECURE_BOOT_KEY_REVOKE0

Step 4: Future firmware is signed with the new primary (KEY1)

Second rotation (if ever needed): repeat with KEY1 -> KEY2, then
  espefuse --chip esp32p4 burn-efuse SECURE_BOOT_KEY_REVOKE1
  leaving KEY2 as the sole remaining key.
```

**Constraints:**

- Revocation is irreversible. Once `SECURE_BOOT_KEY_REVOKE0` is burned, KEY0 is permanently rejected.
- The **bootloader on the device must already carry the successor key's signature** (Section 4a). SD updates never replace it, so revoking the only key it was signed with bricks the device. The frozen bootloader carries all three signatures for exactly this reason, and the lockdown menu refuses a bootloader that does not.
- A bootloader frozen after a revocation is signed with the remaining keys only. It still boots on devices that have not revoked yet.
- The transitional firmware **must** be installed on all devices before revoking the outgoing key. Devices that miss the update and still run outgoing-key-only firmware will be bricked after revocation (on the next full boot verification).
- Three slots allow two rotations. After both are spent, only KEY2 remains and no further rotation is possible.

---

## 7. Anti-Rollback

Anti-rollback prevents downgrading to older firmware versions that may contain known vulnerabilities.

### Mechanism

- The ESP-IDF bootloader reads a **security version** from the firmware image header.
- It compares this against an eFuse **monotonic counter**.
- If the image's security version is lower than the eFuse counter, boot is rejected.
- After successful boot, the eFuse counter is updated to match the image's security version (burning additional bits — irreversible).

### It Is Part of the Frozen Bootloader

The boot-time check is bootloader code, compiled in by `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`. A bootloader frozen without it never refuses an older signed app at boot, whatever the app is built with; the app-side check on SD updates would still run, but writing an older signed release over USB would get past them. Turning it on later means a re-freeze and a USB reflash on every device that wants it. So the on/off decision has to be made before the first freeze (Section 4a).

### Partition Layout Requirement

Anti-rollback assumes an **OTA-only** partition table — two `ota_app` slots and no `factory` (stated in ESP-IDF's `bootloader_utility.c`). A factory image is frozen at flash time with security version 0, so the first eFuse counter increment would make it unbootable. Kern's Phase 3 partition migration drops the factory partition accordingly; the fallback role moves to the *previous OTA slot*, which is why the SD update flow must self-test and call `esp_ota_mark_app_valid_cancel_rollback()` after every update (see [security-plan.md Phase 4](security-plan.md#phase-4--air-gapped-sd-card-updates)).

### Configuration

In `sdkconfig.secure` (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`, which it depends on, is in `sdkconfig.defaults`):

```
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16
```

The security version starts at 0, which burns nothing, and is stored in `sdkconfig.secure` as `CONFIG_BOOTLOADER_APP_SECURE_VERSION`. `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD` is the size of the eFuse counter and therefore the number of increments a device gets: 16, the whole field on ESP32-P4. It must never change afterwards, because it is how every build reads the bits already burned.

### When to Increment

Increment the security version **only** for security-critical fixes — not for feature releases or minor bug fixes.

- The security version is independent from the app version in `version.txt`.
- Each increment permanently burns eFuse bits on every device that installs the update.
- The total number of increments is limited by the eFuse counter size.

Example:

| Release | App Version (`version.txt`) | Security Version (eFuse) | Reason |
|---------|---------------------------|-------------------------|--------|
| v0.1.0 | 0.1.0 | 0 | Initial release |
| v0.2.0 | 0.2.0 | 0 | Feature release — no increment |
| v0.2.1 | 0.2.1 | 1 | Critical signing vulnerability fixed |
| v0.3.0 | 0.3.0 | 1 | Feature release — no increment |

---

## 8. sdkconfig.secure Overlay

`sdkconfig.secure` turns a build into one that can be locked from Settings. It is applied on top of the board defaults (and `sdkconfig.release` for releases):

```ini
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y
CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16
```

- `CONFIG_SECURE_INSECURE_ALLOW_DL_MODE` is not an opening: with `CONFIG_SECURE_BOOT` the default download-mode choice is secure download mode, which every app burns at startup (`esp_efuse_startup.c`), locked or not. The Settings lockdown burns it together with `SECURE_BOOT_EN` instead.
- The hardening options IDF ties to `CONFIG_SECURE_BOOT` (JTAG, `RD_DIS`, unused-slot revokes) only act inside `esp_secure_boot_v2_permanently_enable()`, which `secure_boot_opt_in` defers until secure boot is on, and then returns early; the app burns that set itself.
- `CONFIG_SECURE_BOOT_V2_ENABLED` selects `CONFIG_ESPTOOLPY_NO_STUB`, so `idf.py flash` runs without the stub and leaves the bootloader out; write it with esptool at `0x2000`.
- Anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`) is on, at security version 0 (Section 7). It burns `SECURE_VERSION` by itself whenever an app with a higher security version is confirmed, and version 0 burns nothing. It was turned on before the first freeze because the bootloader half of it cannot be added afterwards without a re-freeze.
- Aggressive key revocation stays off: revoking a good key on a single failed verification would be a bricking hazard for a wallet.
- Signing: builds sign with `dev_signing_key.pem`. Releases re-sign the app offline with key 0 and ship the frozen bootloader instead of the built one (Sections 4a, 4b).
- `CONFIG_BOOTLOADER_PROJECT_VER` will carry the freeze number once the first freeze is prepared.

> **Verify every symbol landed.** A plain rebuild can keep stale values. Remove `build_<board>/sdkconfig` and grep the generated `sdkconfig` before trusting the overlay.

### Dry run with virtual eFuses

`just sbtest-flash <board>` builds with `sdkconfig.secure` plus `sdkconfig.sbtest` (`CONFIG_EFUSE_VIRTUAL=y`), signs with test keys (`dev_signing_key.pem` plus two throwaway keys in `build_sbtest_<board>/keys`, whose digests replace the release ones), and flashes it. Every eFuse write in this build goes to a RAM copy of the real eFuses, so the whole Settings flow runs on real hardware and leaves nothing behind after the restart. The board needs a PIN set up with a normal build first: virtual KEY4/KEY5 would not reach the HMAC peripheral. Expect `secure_boot: Off until enabled in Settings` in the bootloader log. `just flash <board>` restores the normal firmware. What it cannot show is the ROM and bootloader enforcing the real digests after `SECURE_BOOT_EN`; that takes a board you are prepared to lock.

## 9. eFuse Burn Order Summary

eFuses must be burned in a specific order. The critical rule: **the read-protected keys (KEY5, KEY4) must be burned before `SECURE_BOOT_EN`** — enabling secure boot write-protects `RD_DIS`, after which no key block can be read-protected. Both are burned during PIN setup, and the lockdown menu refuses to run until they are sealed. See [security-plan.md](security-plan.md#the-hard-constraint-read-protected-keys-before-secure-boot).

| Order | Command | eFuse | Phase | Notes |
|-------|---------|-------|-------|-------|
| 1 | `burn-key BLOCK_KEY5 ... HMAC_UP` | KEY5 | Phase 2 | Anti-phishing HMAC, read-protected. Done by PIN setup |
| 2 | `burn-key BLOCK_KEY4 ... HMAC_UP` | KEY4 | Phase 3 | NVS-encryption HMAC, read-protected. Done by PIN setup |
| 3 | `burn-key BLOCK_KEY0 ... SECURE_BOOT_DIGEST0` | KEY0 | Phase 6 | Primary secure boot digest |
| 4 | `burn-key BLOCK_KEY1 ... SECURE_BOOT_DIGEST1` | KEY1 | Phase 6 | Rotation #1 secure boot digest |
| 5 | `burn-key BLOCK_KEY2 ... SECURE_BOOT_DIGEST2` | KEY2 | Phase 6 | Rotation #2 secure boot digest |
| 6 | `burn-efuse SECURE_BOOT_EN` (+ hardening set) | Control | Phase 6 | **Enables secure boot permanently.** Burned together with `DIS_DIRECT_BOOT`, the JTAG-disable set, secure download mode, then the `RD_DIS` write-protect |

> **Every eFuse burn is irreversible.** Use `espefuse summary` to inspect the eFuse state before the lockdown. Afterwards secure download mode refuses it, and what is left is `esptool --no-stub get-security-info` and the Secure Boot page (Section 10). The whole sequence runs from on-device flows: rows 1–2 during PIN setup, rows 3–6 from the Secure Boot menu. If you ever leave a digest slot empty (a custom hybrid layout), revoke it before enabling secure boot.

---

## 10. Testing Checklist

Complete these steps on a **development board** before any production device.

### Pre-Lockdown

- [ ] Build production firmware with `sdkconfig.secure` overlay
- [ ] Confirm the generated `sdkconfig` has `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y` (not ECDSA)
- [ ] Verify the signed image: `espsecure verify-signature --version 2 --keyfile kern-sb-key0-pub.pem firmware-signed.bin`
- [ ] Confirm the bootloader carries all three signatures (key0/key1/key2)
- [ ] Flash the bootloader and app over USB — confirm the device boots normally and the bootloader logs `Off until enabled in Settings`
- [ ] `espefuse summary` after several boots — nothing burned by the bootloader or the app
- [ ] Read eFuse state: `espefuse summary` — verify KEY0/KEY1/KEY2 are empty
- [ ] Verify embedded digests match published digests: navigate to **Settings → Security → Secure Boot** and compare displayed hex against release notes

### Frozen Bootloader (before each freeze, and its release gate)

- [ ] Every board's unsigned release bootloader falls into one of the expected variants
- [ ] Two builds of the same commit in different directories give the same `bootloader-unsigned.bin`
- [ ] Each frozen image verifies against all three public keys and matches its manifest hash
- [ ] A release zip contains the frozen bootloader for its board, byte for byte
- [ ] A device installed from a pre-freeze release and updated over SD is refused by the lockdown menu with the bootloader message; one USB install of the release zip clears it
- [ ] Each new release boots on every frozen variant still in the field
- [ ] On a locked board: a later release installs over SD and boots
- [ ] On a locked board: the web flasher writes a signed release zip (secure download mode) and the device boots
- [ ] On a locked board: a bootloader with a modified header, or signed by other keys, is rejected by the ROM, and re-flashing the frozen one recovers the device

### Dry Run (virtual eFuses)

- [ ] `just sbtest-flash <board>` on a board with a PIN; the bootloader logs `Off until enabled in Settings` and `espefuse summary` shows nothing new
- [ ] Settings → Security → Secure Boot shows the test-key fingerprints and offers Enable
- [ ] Enable, confirm, enter the PIN: the burn and read-back succeed, the device restarts, real eFuses unchanged

### On-Device Lockdown (Primary Path)

- [ ] Navigate to **Settings → Security → Secure Boot**
- [ ] Verify all three digest hex values are displayed correctly on screen
- [ ] Verify PIN is required before proceeding
- [ ] Verify warning about irreversibility is shown
- [ ] Confirm lockdown — device writes three digests, burns the hardening set, and burns `SECURE_BOOT_EN`
- [ ] Device restarts and boots normally; the ROM prints `Valid secure boot key blocks: 0 1 2` and `RSA-PSS secure boot verification succeeded`
- [ ] `espefuse summary` is now refused (`not supported in Secure Download Mode`): the host can no longer read eFuses
- [ ] `esptool --no-stub get-security-info` — `Secure Boot: Enabled`, chip in Secure Download Mode, `JTAG: Permanently Disabled`, KEY0/KEY1/KEY2 hold `SECURE_BOOT_DIGEST0/1/2`, flags `0xc5` (secure boot, secure download mode, both JTAG disables, no key revoked)
- [ ] The Secure Boot page shows **Enabled** with the three burned digests and the security version, not "Enabled, setup unfinished": it is the only check left for `DIS_DIRECT_BOOT`, `DIS_USB_JTAG`, the `RD_DIS` write-protect and the anti-rollback counter, which the host cannot read any more
- [ ] Attempt JTAG attach — **must fail**

### On-Device Lockdown — Guard Rails

- [ ] Attempt lockdown on a device with `SECURE_BOOT_EN` already set — **must refuse**
- [ ] Attempt lockdown on a device whose KEY0/KEY1/KEY2 hold *unexpected* digests — **must refuse**
- [ ] Pre-burn the three embedded digests via `espefuse` (simulating a power cut before `SECURE_BOOT_EN`), then open the menu — **must offer to resume/complete the lockdown**, not refuse
- [ ] Attempt lockdown with unsigned firmware running — **must refuse** (firmware should detect it is not properly signed and block the operation)
- [ ] Attempt lockdown with firmware signed by a key that does not match the embedded digests — **must refuse**
- [ ] Attempt lockdown with a bootloader that does not carry signatures covering all three embedded digests — **must refuse**
- [ ] Open the page on a chip of revision v3.1 or later — **must refuse**, naming the chip revision

### Manual Lockdown via espefuse (Alternative Path)

- [ ] Burn the three digests: `espefuse burn-key BLOCK_KEY0 digest0.bin SECURE_BOOT_DIGEST0 BLOCK_KEY1 digest1.bin SECURE_BOOT_DIGEST1 BLOCK_KEY2 digest2.bin SECURE_BOOT_DIGEST2`
- [ ] Read eFuse state: `espefuse summary` — verify KEY0/KEY1/KEY2 are programmed
- [ ] Device still boots (secure boot not yet enabled, so unsigned firmware also works)
- [ ] `espefuse burn-efuse SECURE_BOOT_EN`
- [ ] Hardening set burned with `ENABLE_SECURITY_DOWNLOAD` last: every `espefuse` command after it is refused
- [ ] Device boots with signed firmware — **confirm normal operation**

### Post-Lockdown Verification

- [ ] Attempt to flash unsigned firmware via serial — **must fail**
- [ ] Attempt flash readout via ROM download mode — **must fail** (secure download mode)
- [ ] Attempt to flash firmware signed with a different key — **must fail**
- [ ] Sign firmware with key0 → boots successfully
- [ ] Sign firmware with key1 → boots successfully
- [ ] Sign firmware with key2 → boots successfully
- [ ] Sign firmware with a random key → **fails to boot**

### Key Rotation (dev board)

- [ ] Dual-sign firmware with key0 + key1, install, confirm boot
- [ ] Burn `SECURE_BOOT_KEY_REVOKE0`, confirm key0-only firmware no longer boots
- [ ] Confirm key1-signed firmware still boots (the frozen bootloader carries key1's signature)

### Anti-Rollback (eFuse-enforced from this phase; SD update path exists since Phase 4)

- [ ] Install firmware with security version 1
- [ ] Attempt to install firmware with security version 0 via SD card — **must be rejected**
- [ ] Counter is 1: the Secure Boot page of a locked device shows `Security version 1`; on an unlocked board `espefuse summary` shows `SECURE_VERSION`
- [ ] Write the security version 0 firmware over USB — the bootloader **must refuse it** (`No bootable app partitions`), and writing version 1 back must recover the device

### Recovery

- [ ] After secure boot is enabled, re-run the Phase 4d SD update validation suite — all tests must pass
- [ ] Simulate power loss during SD card update — device should boot from previous slot

---

## 11. Security Considerations

### Key Compromise

If a signing key's private key is leaked:

- An attacker can sign malicious firmware that will pass secure boot verification until that key's slot is revoked.
- **Mitigation**: Revoke the compromised key's digest slot and rotate to a successor key (see [Section 6](#6-key-rotation--revocation)). With three slots, Kern can absorb up to two independent compromises/rotations. This requires that a dual-signed transitional firmware was distributed *before* revocation.
- If every burned key is compromised, there is no recovery — the device will accept attacker-signed firmware indefinitely.

### Lost Keys

If all copies of a signing key are lost:

- No new firmware can be signed with that key.
- If the device only has that key's digest un-revoked, it becomes un-updatable.
- **Mitigation**: Always maintain redundant backups (Section 3b) and burn three digests (KEY0 + KEY1 + KEY2), so a lost or compromised primary can be rotated out.

### A Flaw in the Frozen Bootloader

The frozen bootloader is the one piece of Kern's code an SD update cannot fix. A bug in it stays on every locked device until its owner reflashes a re-frozen bootloader over USB. It is therefore kept small (stock ESP-IDF plus the `secure_boot_opt_in` wrapper), validated on a board that is really locked before the freeze, and reproducible from a tagged commit so that others can review exactly what was signed.

### Supply Chain Attacks

- A compromised build environment could inject malicious code before signing.
- **Mitigation**: Build on a trusted, air-gapped machine. The frozen bootloader is reproducible from its tag today (Section 4a); reproducible app builds (future work) would extend that to every release.
- Pre-flashed devices from untrusted sources could have attacker digests burned.
- **Mitigation**: Lock the device yourself. `espefuse summary` shows the eFuse state of a device that is not locked yet. A locked one cannot be read that way: `esptool --no-stub get-security-info` shows which key slots hold digests but not their values, so install the official release over USB and compare the digests on its Secure Boot page with the published ones.

### Cross-Phase Dependencies

Secure boot alone does not protect against all threats:

| Threat | Requires |
|--------|----------|
| NVS data readout (PIN hash) | NVS Encryption (Phase 3) |
| Firmware downgrade | Anti-Rollback (this phase) + SD card updates (Phase 4) |
| JTAG/debug access | Burned off by the lockdown itself |
| Flash readout by desoldering | Not covered: flash is not encrypted. Nothing secret is stored there in plaintext (PIN hash under NVS encryption, mnemonics as KEF); saved plaintext descriptors are a privacy exposure |
| PSRAM probing on a running device | Not covered: secrets stay in internal RAM, working buffers do not |

Secure boot provides firmware integrity and is the last lockdown step. The uncovered rows are accepted risks, listed in [security-plan.md](security-plan.md#accepted-residual-risks).

### Anti-Phishing Synergy

With secure boot enabled, the anti-phishing words (Phase 2) become a strong tamper-detection guarantee. Before secure boot, malicious firmware on the same chip could fake the anti-phishing display. After secure boot, only signed firmware runs, closing this gap.

---

## 12. References

- [ESP-IDF Secure Boot v2 Documentation (ESP32-P4)](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32p4/security/secure-boot-v2.html) — includes the ECDSA "not functional on ESP32-P4" advisory
- [ESP-IDF Anti-Rollback](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32p4/api-reference/system/ota.html#anti-rollback)
- [ESP-IDF 6.0 Security Migration Guide](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32/migration-guides/release-6.x/6.0/security.html) — removed/renamed APIs, NISTP192 deprecation
- [espefuse Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espefuse/)
- [espsecure Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espsecure/)
- [esptool v5 Migration Guide](https://docs.espressif.com/projects/esptool/en/latest/esp32/migration-guide.html) — `.py` drop and hyphenated subcommands
- [Kern Security Plan](security-plan.md) — full security roadmap and eFuse allocation table
