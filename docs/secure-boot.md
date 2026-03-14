# Kern Secure Boot Guide (Phase 3)

> **Warning**: Secure boot burns eFuses permanently. Practice every step on a development board before touching a production device. There is no undo.

This document covers ESP32-P4 Secure Boot v2 as applied to the Kern hardware wallet — key generation, firmware signing, digest burning, and the various user scenarios for locking down a device.

For the broader security roadmap, see [security-plan.md](security-plan.md).

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
    ▼  ECDSA-P256 sign with private key
Signature block (appended to image):
    ├── Public key
    └── Signature over image hash
```

The signature covers the SHA-256 hash of the **entire image content** — header, code, and data. An attacker cannot modify any byte of the firmware without invalidating the signature.

### Verification (every boot)

On every boot the ROM bootloader performs these steps for both the second-stage bootloader and the application image (each verified independently):

1. **Hash the full image** — compute SHA-256 over the entire image content (everything except the appended signature block).
2. **Read the signature block** — extract the public key and ECDSA signature appended to the image.
3. **Verify the signature** — use the public key to verify the ECDSA signature against the image hash from step 1. This proves the image is unmodified since signing.
4. **Verify the public key** — compute SHA-256 of the public key and compare against the digest(s) stored in eFuse key blocks. This proves the signature came from a trusted key.
5. If both checks pass, execution proceeds. Otherwise the chip refuses to boot.

This two-step verification prevents forgery: even if an attacker replaces the signature block with their own key and signature, step 4 will fail because their public key's digest won't match any eFuse slot.

Both the second-stage bootloader and the application image are verified independently — each carries its own signature.

### Digest Slots

The ESP32-P4 provides multiple eFuse key blocks. Kern allocates two for secure boot:

| eFuse Block | Purpose | Notes |
|-------------|---------|-------|
| KEY0 (BLOCK_KEY0) | Secure Boot Digest 0 — primary signing key | Day-to-day firmware signing |
| KEY1 (BLOCK_KEY1) | Secure Boot Digest 1 — backup/rotation key | Key rotation or hybrid scenario |

KEY2–KEY3 are reserved for flash encryption (Phase 5). KEY4–KEY5 are reserved for HMAC (Phases 2, 6).

### Revocation

Each digest slot has a corresponding revocation bit:

- `SECURE_BOOT_KEY_REVOKE0` — revokes KEY0
- `SECURE_BOOT_KEY_REVOKE1` — revokes KEY1

Once a revocation bit is set, the ROM bootloader will no longer accept signatures verified by that slot's digest. Revocation is irreversible.

### Point of No Return

Setting the `SECURE_BOOT_EN` eFuse bit permanently enables secure boot. From that moment:

- Only firmware signed with a key whose digest matches a non-revoked eFuse slot will boot.
- Serial flashing of unsigned firmware is blocked (UART download mode is restricted).
- The device can only be updated via signed images (SD card OTA after Phase 4).

---

## 2. Algorithm Choice

**Recommended: ECDSA with NIST P-256 (secp256r1)**

| Factor | ECDSA-P256 | RSA-3072 |
|--------|-----------|----------|
| Signature size | 64 bytes | 384 bytes |
| Public key size | 64 bytes | 384 bytes |
| Hardware accel. on ESP32-P4 | Yes (ECDSA peripheral) | No |
| Boot verification speed | Faster | Slower |
| Ecosystem confusion risk | None (P-256 != secp256k1) | None |

ECDSA-P256 is the clear choice: smaller signatures, faster verification, and hardware support. There is no risk of confusion with Bitcoin's secp256k1 — they are entirely different curves used in different contexts.

RSA-3072 (RSA-PSS) is a valid alternative if there is a specific reason to prefer it. The commands in this document use ECDSA-P256.

---

## 3. Key Management

### 3a. Key Generation

Generate two ECDSA-P256 signing keys: a primary key and a backup key for rotation.

```bash
# Primary signing key
espsecure.py generate_signing_key \
    --version 2 \
    --scheme ecdsa256 \
    kern-sb-key0.pem

# Backup/rotation signing key
espsecure.py generate_signing_key \
    --version 2 \
    --scheme ecdsa256 \
    kern-sb-key1.pem
```

**Environment requirements:**

- Air-gapped machine (no network connection) — strongly preferred.
- At minimum: full-disk-encrypted laptop, offline, in a private space.
- Verify the generated key:

```bash
openssl ec -in kern-sb-key0.pem -text -noout
# Should show: ASN1 OID: prime256v1 (aka P-256)
```

### 3b. Key Backup

Private keys are the most critical secret in the secure boot system. If lost, no new firmware can be signed. If leaked, an attacker can sign malicious firmware.

**Storage:** Keep at least 2 encrypted copies of each key on separate media, stored in physically separate locations. Never store private keys unencrypted or in online services.

### 3c. Public Key Extraction & Distribution

Users who want to burn the developer's digest need the public key digest files. These are safe to publish — they contain no private key material.

**Extract public keys:**

```bash
espsecure.py extract_public_key \
    --keyfile kern-sb-key0.pem \
    kern-sb-key0-pub.pem

espsecure.py extract_public_key \
    --keyfile kern-sb-key1.pem \
    kern-sb-key1-pub.pem
```

**Compute digests:**

```bash
espsecure.py digest_sbv2_public_key \
    --keyfile kern-sb-key0.pem \
    --output kern-sb-digest0.bin

espsecure.py digest_sbv2_public_key \
    --keyfile kern-sb-key1.pem \
    --output kern-sb-digest1.bin
```

**Publish in GitHub Releases:**

Each release should include:

```
kern-sb-key0-pub.pem       # Public key 0
kern-sb-key1-pub.pem       # Public key 1
kern-sb-digest0.bin        # SHA-256 digest of key 0 (32 bytes, for eFuse)
kern-sb-digest1.bin        # SHA-256 digest of key 1 (32 bytes, for eFuse)
SHA256SUMS                 # Checksums of all release artifacts
SHA256SUMS.sig             # GPG or SSH signature of SHA256SUMS
```

Include the hex representation of digests in the release notes for visual verification:

```bash
xxd -p kern-sb-digest0.bin | tr -d '\n'
# Example: a1b2c3d4e5f6...  (64 hex chars = 32 bytes)
```

**Generate SHA256SUMS and sign it:**

These files are checked into the project root so users can verify the public keys and digests.

```bash
# From the project root, compute checksums of the public key artifacts
sha256sum \
    kern-sb-key0-pub.pem \
    kern-sb-key1-pub.pem \
    kern-sb-digest0.bin \
    kern-sb-digest1.bin \
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

**Generated header:**

A build-time script generates a header from the configured public keys:

```bash
# scripts/generate_sb_digests.h.py
# Reads public key PEM files and outputs a C header with digest constants.
# Usage: python scripts/generate_sb_digests.h.py \
#            kern-sb-key0-pub.pem kern-sb-key1-pub.pem \
#            > components/secure_boot/include/kern_sb_digests.h
```

The generated header contains:

```c
// kern_sb_digests.h — AUTO-GENERATED, DO NOT EDIT
// Rebuild with: just generate-sb-digests

#pragma once
#include <stdint.h>

// SHA-256 of kern-sb-key0-pub.pem (primary)
static const uint8_t KERN_SB_DIGEST0[32] = {
    0xa1, 0xb2, 0xc3, 0xd4, /* ... 32 bytes total ... */
};

// SHA-256 of kern-sb-key1-pub.pem (backup/rotation)
static const uint8_t KERN_SB_DIGEST1[32] = {
    0xe5, 0xf6, 0x07, 0x18, /* ... 32 bytes total ... */
};

// Number of developer digest slots
#define KERN_SB_DEVELOPER_DIGEST_COUNT 2
```

**Build integration:**

```bash
# Justfile target
generate-sb-digests:
    python scripts/generate_sb_digests.h.py \
        kern-sb-key0-pub.pem kern-sb-key1-pub.pem \
        > components/secure_boot/include/kern_sb_digests.h
```

The generated header is checked into the repository. It changes only when the signing keys change (which should be extremely rare — ideally never after the initial key ceremony). CI can verify that the header matches the public keys in the repo.

**Self-sovereign builds:** Users building from source with their own keys run `just generate-sb-digests` with their own public key files. The header is regenerated with their digests, and the firmware-driven lockdown menu (Section 5a) will burn those instead.

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

Keys generated:
  [ ] kern-sb-key0.pem  (primary)
  [ ] kern-sb-key1.pem  (backup/rotation)

Verification (openssl ec -text -noout):
  Key0 fingerprint (first 8 hex of SHA-256 of PEM):  ________
  Key1 fingerprint (first 8 hex of SHA-256 of PEM):  ________

Public keys extracted:
  [ ] kern-sb-key0-pub.pem
  [ ] kern-sb-key1-pub.pem

Digests computed:
  Digest0 (hex): ________________________________________________
  Digest1 (hex): ________________________________________________

Backups:
  [ ] Encrypted USB #1 — location: _______________
  [ ] Encrypted USB #2 — location: _______________
  [ ] Paper backup (optional) — location: _______________

Private key material wiped from ceremony machine:
  [ ] Confirmed (shred -u kern-sb-key*.pem on non-backup machine)

Signed by: ___________________________ (date: ____-__-__)
```

---

## 4. Developer Workflow

### 4a. Signing Firmware

When `CONFIG_SECURE_BOOT=y` and the signing key path is configured in sdkconfig, the ESP-IDF build system automatically signs the bootloader and app images.

**Manual signing** (for air-gapped workflows where the build machine doesn't have the key):

```bash
# Sign the app image
espsecure.py sign_data \
    --version 2 \
    --keyfile kern-sb-key0.pem \
    --output kern-signed.bin \
    build/kern.bin

# Sign the bootloader
espsecure.py sign_data \
    --version 2 \
    --keyfile kern-sb-key0.pem \
    --output bootloader-signed.bin \
    build/bootloader/bootloader.bin
```

**Verify a signature:**

```bash
espsecure.py verify_signature \
    --version 2 \
    --keyfile kern-sb-key0-pub.pem \
    kern-signed.bin
```

### 4b. Dev vs. Production Builds

Maintain two sdkconfig profiles:

| Profile | Secure Boot | Serial Flash | Use Case |
|---------|-------------|-------------|----------|
| `sdkconfig.defaults` | Disabled | Works | Daily development, debugging |
| `sdkconfig.defaults` + `sdkconfig.secure` | Enabled | Blocked after lockdown | Production releases |

**Development build** (default):

```bash
idf.py build
# or
just build
```

**Production build** (with secure boot overlay):

```bash
idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.secure" build
```

The `sdkconfig.secure` overlay is defined in [Section 8](#8-sdkconfigsecure-overlay).

### 4c. CI Pipeline

**Recommended approach: CI builds unsigned, developer signs locally.**

This keeps private keys off any networked machine.

```
CI Pipeline:
  1. Build firmware (no signing key configured)
  2. Upload unsigned .bin as build artifact
  3. Verify build reproducibility (optional)

Developer (air-gapped):
  4. Download unsigned .bin
  5. Sign with espsecure.py sign_data
  6. Verify signature with public key
  7. Upload signed .bin to GitHub Release
```

**CI verification** (runs on every build, uses public key only):

```bash
# CI can verify that a release binary was signed correctly
espsecure.py verify_signature \
    --version 2 \
    --keyfile kern-sb-key0-pub.pem \
    kern-signed.bin
```

**Alternative: CI signing with GitHub encrypted secrets.** The signing key is stored as a GitHub encrypted secret and used during CI builds. This is more convenient but increases the attack surface — a compromised CI pipeline or GitHub account could sign malicious firmware. Not recommended for a security-critical project like a hardware wallet.

---

## 5. User Scenarios

### 5a. User Burns Developer Digest (Recommended)

The most common scenario: the user trusts the Kern developer's signing key and burns its digest into their device. After lockdown, only firmware signed by the developer will boot.

The developer's public key digests are embedded in the firmware binary (see [Section 3d](#3d-embedded-public-key-digests)), so the device can activate secure boot entirely through the on-device menu — no external tools, SD card, or terminal commands required.

#### Primary Method: On-Device Lockdown Menu

**Prerequisites:**

- Device running signed Kern firmware (flashed via serial before lockdown).
- The user has verified the release artifacts with GPG before flashing:

```bash
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

**Steps:**

1. Flash the signed firmware via serial (last time serial will work):

```bash
esptool.py --chip esp32p4 write_flash \
    0x0 bootloader-signed.bin \
    0x20000 kern-signed.bin
```

2. Boot into Kern and navigate to **Settings → Secure Boot → Lock with Developer Keys**.
3. The device displays:
   - The hex representation of Digest 0 and Digest 1 (from the embedded constants).
   - A warning that this action is **irreversible**.
   - The user can compare the displayed digests against those published in the release notes or repository.
4. Confirm by entering the device PIN.
5. The firmware:
   - Verifies that `SECURE_BOOT_EN` is not already set.
   - Verifies that KEY0 and KEY1 eFuse blocks are empty.
   - Writes `KERN_SB_DIGEST0` to `BLOCK_KEY0` with purpose `SECURE_BOOT_DIGEST0`.
   - Writes `KERN_SB_DIGEST1` to `BLOCK_KEY1` with purpose `SECURE_BOOT_DIGEST1`.
   - Burns the `SECURE_BOOT_EN` eFuse bit.
   - Displays confirmation with the final eFuse state.
6. Device reboots. From this point, only firmware signed with `kern-sb-key0.pem` or `kern-sb-key1.pem` will boot.

**Implementation notes:**

The lockdown function should follow this sequence:

```c
#include "esp_efuse.h"
#include "kern_sb_digests.h"

esp_err_t kern_secure_boot_lockdown(void) {
    // 1. Pre-flight checks
    //    - Verify SECURE_BOOT_EN is not already set
    //    - Verify KEY0 and KEY1 blocks are empty
    //    - Verify the running firmware is properly signed

    // 2. Burn digests
    esp_efuse_write_key(EFUSE_BLK_KEY0,
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0,
        KERN_SB_DIGEST0, 32);

    esp_efuse_write_key(EFUSE_BLK_KEY1,
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1,
        KERN_SB_DIGEST1, 32);

    // 3. Enable secure boot — POINT OF NO RETURN
    esp_efuse_write_field_bit(ESP_EFUSE_SECURE_BOOT_EN);

    return ESP_OK;
}
```

The menu system must enforce:

- PIN entry before showing the lockdown option.
- Display of both digest hex values for visual verification.
- An explicit confirmation prompt warning of irreversibility.
- Verification that the running firmware is signed before proceeding (a device that locks down with unsigned firmware running will brick on next boot).

#### Alternative Method: Manual Lockdown via espefuse.py

For advanced users who prefer command-line tools, or for development/testing:

**Prerequisites:**

- `kern-sb-digest0.bin` and `kern-sb-digest1.bin` downloaded from a GitHub Release.
- `SHA256SUMS` and `SHA256SUMS.sig` from the same release.
- Developer's GPG public key for signature verification.

**Steps:**

```bash
# 1. Verify the release artifacts
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

# 2. Flash the signed firmware via serial (last time serial will work)
esptool.py --chip esp32p4 write_flash \
    0x0 bootloader-signed.bin \
    0x20000 kern-signed.bin

# 3. Burn the primary signing key digest into KEY0
espefuse.py --chip esp32p4 burn_key \
    BLOCK_KEY0 kern-sb-digest0.bin SECURE_BOOT_DIGEST0

# 4. Burn the backup signing key digest into KEY1
espefuse.py --chip esp32p4 burn_key \
    BLOCK_KEY1 kern-sb-digest1.bin SECURE_BOOT_DIGEST1

# 5. Enable secure boot — POINT OF NO RETURN
espefuse.py --chip esp32p4 burn_efuse SECURE_BOOT_EN
```

After step 5, only firmware signed with `kern-sb-key0.pem` or `kern-sb-key1.pem` will boot on this device.

### 5b. User Builds from Source (Self-Sovereign)

The user generates their own signing keys, builds firmware from source with `sdkconfig.secure`, and burns their own digests. They take full responsibility for key management and firmware signing.

```bash
# Generate own keys
espsecure.py generate_signing_key --version 2 --scheme ecdsa256 my-key0.pem
espsecure.py generate_signing_key --version 2 --scheme ecdsa256 my-key1.pem

# Extract public keys and generate the embedded digest header
espsecure.py extract_public_key --keyfile my-key0.pem my-key0-pub.pem
espsecure.py extract_public_key --keyfile my-key1.pem my-key1-pub.pem
just generate-sb-digests MY_KEY0_PUB=my-key0-pub.pem MY_KEY1_PUB=my-key1-pub.pem

# Build with secure boot (configure key path in sdkconfig.secure)
idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.secure" build
```

After flashing, the user can activate secure boot via the on-device menu (**Settings → Secure Boot → Lock with Developer Keys**). The menu will display the user's own digests (since the header was regenerated from their keys). The flow is identical to 5a — the firmware doesn't distinguish between "developer" and "user" digests; it burns whatever is embedded.

Alternatively, the user can burn digests manually with `espefuse.py` as described in the 5a alternative method, using their own digest `.bin` files.

This is the most sovereign option. The user does not need to trust the Kern developer for firmware integrity — they verify the source code and build it themselves.

### 5c. Hybrid (Developer Key + Own Key)

The user burns the developer's digest in KEY0 and their own digest in KEY1 (or vice versa). This allows the device to boot both official releases and self-built firmware.

This scenario **cannot use the on-device menu** in its default form, because the menu burns both slots from the embedded constants. Instead, the user must use `espefuse.py`:

```bash
# Burn developer digest in KEY0
espefuse.py --chip esp32p4 burn_key \
    BLOCK_KEY0 kern-sb-digest0.bin SECURE_BOOT_DIGEST0

# Burn own digest in KEY1
espefuse.py --chip esp32p4 burn_key \
    BLOCK_KEY1 my-digest1.bin SECURE_BOOT_DIGEST1

# Enable secure boot
espefuse.py --chip esp32p4 burn_efuse SECURE_BOOT_EN
```

> **Future work:** An advanced lockdown menu option could allow the user to load one custom digest from SD card and burn it alongside one of the embedded developer digests. This would support the hybrid scenario without requiring `espefuse.py`.

**Trust implications:**

- The device will boot firmware signed by **either** key. If one key is compromised, the attacker can sign malicious firmware.
- The user must trust both themselves (key1 management) and the developer (key0 management).
- Key rotation is no longer possible — both slots are occupied. If either key is compromised, revocation removes that slot but leaves no room for a replacement.

This scenario trades rotation capability for the flexibility of running both official and custom firmware.

---

## 6. Key Rotation & Revocation

Secure boot supports key rotation using the two digest slots, but with a hard constraint: only one rotation is possible (2 slots, KEY2–KEY3 are reserved for flash encryption).

### Rotation Procedure

```
Timeline:
  KEY0 = old key (to be retired)
  KEY1 = new key (already burned as backup)

Step 1: Sign transitional firmware with BOTH keys
  espsecure.py sign_data --version 2 --keyfile old-key.pem --output temp.bin build/kern.bin
  espsecure.py sign_data --version 2 --keyfile new-key.pem --append_signatures --output kern-transition.bin temp.bin

Step 2: Release the dual-signed firmware
  Users install it via SD card update (Phase 4)
  Device boots — ROM verifies against KEY0 (old), succeeds

Step 3: After all users have updated, revoke the old key
  espefuse.py --chip esp32p4 burn_efuse SECURE_BOOT_KEY_REVOKE0

Step 4: Future firmware only needs to be signed with the new key (KEY1)
```

**Constraints:**

- Revocation is irreversible. Once `SECURE_BOOT_KEY_REVOKE0` is burned, KEY0 is permanently rejected.
- After rotation, only KEY1 remains. There is no slot for a second rotation.
- The transitional firmware **must** be installed on all devices before revoking the old key. Devices that miss the update and still run old-key-only firmware will be bricked after revocation (if they ever re-verify, e.g., after a power cycle that triggers a full boot check).

---

## 7. Anti-Rollback

Anti-rollback prevents downgrading to older firmware versions that may contain known vulnerabilities.

### Mechanism

- The ESP-IDF bootloader reads a **security version** from the firmware image header.
- It compares this against an eFuse **monotonic counter**.
- If the image's security version is lower than the eFuse counter, boot is rejected.
- After successful boot, the eFuse counter is updated to match the image's security version (burning additional bits — irreversible).

### Configuration

In `sdkconfig.secure`:

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
```

The security version starts at 0 and is stored in `sdkconfig.secure` as `CONFIG_BOOTLOADER_APP_SECURE_VERSION`.

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

This file is applied on top of `sdkconfig.defaults` for production builds:

```bash
idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.secure" build
```

**Contents of `sdkconfig.secure`:**

```ini
# ============================================================
# Kern Secure Boot Configuration Overlay
# Apply with: idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.secure" build
# ============================================================

# --- Secure Boot v2 ---
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_SIGNING_KEY="kern-sb-key0.pem"

# Verify app signature on every boot (not just on first boot)
CONFIG_SECURE_BOOT_VERIFY_RSA=n
CONFIG_SECURE_BOOT_VERIFY_ECDSA=y

# Allow signing with multiple keys (needed for key rotation)
CONFIG_SECURE_SIGNED_ON_BOOT_NO_SINGLE_KEY_CHECK=y

# --- Anti-Rollback ---
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
```

> **Note:** The `CONFIG_SECURE_BOOT_SIGNING_KEY` path is relative to the project root. For air-gapped signing workflows where the key is not on the build machine, remove this line and sign manually with `espsecure.py sign_data` after building.

---

## 9. eFuse Burn Order Summary

eFuses must be burned in a specific order. Earlier phases may have already burned some slots.

| Order | Command | eFuse | Reversible? | Phase | Notes |
|-------|---------|-------|-------------|-------|-------|
| 1 | `burn_key BLOCK_KEY5 ... HMAC_UP` | KEY5 | **No** | Phase 2 | Anti-phishing HMAC (already done if Phase 2 complete) |
| 2 | `burn_key BLOCK_KEY0 ... SECURE_BOOT_DIGEST0` | KEY0 | **No** | Phase 3 | Primary secure boot digest |
| 3 | `burn_key BLOCK_KEY1 ... SECURE_BOOT_DIGEST1` | KEY1 | **No** | Phase 3 | Backup secure boot digest |
| 4 | `burn_efuse SECURE_BOOT_EN` | Control | **No** | Phase 3 | **Enables secure boot permanently** |
| 5 | `burn_key BLOCK_KEY2 ... XTS_AES_256_KEY_1` | KEY2 | **No** | Phase 5 | Flash encryption key (part 1) |
| 6 | `burn_key BLOCK_KEY3 ... XTS_AES_256_KEY_2` | KEY3 | **No** | Phase 5 | Flash encryption key (part 2) |
| 7 | `burn_key BLOCK_KEY4 ... HMAC_UP` | KEY4 | **No** | Phase 6 | NVS encryption HMAC |

> **Every eFuse burn is irreversible.** Double-check the digest files and key purposes before confirming. Use `espefuse.py summary` to inspect current eFuse state before and after each burn.

---

## 10. Testing Checklist

Complete these steps on a **development board** before any production device.

### Pre-Lockdown

- [ ] Build production firmware with `sdkconfig.secure` overlay
- [ ] Verify the signed image: `espsecure.py verify_signature --version 2 --keyfile key0-pub.pem kern-signed.bin`
- [ ] Flash signed bootloader and app via serial — confirm device boots normally
- [ ] Read eFuse state: `espefuse.py summary` — verify KEY0/KEY1 are empty
- [ ] Verify embedded digests match published digests: navigate to **Settings → Secure Boot** and compare displayed hex against release notes

### On-Device Lockdown (Primary Path)

- [ ] Navigate to **Settings → Secure Boot → Lock with Developer Keys**
- [ ] Verify digest hex values are displayed correctly on screen
- [ ] Verify PIN is required before proceeding
- [ ] Verify warning about irreversibility is shown
- [ ] Confirm lockdown — device writes digests and burns `SECURE_BOOT_EN`
- [ ] Read eFuse state: `espefuse.py summary` — verify KEY0/KEY1 are programmed and `SECURE_BOOT_EN` is set
- [ ] Device reboots and boots normally with signed firmware

### On-Device Lockdown — Guard Rails

- [ ] Attempt lockdown on a device with `SECURE_BOOT_EN` already set — **must refuse**
- [ ] Attempt lockdown on a device with KEY0/KEY1 already occupied — **must refuse**
- [ ] Attempt lockdown with unsigned firmware running — **must refuse** (firmware should detect it is not properly signed and block the operation)

### Manual Lockdown via espefuse.py (Alternative Path)

- [ ] Burn digest0 into KEY0: `espefuse.py burn_key BLOCK_KEY0 digest0.bin SECURE_BOOT_DIGEST0`
- [ ] Burn digest1 into KEY1: `espefuse.py burn_key BLOCK_KEY1 digest1.bin SECURE_BOOT_DIGEST1`
- [ ] Read eFuse state: `espefuse.py summary` — verify KEY0/KEY1 are programmed
- [ ] Device still boots (secure boot not yet enabled, so unsigned firmware also works)
- [ ] `espefuse.py burn_efuse SECURE_BOOT_EN`
- [ ] Device boots with signed firmware — **confirm normal operation**

### Post-Lockdown Verification

- [ ] Attempt to flash unsigned firmware via serial — **must fail**
- [ ] Attempt to flash firmware signed with a different key — **must fail**
- [ ] Sign firmware with key0 → boots successfully
- [ ] Sign firmware with key1 → boots successfully
- [ ] Sign firmware with random key → **fails to boot**

### Anti-Rollback (after Phase 4 SD updates)

- [ ] Install firmware with security version 1
- [ ] Attempt to install firmware with security version 0 via SD card — **must be rejected**
- [ ] `espefuse.py summary` — verify security version counter shows 1

### Recovery

- [ ] After secure boot is enabled, verify SD card update path works (Phase 4)
- [ ] Simulate power loss during SD card update — device should boot from previous slot

---

## 11. Security Considerations

### Key Compromise

If a signing key's private key is leaked:

- An attacker can sign malicious firmware that will pass secure boot verification.
- **Mitigation**: Revoke the compromised key's digest slot and rotate to the backup key (see [Section 6](#6-key-rotation--revocation)). This requires that a dual-signed transitional firmware was distributed *before* revocation.
- If both keys are compromised, there is no recovery — the device will accept attacker-signed firmware indefinitely.

### Lost Keys

If all copies of a signing key are lost:

- No new firmware can be signed with that key.
- If the device only has that key's digest burned, it becomes un-updatable.
- **Mitigation**: Always maintain redundant backups (Section 3b) and burn both a primary and backup digest (KEY0 + KEY1).

### Supply Chain Attacks

- A compromised build environment could inject malicious code before signing.
- **Mitigation**: Build on a trusted, air-gapped machine. Reproducible builds (future work) would allow independent verification.
- Pre-flashed devices from untrusted sources could have attacker digests burned.
- **Mitigation**: Users should verify eFuse state with `espefuse.py summary` before trusting a pre-flashed device, or flash and lock down the device themselves.

### Cross-Phase Dependencies

Secure boot alone does not protect against all threats:

| Threat | Requires |
|--------|----------|
| Flash content extraction | Flash Encryption (Phase 5) |
| NVS data readout (PIN hash) | Flash Encryption (Phase 5) + NVS Encryption (Phase 6) |
| Firmware downgrade | Anti-Rollback (this phase) + SD card updates (Phase 4) |
| JTAG/debug access | Flash Encryption (Phase 5) — locks JTAG automatically |

Secure boot provides firmware integrity. For full device security, all phases through Phase 6 are needed.

### Anti-Phishing Synergy

With secure boot enabled, the anti-phishing words (Phase 2) become a strong tamper-detection guarantee. Before secure boot, malicious firmware on the same chip could fake the anti-phishing display. After secure boot, only signed firmware runs, closing this gap.

---

## 12. References

- [ESP-IDF Secure Boot v2 Documentation](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32p4/security/secure-boot-v2.html)
- [ESP-IDF Anti-Rollback](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32p4/api-reference/system/ota.html#anti-rollback)
- [espefuse.py Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espefuse/)
- [espsecure.py Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espsecure/)
- [Kern Security Plan](security-plan.md) — full security roadmap and eFuse allocation table
