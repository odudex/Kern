# Kern Secure Boot Guide (Phase 5)

> **Warning**: Secure boot burns eFuses permanently. Practice every step on a development board before touching a production device. There is no undo.

This document covers ESP32-P4 Secure Boot v2 as applied to the Kern hardware wallet — key generation, firmware signing, digest burning, and the various user scenarios for locking down a device.

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

KEY3 holds the flash-encryption key (Phase 4), KEY4 the NVS-encryption HMAC (Phase 3), and KEY5 the anti-phishing HMAC (Phase 2). All six blocks are allocated. Because **all three secure-boot digest slots are populated**, there is no free digest slot for an attacker to inject a rogue signing key.

> **Flash-encryption interaction:** With three digest slots consuming KEY0–KEY2, only one key block (KEY3) is left for flash encryption. XTS-AES-256 normally needs two blocks. Kern keeps 256-bit strength by deploying the flash-encryption key through the ESP32-P4 **Key Manager** (`CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE`), which stores the key outside the shared eFuse blocks. If the Key Manager path is not used, fall back to **XTS-AES-128** in KEY3 (single block). This is a Phase 4 decision — see [security-plan.md](security-plan.md).

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
- Serial flashing of unsigned firmware is blocked (UART download mode is restricted).
- The device can only be updated via signed images (SD card OTA after Phase 6).

---

## 2. Algorithm Choice

**Required on ESP32-P4: RSA-3072 (RSA-PSS).**

> **ECDSA is broken on ESP32-P4.** Per Espressif's chip errata and the ESP-IDF v6.0.2 documentation, "the ECDSA based Secure Boot V2 scheme is not functional for certain input vectors and is therefore not recommended" on ESP32-P4. Enabling it at all requires `CONFIG_SECURE_BOOT_INSECURE` + `CONFIG_SECURE_BOOT_V2_FORCE_ENABLE_ECDSA` — unacceptable for a hardware wallet. A fix is expected in a future silicon ECO revision. Until Kern can gate on a fixed chip revision, **all builds use RSA-3072.**

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
#            kern-sb-key0-pub.pem kern-sb-key1-pub.pem kern-sb-key2-pub.pem \
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

// SHA-256 of kern-sb-key1-pub.pem (rotation #1)
static const uint8_t KERN_SB_DIGEST1[32] = {
    0xe5, 0xf6, 0x07, 0x18, /* ... 32 bytes total ... */
};

// SHA-256 of kern-sb-key2-pub.pem (rotation #2)
static const uint8_t KERN_SB_DIGEST2[32] = {
    0x29, 0x3a, 0x4b, 0x5c, /* ... 32 bytes total ... */
};

// Number of developer digest slots
#define KERN_SB_DEVELOPER_DIGEST_COUNT 3
```

Note that the eFuse digest is a 32-byte SHA-256 regardless of the signature scheme, so the embedded-digest and on-device lockdown mechanics are identical whether the keys are RSA-3072 or ECDSA.

**Build integration:**

```bash
# Justfile target
generate-sb-digests:
    python scripts/generate_sb_digests.h.py \
        kern-sb-key0-pub.pem kern-sb-key1-pub.pem kern-sb-key2-pub.pem \
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

### 4a. Signing Firmware

When `CONFIG_SECURE_BOOT=y` and the signing key path is configured in sdkconfig, the ESP-IDF build system automatically signs the bootloader and app images with the configured key.

> **Sign the bootloader with all three keys.** The second-stage bootloader is frozen at initial flash — it is never updated by OTA. To survive key rotations, it must carry a signature from every key whose digest will remain valid after future revocations. Sign the bootloader with key0, key1, **and** key2 (appended signatures). The app only needs the current key, because a rotated app can be re-signed and re-deployed via SD card OTA.

**Manual signing** (for air-gapped workflows where the build machine doesn't have the key):

```bash
# Sign the app image with the current primary key
espsecure sign-data \
    --version 2 \
    --keyfile kern-sb-key0.pem \
    --output kern-signed.bin \
    build/kern.bin

# Sign the bootloader with ALL three keys (append each signature)
espsecure sign-data \
    --version 2 \
    --keyfile kern-sb-key0.pem \
    --output bl-tmp0.bin \
    build/bootloader/bootloader.bin
espsecure sign-data \
    --version 2 \
    --keyfile kern-sb-key1.pem \
    --append-signatures \
    --output bl-tmp1.bin \
    bl-tmp0.bin
espsecure sign-data \
    --version 2 \
    --keyfile kern-sb-key2.pem \
    --append-signatures \
    --output bootloader-signed.bin \
    bl-tmp1.bin
```

**Verify a signature:**

```bash
espsecure verify-signature \
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
  5. Sign with espsecure sign-data (bootloader with all 3 keys, app with primary)
  6. Verify signature with public key
  7. Upload signed .bin to GitHub Release
```

**CI verification** (runs on every build, uses public key only):

```bash
# CI can verify that a release binary was signed correctly
espsecure verify-signature \
    --version 2 \
    --keyfile kern-sb-key0-pub.pem \
    kern-signed.bin
```

**Alternative: CI signing with GitHub encrypted secrets.** The signing key is stored as a GitHub encrypted secret and used during CI builds. This is more convenient but increases the attack surface — a compromised CI pipeline or GitHub account could sign malicious firmware. Not recommended for a security-critical project like a hardware wallet.

---

## 5. User Scenarios

### 5a. User Burns Developer Digest (Recommended)

The most common scenario: the user trusts the Kern developer's signing keys and burns their digests into their device. After lockdown, only firmware signed by the developer will boot.

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
esptool --chip esp32p4 write-flash \
    0x0 bootloader-signed.bin \
    0x20000 kern-signed.bin
```

2. Boot into Kern and navigate to **Settings → Secure Boot → Lock with Developer Keys**.
3. The device displays:
   - The hex representation of Digest 0, Digest 1, and Digest 2 (from the embedded constants).
   - A warning that this action is **irreversible**.
   - The user can compare the displayed digests against those published in the release notes or repository.
4. Confirm by entering the device PIN.
5. The firmware:
   - Verifies that `SECURE_BOOT_EN` is not already set.
   - Verifies that KEY0, KEY1, and KEY2 eFuse blocks are empty.
   - Verifies the running firmware carries a valid signature (so a device with an unsigned image can't brick itself).
   - Writes `KERN_SB_DIGEST0` to `BLOCK_KEY0` with purpose `SECURE_BOOT_DIGEST0`.
   - Writes `KERN_SB_DIGEST1` to `BLOCK_KEY1` with purpose `SECURE_BOOT_DIGEST1`.
   - Writes `KERN_SB_DIGEST2` to `BLOCK_KEY2` with purpose `SECURE_BOOT_DIGEST2`.
   - Burns the `SECURE_BOOT_EN` eFuse bit.
   - Displays confirmation with the final eFuse state.
6. Device reboots. From this point, only firmware signed with `kern-sb-key0.pem`, `kern-sb-key1.pem`, or `kern-sb-key2.pem` will boot.

**Implementation notes:**

The lockdown function should follow this sequence:

```c
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_secure_boot.h"
#include "kern_sb_digests.h"

esp_err_t kern_secure_boot_lockdown(void) {
    // 1. Pre-flight checks
    //    - Verify SECURE_BOOT_EN is not already set
    //    - Verify KEY0, KEY1, KEY2 blocks are empty
    //    - Verify the running app is properly signed:
    //        esp_secure_boot_verify_rsa_signature_block() over the running image.
    //      (The generic esp_secure_boot_verify_signature_block() was removed in
    //       ESP-IDF 6.0 — use the RSA-specific variant.)

    // 2. Burn digests (batch so a power cut can't leave a half-written set)
    esp_efuse_batch_write_begin();
    esp_efuse_write_key(EFUSE_BLK_KEY0,
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, KERN_SB_DIGEST0, 32);
    esp_efuse_write_key(EFUSE_BLK_KEY1,
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, KERN_SB_DIGEST1, 32);
    esp_efuse_write_key(EFUSE_BLK_KEY2,
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2, KERN_SB_DIGEST2, 32);
    esp_efuse_batch_write_commit();

    // 3. Enable secure boot — POINT OF NO RETURN
    esp_efuse_write_field_bit(ESP_EFUSE_SECURE_BOOT_EN);

    return ESP_OK;
}
```

The menu system must enforce:

- PIN entry before showing the lockdown option.
- Display of all three digest hex values for visual verification.
- An explicit confirmation prompt warning of irreversibility.
- Verification that the running firmware is signed before proceeding (a device that locks down with unsigned firmware running will brick on next boot).

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

# 2. Flash the signed firmware via serial (last time serial will work)
esptool --chip esp32p4 write-flash \
    0x0 bootloader-signed.bin \
    0x20000 kern-signed.bin

# 3. Burn the three signing key digests into KEY0, KEY1, KEY2
espefuse --chip esp32p4 burn-key \
    BLOCK_KEY0 kern-sb-digest0.bin SECURE_BOOT_DIGEST0 \
    BLOCK_KEY1 kern-sb-digest1.bin SECURE_BOOT_DIGEST1 \
    BLOCK_KEY2 kern-sb-digest2.bin SECURE_BOOT_DIGEST2

# 4. Enable secure boot — POINT OF NO RETURN
espefuse --chip esp32p4 burn-efuse SECURE_BOOT_EN
```

After step 4, only firmware signed with `kern-sb-key0.pem`, `kern-sb-key1.pem`, or `kern-sb-key2.pem` will boot on this device.

### 5b. User Builds from Source (Self-Sovereign)

The user generates their own signing keys, builds firmware from source with `sdkconfig.secure`, and burns their own digests. They take full responsibility for key management and firmware signing.

```bash
# Generate own keys
for n in 0 1 2; do
    espsecure generate-signing-key --version 2 --scheme rsa3072 my-key${n}.pem
    espsecure extract-public-key --keyfile my-key${n}.pem my-key${n}-pub.pem
done

# Generate the embedded digest header from the public keys
just generate-sb-digests \
    MY_KEY0_PUB=my-key0-pub.pem \
    MY_KEY1_PUB=my-key1-pub.pem \
    MY_KEY2_PUB=my-key2-pub.pem

# Build with secure boot (configure key path in sdkconfig.secure)
idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.secure" build
```

After flashing, the user can activate secure boot via the on-device menu (**Settings → Secure Boot → Lock with Developer Keys**). The menu will display the user's own digests (since the header was regenerated from their keys). The flow is identical to 5a — the firmware doesn't distinguish between "developer" and "user" digests; it burns whatever is embedded.

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

# Enable secure boot
espefuse --chip esp32p4 burn-efuse SECURE_BOOT_EN
```

> If any digest slot is intentionally left **empty**, revoke it before enabling secure boot (`espefuse burn-efuse SECURE_BOOT_KEY_REVOKE2`), so an attacker with physical access cannot later burn their own digest into the free slot.

> **Future work:** An advanced lockdown menu option could allow the user to load one custom digest from SD card and burn it alongside the embedded developer digests. This would support the hybrid scenario without requiring `espefuse`.

**Trust implications:**

- The device will boot firmware signed by **any** burned key. If one key is compromised, the attacker can sign malicious firmware until that slot is revoked.
- The user must trust every party whose key is burned (themselves for their keys, the developer for developer keys).
- Each slot spent on a second trust anchor is a slot not available for rotation. A layout that burns all three slots on trust anchors leaves no rotation headroom.

---

## 6. Key Rotation & Revocation

Kern burns three digests (KEY0/KEY1/KEY2), which enables **up to two key rotations** — one more than a two-slot scheme. Keep at least one non-revoked digest at all times, or the device can no longer boot.

### Rotation Procedure

```
Timeline:
  KEY0 = key currently in daily use
  KEY1, KEY2 = successor keys (already burned as digests, not yet used to sign releases)

Step 1: Sign transitional firmware with BOTH the outgoing and incoming key
  espsecure sign-data --version 2 --keyfile kern-sb-key0.pem --output temp.bin build/kern.bin
  espsecure sign-data --version 2 --keyfile kern-sb-key1.pem --append-signatures --output kern-transition.bin temp.bin

Step 2: Release the dual-signed firmware
  Users install it via SD card update (Phase 6)
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
- The **bootloader must have been signed with the successor key at initial flash** (Section 4a). Because the bootloader is frozen and never updated by OTA, revoking a key that the bootloader was *not* signed with will not brick it, but revoking the only key the bootloader *was* signed with will. Signing the bootloader with all three keys up front avoids this entirely.
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

### Configuration

In `sdkconfig.secure`:

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
```

The security version starts at 0 and is stored in `sdkconfig.secure` as `CONFIG_BOOTLOADER_APP_SECURE_VERSION`. The size of the eFuse counter (and therefore the maximum number of increments) is set by `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD` — size it generously, since every increment is permanent.

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

# --- Secure Boot v2 (RSA-3072; ECDSA is non-functional on ESP32-P4) ---
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y
CONFIG_SECURE_BOOT_SIGNING_KEY="kern-sb-key0.pem"

# Leave aggressive key revocation OFF — revoking a good key on a single
# failed verification would be a bricking hazard for a wallet.
# CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE is not set

# --- Anti-Rollback ---
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
```

> **Verify every symbol landed.** A plain rebuild can keep stale values — remove `build_<board>/sdkconfig` and grep the generated `sdkconfig` to confirm `CONFIG_SECURE_BOOT`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME`, and the anti-rollback options are set as expected before trusting the overlay.

> **Note:** The `CONFIG_SECURE_BOOT_SIGNING_KEY` path is relative to the project root and is only used for the build-system's automatic signing. For air-gapped signing workflows where the key is not on the build machine, remove this line and sign manually with `espsecure sign-data` after building (bootloader with all three keys — see Section 4a).

---

## 9. eFuse Burn Order Summary

eFuses must be burned in a specific order. The critical rule: **every read-protected key (NVS-HMAC KEY4, flash-encryption XTS key) must be burned before `SECURE_BOOT_EN`** — enabling secure boot write-protects `RD_DIS`, after which no other key block can be read-protected. This is why NVS encryption (Phase 3) and flash encryption (Phase 4) precede secure boot (Phase 5) in the plan. See [security-plan.md](security-plan.md#the-hard-constraint-read-protected-keys-before-secure-boot).

| Order | Command | eFuse | Reversible? | Phase | Notes |
|-------|---------|-------|-------------|-------|-------|
| 1 | `burn-key BLOCK_KEY5 ... HMAC_UP` | KEY5 | **No** | Phase 2 | Anti-phishing HMAC (already done if Phase 2 complete) |
| 2 | `burn-key BLOCK_KEY4 ... HMAC_UP` | KEY4 | **No** | Phase 3 | NVS-encryption HMAC — read-protected; must precede secure boot |
| 3 | Flash-encryption key (Key Manager, or `burn-key BLOCK_KEY3 ... XTS_AES_128_KEY`) | KEY3 / Key Manager | **No** | Phase 4 | XTS-AES-256 via Key Manager (preferred) or XTS-AES-128 in KEY3; read-protected, must precede secure boot |
| 4 | `burn-key BLOCK_KEY0 ... SECURE_BOOT_DIGEST0` | KEY0 | **No** | Phase 5 | Primary secure boot digest |
| 5 | `burn-key BLOCK_KEY1 ... SECURE_BOOT_DIGEST1` | KEY1 | **No** | Phase 5 | Rotation #1 secure boot digest |
| 6 | `burn-key BLOCK_KEY2 ... SECURE_BOOT_DIGEST2` | KEY2 | **No** | Phase 5 | Rotation #2 secure boot digest |
| 7 | `burn-efuse SECURE_BOOT_EN` | Control | **No** | Phase 5 | **Enables secure boot permanently; write-protects `RD_DIS`** |
| 8 | Flash-encryption release mode + secure/disabled serial download | Control | **No** | Phase 7 | Release lockdown — permanently disables plaintext serial flashing |

> **Every eFuse burn is irreversible.** Double-check the digest files and key purposes before confirming. Use `espefuse summary` to inspect current eFuse state before and after each burn. Because all three secure-boot digest slots are used, there is no unused digest slot to revoke — but if you ever leave one empty (e.g. a custom hybrid layout), revoke it before enabling secure boot. For **Profile A** (on-device: PIN/NVS encryption + secure boot, no flash encryption) rows 3 and 8 are skipped, and the whole sequence — including the KEY4 (NVS) burn in row 2 — runs from on-device flows.

---

## 10. Testing Checklist

Complete these steps on a **development board** before any production device.

### Pre-Lockdown

- [ ] Build production firmware with `sdkconfig.secure` overlay
- [ ] Confirm the generated `sdkconfig` has `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y` (not ECDSA)
- [ ] Verify the signed image: `espsecure verify-signature --version 2 --keyfile kern-sb-key0-pub.pem kern-signed.bin`
- [ ] Confirm the bootloader carries all three signatures (key0/key1/key2)
- [ ] Flash signed bootloader and app via serial — confirm device boots normally
- [ ] Read eFuse state: `espefuse summary` — verify KEY0/KEY1/KEY2 are empty
- [ ] Verify embedded digests match published digests: navigate to **Settings → Secure Boot** and compare displayed hex against release notes

### On-Device Lockdown (Primary Path)

- [ ] Navigate to **Settings → Secure Boot → Lock with Developer Keys**
- [ ] Verify all three digest hex values are displayed correctly on screen
- [ ] Verify PIN is required before proceeding
- [ ] Verify warning about irreversibility is shown
- [ ] Confirm lockdown — device writes three digests and burns `SECURE_BOOT_EN`
- [ ] Read eFuse state: `espefuse summary` — verify KEY0/KEY1/KEY2 are programmed and `SECURE_BOOT_EN` is set
- [ ] Device reboots and boots normally with signed firmware

### On-Device Lockdown — Guard Rails

- [ ] Attempt lockdown on a device with `SECURE_BOOT_EN` already set — **must refuse**
- [ ] Attempt lockdown on a device with any of KEY0/KEY1/KEY2 already occupied — **must refuse**
- [ ] Attempt lockdown with unsigned firmware running — **must refuse** (firmware should detect it is not properly signed and block the operation)

### Manual Lockdown via espefuse (Alternative Path)

- [ ] Burn the three digests: `espefuse burn-key BLOCK_KEY0 digest0.bin SECURE_BOOT_DIGEST0 BLOCK_KEY1 digest1.bin SECURE_BOOT_DIGEST1 BLOCK_KEY2 digest2.bin SECURE_BOOT_DIGEST2`
- [ ] Read eFuse state: `espefuse summary` — verify KEY0/KEY1/KEY2 are programmed
- [ ] Device still boots (secure boot not yet enabled, so unsigned firmware also works)
- [ ] `espefuse burn-efuse SECURE_BOOT_EN`
- [ ] Device boots with signed firmware — **confirm normal operation**

### Post-Lockdown Verification

- [ ] Attempt to flash unsigned firmware via serial — **must fail**
- [ ] Attempt to flash firmware signed with a different key — **must fail**
- [ ] Sign firmware with key0 → boots successfully
- [ ] Sign firmware with key1 → boots successfully
- [ ] Sign firmware with key2 → boots successfully
- [ ] Sign firmware with a random key → **fails to boot**

### Key Rotation (dev board)

- [ ] Dual-sign firmware with key0 + key1, install, confirm boot
- [ ] Burn `SECURE_BOOT_KEY_REVOKE0`, confirm key0-only firmware no longer boots
- [ ] Confirm key1-signed firmware still boots (bootloader was signed with key1)

### Anti-Rollback (after Phase 6 SD updates)

- [ ] Install firmware with security version 1
- [ ] Attempt to install firmware with security version 0 via SD card — **must be rejected**
- [ ] `espefuse summary` — verify security version counter shows 1

### Recovery

- [ ] After secure boot is enabled, verify SD card update path works (Phase 6)
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

### Supply Chain Attacks

- A compromised build environment could inject malicious code before signing.
- **Mitigation**: Build on a trusted, air-gapped machine. Reproducible builds (future work) would allow independent verification.
- Pre-flashed devices from untrusted sources could have attacker digests burned.
- **Mitigation**: Users should verify eFuse state with `espefuse summary` before trusting a pre-flashed device, or flash and lock down the device themselves.

### Cross-Phase Dependencies

Secure boot alone does not protect against all threats:

| Threat | Requires |
|--------|----------|
| Flash content extraction | Flash Encryption (Phase 4) |
| NVS data readout (PIN hash) | NVS Encryption (Phase 3) |
| Firmware downgrade | Anti-Rollback (this phase) + SD card updates (Phase 6) |
| JTAG/debug access | Flash Encryption (Phase 4) — locks JTAG automatically |

Secure boot provides firmware integrity. For full device security, all phases through Phase 7 (release lockdown) are needed.

### Anti-Phishing Synergy

With secure boot enabled, the anti-phishing words (Phase 2) become a strong tamper-detection guarantee. Before secure boot, malicious firmware on the same chip could fake the anti-phishing display. After secure boot, only signed firmware runs, closing this gap.

---

## 12. References

- [ESP-IDF Secure Boot v2 Documentation (ESP32-P4)](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32p4/security/secure-boot-v2.html) — includes the ECDSA "not functional on ESP32-P4" advisory
- [ESP-IDF Flash Encryption (ESP32-P4)](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32p4/security/flash-encryption.html) — Key Manager vs eFuse key source, XTS-AES-128/256
- [ESP-IDF Anti-Rollback](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32p4/api-reference/system/ota.html#anti-rollback)
- [ESP-IDF 6.0 Security Migration Guide](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32/migration-guides/release-6.x/6.0/security.html) — removed/renamed APIs, NISTP192 deprecation
- [espefuse Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espefuse/)
- [espsecure Reference](https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espsecure/)
- [esptool v5 Migration Guide](https://docs.espressif.com/projects/esptool/en/latest/esp32/migration-guide.html) — `.py` drop and hyphenated subcommands
- [Kern Security Plan](security-plan.md) — full security roadmap and eFuse allocation table
