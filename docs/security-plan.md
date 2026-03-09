# Kern Security Model & Implementation Plan

## Baseline

- **Air-gapped by design** — no radio on ESP32-P4, QR-only I/O
- **Session-only keys** — mnemonics live in RAM, cleared on unload
- **libwally-core** — proven Bitcoin cryptographic primitives
- **Entropy validation** — Shannon entropy threshold for camera-based seed generation

## Threat Model

| Threat | Attack vector | Mitigation |
|--------|--------------|------------|
| Firmware tampering | Malicious flash via UART/JTAG | **Secure Boot + JTAG lockdown** |
| Flash readout | Physical extraction of flash chip | **Flash Encryption** |
| Evil maid / stolen device | Physical access while powered off | **PIN + encrypted storage** |
| Device swap / evil maid | Replace device with lookalike | **Anti-phishing words (eFuse HMAC)** |
| Evil maid tampering | "Evil maid" tamper device | **Anti-phishing words + secure boot** |
| Shoulder surfing/theft at rest | Backup QR codes or stored data | **KEF encrypted backups** |
| Firmware downgrade | Flash older vulnerable version | **Anti-rollback (eFuse counter)** |
| Firmware downgrade via SD | Load older vulnerable firmware via update | **Anti-rollback (eFuse counter)** |
| No update path after lockdown | Serial flash disabled in release mode | **Air-gapped SD card updates** |
| RAM snooping via PSRAM | Probing external PSRAM bus | **Flash encryption auto-enables PSRAM encryption** |
| Cold boot / remanence | Reading RAM after power-off | **Secure memory wiping** |

## ESP32-P4 Security Hardware Summary

### Usable for Kern
- **Secure Boot v2** — RSA-PSS or ECDSA-P256, up to 3 key digest slots in eFuse
- **Flash Encryption** — XTS-AES-128/256, auto-encrypts PSRAM too
- **NVS Encryption** — HMAC-based key derivation from eFuse (no separate key partition needed)
- **HMAC peripheral** — computes HMAC-SHA256 using eFuse keys without exposing them to software; used for anti-phishing word derivation (`esp_hmac_calculate()` with `HMAC_KEY5` purpose)
- **AES/SHA hardware accelerators** — transparent via mbedTLS, useful for KEF and general crypto
- **TRNG** — hardware entropy source for random numbers generation (mix with additional sources)
- **Anti-rollback** — security version counter in eFuse
- **JTAG/UART lockdown** — automatic when security features are enabled

### NOT usable for Bitcoin
- **ECDSA peripheral** — P-192/P-256 only, **secp256k1 not supported**. All Bitcoin signing uses software libsecp256k1 via libwally-core.
- **Digital Signature peripheral** — RSA-based, no Bitcoin application.

### Future potential
- **World Controller / PMS** — two-world privilege separation (secure vs non-secure). ESP-IDF support for ESP32-P4 TEE still maturing. Could isolate signing operations from UI.

### eFuse Key Block Allocation

| Block | Purpose | Phase |
|-------|---------|-------|
| KEY0 (BLK4) | Secure Boot Digest 0 (primary) | Phase 3 |
| KEY1 (BLK5) | Secure Boot Digest 1 (backup/rotation) | Phase 3 |
| KEY2 (BLK6) | Flash Encryption XTS-AES-256 (part 1) | Phase 5 |
| KEY3 (BLK7) | Flash Encryption XTS-AES-256 (part 2) | Phase 5 |
| KEY4 (BLK8) | HMAC for NVS encryption | Phase 6 |
| KEY5 (BLK9) | HMAC for anti-phishing words (HMAC_UP) | Phase 2 |

All 6 key blocks allocated. KEY5 uses the `HMAC_UP` purpose — software can request HMAC computations but never reads the raw key material.

## Partition Table

### Current layout (no OTA)

```
# Name    Type  SubType  Offset   Size     (Human)
nvs       data  nvs      0x9000   0x6000   (24K)
phy_init  data  phy      0xF000   0x1000   (4K)
factory   app   factory           0x800000 (8M)
storage   data  spiffs            0x700000 (7M)
```

### Proposed layout (factory + dual OTA)

```
# Name    Type  SubType  Offset     Size       (Human)
nvs       data  nvs      0x9000     0x6000     (24K)
otadata   data  ota      0xF000     0x2000     (8K)
phy_init  data  phy      0x11000    0x1000     (4K)
factory   app   factory  0x20000    0x400000   (4M)
ota_0     app   ota_0    0x420000   0x400000   (4M)
ota_1     app   ota_1    0x820000   0x400000   (4M)
storage   data  spiffs   0xC20000   0x3E0000   (~3.9M)
```

**Rationale**: Factory partition provides a known-good fallback that cannot be overwritten by OTA. Dual OTA enables safe A/B updates — if a new firmware fails, the device rolls back to the previous working slot. Storage shrinks from 7M to ~3.9M (still ample for encrypted mnemonics and descriptors). App partitions are 64KB-aligned as required by ESP-IDF.

## Phase Ordering Rationale

Phases are ordered by dependency constraints, not just complexity:

1. **Phase 2 (PIN + anti-phishing) before Phase 3 (secure boot)** — PIN system is pure software and reversible; secure boot burns eFuses permanently. Anti-phishing word provisioning (KEY5) is the only eFuse burn in Phase 2, and it's independent of secure boot keys.

2. **Phase 3 (secure boot) before Phase 4 (SD updates)** — SD card updates must verify firmware signatures. Secure boot provides the signing infrastructure that OTA verification depends on.

3. **Phase 4 (SD updates) before Phase 5 (flash encryption release mode)** — Flash encryption release mode permanently disables serial flashing. The SD update path **must** be proven reliable before this point, or the device becomes un-updatable. Flash encryption development mode (serial fallback still works) can be tested alongside Phase 4.

4. **Phase 6 (NVS encryption) after Phase 5** — NVS encryption uses the same eFuse HMAC infrastructure and should be enabled after flash encryption is stable.

### Cross-Phase Security Dependencies

Some features only reach their full security guarantee when combined with later phases. Until those phases are complete, certain attack vectors remain open:

| Feature (Phase) | Depends on | Gap until dependency is met |
|-----------------|------------|----------------------------|
| Anti-phishing words (2) | Secure Boot (3) | Anti-phishing detects a *different chip* (eFuse mismatch), but an attacker who controls the firmware can bypass the check entirely — malicious firmware on the *same chip* can fake the words or exfiltrate the PIN. Secure boot closes this by ensuring only signed firmware runs. |
| Anti-phishing words (2) | Flash Encryption (5) | Without flash encryption, an attacker with physical access can read the NVS partition (PIN hash, split position) and the firmware binary. They could clone the flash to a new chip, or analyze the PIN hash offline. Flash encryption makes flash contents unreadable. |
| PIN hash in NVS (2) | NVS Encryption (6) | The PBKDF2 hash is stored in plaintext NVS. Physical flash extraction exposes it to offline brute-force (limited by 100k PBKDF2 iterations and the device-bound salt, but still a risk for weak PINs). NVS encryption removes this vector. |
| PIN hash in NVS (2) | Flash Encryption (5) | Even before NVS encryption, flash encryption makes the entire flash unreadable, protecting the PIN hash at the storage layer. |
| Wipe-after-N-failures (2) | Secure Boot (3) | Custom firmware could reset the failure counter or skip the wipe check. Secure boot prevents running unauthorized firmware. |
| SD card OTA (4) | Secure Boot (3) | Without secure boot, the OTA path cannot verify firmware signatures — any `.bin` file would be accepted. Secure boot is a hard prerequisite. |
| Session timeout (2) | Flash Encryption (5) | After timeout, keys are wiped from RAM, but PSRAM contents could theoretically be probed. Flash encryption auto-enables PSRAM encryption, closing this gap. |

**In summary**: Phase 2 provides strong *usability-layer* security (PIN gating, anti-phishing UX, auto-wipe), but its tamper-detection guarantees are only as strong as the firmware integrity guarantees. Phases 3 and 5 are what turn anti-phishing from "detects accidental device swaps" into "cryptographically proves device authenticity".

## Implementation Phases

### Phase 0 — Foundations ✅

#### 0a. Secure memory primitives ✅
- `secure_memzero()` that can't be optimized away (`volatile` barrier)
- `secure_mem.h`: `secure_memzero()`, `secure_memcmp()` (constant-time comparison)
- Audited paths in `key.c` and `wallet.c` where seeds/keys exist on stack or heap

#### 0b. AES encryption utility ✅
- `crypto_utils.c` wrapping ESP-IDF's mbedTLS AES (uses hardware accelerator transparently)
- Functions: `aes_encrypt_buffer()`, `aes_decrypt_buffer()`, `pbkdf2_derive_key()`
- Building block for KEF, PIN-protected storage, etc.

### Phase 1 — KEF Encryption ✅

- `kef.c/h` in `main/core/` — 12 encryption versions, AES-256 + PBKDF2
- QR scanner pipeline: detect KEF-encrypted QR, prompt for password, decrypt
- QR export: encrypted mnemonic/descriptor QRs
- Storage: save/load encrypted mnemonics and descriptors to SPIFFS and SD card

### Phase 2 — Split PIN with Anti-Phishing Words ✅

**Goal**: PIN authentication with tamper detection. User can verify they're interacting with their own device, not a replacement or clone.

**Mechanism**: The ESP32-P4 HMAC peripheral computes HMAC-SHA256 using an eFuse key that software can never read directly (`HMAC_UP` purpose). Each physical chip produces unique outputs — a cloned flash on a different chip produces different words.

#### 2a. PIN entry UI and basic authentication ✅
- Text input page with virtual keyboard and eye toggle (`pages/pin/pin_page.c`)
- PIN: 6-16 characters, alphanumeric + symbols
- PBKDF2-HMAC-SHA256 (100k iterations) hash stored in NVS
  - Salt derived from `HMAC(KEY5, SHA256("C-Krux-PIN-salt-v1"))` — device-bound salt without exposing eFuse key
- PIN required right after boot
- Attempt limiting: exponential backoff (2^n seconds, capped at ~9 hours)
- Pre-increment failure counter before hash check (power-cut safe)
- Constant-time hash comparison (`secure_memcmp()`)
- Session timeout: auto-lock after configurable idle period (off/1/5/15/30 min)
- Screensaver on timeout: unloads wallet from RAM, animated display, touch to unlock

#### 2b. First-boot device secret provisioning ✅
- Generate 256-bit random device secret using hardware TRNG (`crypto_random_bytes()`)
- Burn into eFuse KEY5 with purpose `HMAC_UP` (software HMAC only, no raw read)
- Set read-protection and write-protection on KEY5
- No manufacturing step required — each device self-provisions during first PIN setup
- User confirms eFuse burn via dialog (one-time, irreversible)

#### 2c. Anti-phishing word and identicon derivation ✅
- `esp_hmac_calculate(HMAC_KEY5, SHA256(pin_prefix))` → 256-bit output
- Extract 22 bits (2 x 11-bit indices) → map to 2 BIP39 words via libwally
- Generate 5x5 mirrored identicon with HSL-derived color from HMAC bytes
- Display words + identicon to user for verification
- UI pauses input for 2 seconds when anti-phishing appears, forcing user to check

#### 2d. Split PIN flow ✅
1. User chooses full PIN during setup, confirms it, selects split position interactively
2. Device computes anti-phishing words + identicon from prefix, user records them
3. On each unlock:
   - Enter PIN prefix → device displays identicon + 2 BIP39 words (with 2s pause)
   - User verifies words and image match their recorded pair
   - Enter PIN suffix → full PIN authenticates via PBKDF2 hash check

#### 2e. Wipe after N consecutive failures ✅
- Configurable failure threshold (5/10/15/20/30/50 attempts, default 10)
- After threshold: wipe NVS (PIN hash, settings) and SPIFFS (mnemonics and descriptors), then reboot
- Wipe check occurs before revealing hash mismatch (timing-safe)
- Textarea content scrubbed from heap with `secure_memzero()` after use

**What anti-phishing detects today**: device swap (different eFuse → different words), flash chip cloned to new board. **What it does NOT yet detect**: firmware tampering on the same chip — malicious firmware could fake the anti-phishing display. This gap closes with secure boot (Phase 3), which ensures only signed firmware runs. See "Cross-Phase Security Dependencies" above.

### Phase 3 — Secure Boot

**Irreversible eFuse commitment — practice on a dev board first.**

#### 3a. Key generation and management
- Generate signing keys: `espsecure.py generate_signing_key`
- Key backup strategy: offline, encrypted, redundant storage
- Burn digests into KEY0 (primary) and KEY1 (backup/rotation)
- Document eFuse programming workflow and recovery procedures

#### 3b. Build system integration
- `sdkconfig.secure` overlay with secure boot + anti-rollback config
- CI pipeline: sign firmware images as part of build
- Keep development builds unsigned (separate sdkconfig)
- Anti-rollback counter enabled — firmware includes monotonic security version

### Phase 4 — Partition Table & Air-Gapped SD Card Updates

**Critical**: Must complete and validate before Phase 5 release mode, which permanently disables serial flashing.

#### 4a. Partition table redesign
- Switch to factory + dual OTA layout (see Partition Table section above)
- Add `otadata` partition for OTA slot tracking
- Keep `factory` partition as known-good fallback
- Validate: app partitions 64KB-aligned, offsets contiguous, total fits 32MB flash
- **Migration**: SPIFFS `storage` moves to a new offset and shrinks (7M → ~3.9M) — existing data is lost. Users re-import KEF-encrypted mnemonics/descriptors from SD card or QR backups. NVS is unaffected (same offset/size).

#### 4b. SD card firmware update page
- Settings → Firmware Update → browse SD card for signed `.bin` files
- Firmware signed offline: `espsecure.py sign_data --version <N> --keyfile <key> firmware.bin`
- Update flow using ESP-IDF OTA API (`esp_ota_ops.h`):
  1. `esp_ota_begin()` — allocate OTA slot
  2. `esp_ota_write()` — stream firmware from SD card in chunks
  3. `esp_ota_end()` — verify signature (secure boot) + anti-rollback version
  4. Success → `esp_ota_set_boot_partition()` → confirm → reboot
  5. Failure at any step → stay on current firmware, show error
- Anti-rollback enforced: OTA rejects firmware with security version lower than current eFuse counter

#### 4c. Validation
- Test update cycle: install v1 → update to v2 via SD → verify v2 running
- Test rollback: install bad firmware → verify device stays on previous slot
- Test anti-rollback: attempt downgrade → verify rejection
- **All tests must pass before proceeding to Phase 5 release mode**

### Phase 5 — Flash Encryption

- Enable `CONFIG_SECURE_FLASH_ENC_ENABLED` with **XTS-AES-256** (KEY2 + KEY3)
- PSRAM encryption enabled automatically — protects runtime key material in external RAM
- JTAG and UART download mode locked down automatically

#### Development mode first
- Serial flash fallback still available
- Test full update cycle (SD card OTA) with encryption enabled
- Verify encrypted flash contents are unreadable via physical extraction

#### Release mode (production)
- **Only after SD card updates are proven reliable with encryption enabled**
- Permanently disables serial flash — no going back
- Device is now fully locked: firmware updates only via signed SD card OTA

### Phase 6 — NVS Encryption

- Burn HMAC key into eFuse KEY4
- Enable `CONFIG_NVS_ENCRYPTION` + `CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC`
- All NVS data (PIN hash, settings, cached descriptors) encrypted at rest
- Key derived from eFuse HMAC at runtime — no separate key partition needed
- **Migration**: Enabling NVS encryption requires re-initializing the NVS partition — existing plaintext entries (PIN hash, settings) are lost. Firmware detects missing PIN hash and triggers PIN setup. Anti-phishing words remain the same (eFuse KEY5 is permanent).

### Phase 7 (Future) — TEE / World Controller

- Investigate ESP32-P4 World Controller / PMS maturity in ESP-IDF
- Goal: signing operations in World0 (secure), UI in World1 (non-secure)
- Most complex and least mature — watch Espressif's ESP-TEE progress
- Pragmatic measures (secure_memzero, PSRAM encryption, session-only keys) provide good coverage meanwhile
