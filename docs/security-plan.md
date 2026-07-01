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
- **Secure Boot v2** — **RSA-3072 (RSA-PSS)**, up to 3 key digest slots in eFuse. Kern burns all 3 (KEY0/1/2) to allow two key rotations. **ECDSA is not used**: ECDSA-based Secure Boot v2 is non-functional on ESP32-P4 silicon (chip errata; would require `CONFIG_SECURE_BOOT_INSECURE`). RSA-3072 is also the faster verifier here (~14.8 ms vs ~61.1 ms). See [secure-boot.md](secure-boot.md).
- **Flash Encryption** — XTS-AES-128/256, auto-encrypts PSRAM too. On ESP32-P4 the **Key Manager** can hold the XTS key outside the shared eFuse key blocks (`CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE`), which is what lets Kern keep XTS-AES-256 while spending KEY0–KEY2 on secure boot digests.
- **NVS Encryption** — HMAC-based key derivation from eFuse (no separate key partition needed); independent of flash encryption
- **RSA/MPI + Digital Signature peripherals** — hardware-accelerated RSA; used by Secure Boot v2 RSA-3072 verification at boot
- **HMAC peripheral** — computes HMAC-SHA256 using eFuse keys without exposing them to software; used for anti-phishing word derivation (`esp_hmac_calculate()` with `HMAC_KEY5` purpose) and NVS key derivation (KEY4)
- **AES/SHA hardware accelerators** — transparent via mbedTLS, useful for KEF and general crypto
- **TRNG** — hardware entropy source for random numbers generation (mix with additional sources)
- **Anti-rollback** — security version counter in eFuse
- **JTAG/UART lockdown** — automatic when security features are enabled

### NOT usable for Bitcoin
- **ECDSA peripheral** — P-192/P-256 only, **secp256k1 not supported**. All Bitcoin signing uses software libsecp256k1 via libwally-core. (Separate from the ECDSA *secure-boot verification* defect noted above — that is a boot-ROM issue, this is about the signing curve.)
- **Digital Signature peripheral** — RSA-based, no Bitcoin application. (Still used indirectly: it is the RSA engine behind Secure Boot v2.)

### Future potential
- **World Controller / PMS** — two-world privilege separation (secure vs non-secure). ESP-IDF support for ESP32-P4 TEE still maturing. Could isolate signing operations from UI.

### eFuse Key Block Allocation

| Block | Purpose | Phase |
|-------|---------|-------|
| KEY0 (BLK4) | Secure Boot Digest 0 (primary) | Phase 5 |
| KEY1 (BLK5) | Secure Boot Digest 1 (rotation #1) | Phase 5 |
| KEY2 (BLK6) | Secure Boot Digest 2 (rotation #2) | Phase 5 |
| KEY3 (BLK7) | Flash Encryption XTS-AES key (see note) | Phase 4 |
| KEY4 (BLK8) | HMAC for NVS encryption (HMAC_UP) | Phase 3 |
| KEY5 (BLK9) | HMAC for anti-phishing words (HMAC_UP) | Phase 2 |

All 6 key blocks allocated. Kern spends **three** blocks on secure-boot digests (KEY0–KEY2) so it can rotate a compromised key twice instead of once. Because all three digest *slots* are populated, no free slot remains for an attacker to inject a rogue signing key. Both HMAC keys (KEY4, KEY5) use the `HMAC_UP` purpose — software can request HMAC computations but never reads the raw key material.

**Flash-encryption note:** With three digest slots taking KEY0–KEY2, only one key block (KEY3) is left, but XTS-AES-256 normally needs two. Kern keeps 256-bit strength by deploying the flash-encryption key through the ESP32-P4 **Key Manager** (`CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE`), which stores the key outside the shared eFuse blocks (leaving KEY3 spare). The fallback, if the Key Manager path is not adopted, is **XTS-AES-128** stored in KEY3 (single block). This is finalized in Phase 4.

## Partition Table

The live layout in [`partitions.csv`](../partitions.csv) (`CONFIG_PARTITION_TABLE_CUSTOM=y`) — factory + dual OTA:

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

**Rationale**: Factory partition provides a known-good fallback that cannot be overwritten by OTA. Dual OTA enables safe A/B updates — if a new firmware fails, the device rolls back to the previous working slot. App partitions are 64KB-aligned as required by ESP-IDF.

## Phase Ordering Rationale

The lockdown phases are ordered so that the **roadmap order is also the safe, irreversible eFuse burn order** — there is no separate "burn order" to track. Every read-protected key (KEY5, KEY4, the flash-encryption key) is burned in Phases 2–4, all *before* secure boot (Phase 5) write-protects `RD_DIS`:

1. **Phase 2 (PIN + anti-phishing)** — pure software except one eFuse burn: KEY5 (anti-phishing HMAC), read-protected at burn time, provisioned during first PIN setup.

2. **Phase 3 (NVS encryption)** — coupled to PIN setup, on-device. Burns KEY4 and encrypts the `nvs` partition so the PIN hash is stored at rest. Independent of flash encryption; KEY4 is read-protected here, before secure boot.

3. **Phase 4 (flash encryption + FE key) before Phase 5 (secure boot)** — enabling secure boot write-protects `RD_DIS`, after which no other key block can be read-protected. So the flash-encryption XTS key must be burned in Phase 4. Flash encryption runs in **development mode** here, keeping serial recovery; it is serial-provisioned (Profile B).

4. **Phase 5 (secure boot) before Phase 6 (SD updates)** — SD card updates verify firmware signatures; secure boot provides the signing infrastructure that OTA verification depends on.

5. **Phase 6 (SD updates) before Phase 7 (release lockdown)** — release lockdown permanently disables serial flashing. The SD update path **must** be proven reliable first, or the device becomes un-updatable.

6. **Phase 7 (release lockdown) last** — the only irreversible-and-*unrecoverable* step: flash-encryption release mode + disabling serial download. Everything before it is recoverable (development mode allows re-flashing over serial).

### Cross-Phase Security Dependencies

Some features only reach their full security guarantee when combined with later phases. Until those phases are complete, certain attack vectors remain open:

| Feature (Phase) | Depends on | Gap until dependency is met |
|-----------------|------------|----------------------------|
| Anti-phishing words (2) | Secure Boot (5) | Anti-phishing detects a *different chip* (eFuse mismatch), but an attacker who controls the firmware can bypass the check entirely — malicious firmware on the *same chip* can fake the words or exfiltrate the PIN. Secure boot closes this by ensuring only signed firmware runs. |
| Anti-phishing words (2) | Flash Encryption (4) | Without flash encryption, an attacker with physical access can read the firmware binary and app partitions and clone them to another board. Flash encryption makes those unreadable. (The PIN hash and split position live in `nvs` — that is protected by NVS encryption, Phase 3, not by flash encryption.) |
| PIN hash in NVS (2) | NVS Encryption (3) | The PBKDF2 hash is stored in NVS. Until NVS encryption, physical flash extraction exposes it to offline brute-force (limited by 100k PBKDF2 iterations and the device-bound salt, but still a risk for weak PINs). NVS encryption removes this vector — and, being coupled to PIN setup, is the default for any PIN user. |
| PIN hash in NVS (2) | NVS Encryption (3), **not** Flash Encryption (4) | Common misconception: flash encryption does **not** encrypt the `nvs` partition — ESP-IDF excludes it because NVS's wear-levelled writes are incompatible with the block cipher. NVS encryption (Phase 3) is what protects the PIN hash at rest, independent of flash encryption. |
| Wipe-after-N-failures (2) | Secure Boot (5) | Custom firmware could reset the failure counter or skip the wipe check. Secure boot prevents running unauthorized firmware. |
| SD card OTA (6) | Secure Boot (5) | Without secure boot, the OTA path cannot verify firmware signatures — any `.bin` file would be accepted. Secure boot is a hard prerequisite. |
| Session timeout (2) | Flash Encryption (4) | After timeout, keys are wiped from RAM, but PSRAM contents could theoretically be probed. Flash encryption auto-enables PSRAM encryption, closing this gap. |

**In summary**: Phase 2 provides strong *usability-layer* security (PIN gating, anti-phishing UX, auto-wipe), and Phase 3 encrypts the PIN hash at rest by default — but tamper-detection guarantees are only as strong as firmware integrity. Secure boot (Phase 5) and flash encryption (Phase 4) are what turn anti-phishing from "detects accidental device swaps" into "cryptographically proves device authenticity".

## Enablement Mechanics & Deployment Profiles

The lockdown phases (3–7) are sequenced so the roadmap order **is** the safe eFuse burn order. What still needs spelling out is *how* each feature activates — which determines whether it can be a tools-free on-device action or needs serial provisioning — and the one hardware constraint that fixes the order.

### Deployment profiles

Not every user wants the full lockdown. Two supported profiles:

- **Profile A — On-device (tools-free).** PIN + anti-phishing (Phase 2), **NVS encryption** (Phase 3), and **Secure Boot** (Phase 5), all driven from on-device flows — no serial tools. The read-protected keys (KEY5, KEY4) are burned during PIN setup, before secure boot locks `RD_DIS`. This protects firmware integrity, the PIN hash at rest, and clone detection — the fully self-sovereign path. It omits flash encryption (which needs serial) and release lockdown.
- **Profile B — Fully locked (serial-provisioned).** Profile A **plus** Flash Encryption (Phase 4) and Release Lockdown (Phase 7). Because flash encryption cannot be a UI toggle (below), this profile adds a one-time serial provisioning step while serial still works.

### On-device vs. serial activation

| Feature | How it activates | Self-transforms flash? | Brick risk |
|---------|------------------|------------------------|------------|
| NVS Encryption (3) | **On-device, coupled to PIN setup** — app burns KEY4, then `nvs_flash_secure_init()`; the new PIN hash is written into encrypted NVS | No — the `nvs` partition is erased and re-initialized encrypted | Low: recoverable; worst case NVS re-init → PIN re-setup. Device still boots |
| Secure Boot (5) | **On-device UI** — app burns the three digests + `SECURE_BOOT_EN`; already-signed images stay valid | No | Only if lockdown runs while *unsigned* firmware is booted (guarded in Phase 5) |
| Flash Encryption (4) | **Serial only** — enabled by the *bootloader* on first boot; requires a bootloader built with `CONFIG_SECURE_FLASH_ENC_ENABLED`, flashed over serial | **Yes** — bootloader encrypts bootloader + app + `encrypted` partitions *in place* on first boot (up to ~1 min) | Real: power loss during the first-boot pass corrupts flash. Recoverable in development mode; release mode (Phase 7) makes serial recovery impossible |

**Consequence:** the tools-free on-device flows cover NVS encryption and secure boot (all of Profile A). Flash encryption **cannot** be a UI toggle — there is no supported API for a running app to enable flash encryption over a non-FE bootloader, and forcing the eFuse would brick. Profile B therefore adds serial provisioning.

### The hard constraint: read-protected keys before secure boot

Per Espressif's security-features workflow, **Flash Encryption must be enabled before Secure Boot** — which is why Phase 4 precedes Phase 5. Enabling secure boot **write-protects `RD_DIS`** (so the secure-boot digests stay readable for the ROM to verify). Once `RD_DIS` is write-protected, read-protection can **no longer be set on any other key block** — including the flash-encryption XTS key and the NVS-encryption HMAC key. A key left software-readable defeats its own purpose.

**Rule: every read-protected key is burned *and* read-protected before `SECURE_BOOT_EN` is set in Phase 5.** The phase order guarantees this:

- KEY5 (anti-phishing HMAC) — Phase 2, during PIN setup.
- KEY4 (NVS HMAC) — Phase 3, during PIN setup.
- Flash-encryption XTS key — Phase 4. The ESP32-P4 **Key Manager** path may store this key outside a shared eFuse block; confirm on a dev board.

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

**What anti-phishing detects today**: device swap (different eFuse → different words), flash chip cloned to new board. **What it does NOT yet detect**: firmware tampering on the same chip — malicious firmware could fake the anti-phishing display. This gap closes with secure boot (Phase 5), which ensures only signed firmware runs. See "Cross-Phase Security Dependencies" above.

### Phase 3 — NVS Encryption (coupled to PIN setup)

**On-device, no serial tools — part of Profile A.** NVS encryption protects the PIN hash (and settings) at rest. It is independent of flash encryption: its keys derive from an eFuse HMAC key (KEY4), not from anything in flash, so a flash dump yields only ciphertext. Its only ordering constraint is that KEY4 must be burned before secure boot (Phase 5) write-protects `RD_DIS` — naturally satisfied, since this phase runs during PIN setup (right after Phase 2).

**Why couple it to the PIN:** enabling NVS encryption erases and re-initializes the `nvs` partition, which would wipe an existing PIN hash. Doing it *as part of setting the PIN* removes that chicken-and-egg — KEY4 is burned and NVS is re-initialized encrypted *before* the new PIN hash is written, so the hash lands directly in encrypted storage. It also makes at-rest protection the **default** for any PIN user (rather than an optional late step), and mirrors the anti-phishing self-provisioning (KEY5, Phase 2b).

#### 3a. PIN-triggered provisioning
- Setting a PIN (first setup, reset via `pin_change()`, or disable→re-enable) runs — after an explicit warning that this is a **permanent OTP write and clears current NVS settings**:
  1. Burn **KEY4** (256-bit TRNG key, purpose `HMAC_UP`, read- and write-protected) — idempotent, mirroring `pin_efuse_provision()` for KEY5.
  2. Encrypt and re-initialize the `nvs` partition (`nvs_flash_secure_init()`, HMAC scheme).
  3. Write the new PIN hash into the now-encrypted NVS.
- **Existing devices** (plaintext NVS, KEY4 not yet burned) migrate the first time the user changes/resets/re-enables their PIN. A device whose PIN is never touched stays on plaintext NVS until then.
- **Implementation note:** cleanest is to burn KEY4, then reboot; on boot the firmware sees KEY4 present, secure-inits NVS (erasing the old plaintext), and resumes PIN setup — avoiding mid-session `nvs_flash_deinit()`/erase juggling.

#### 3b. Mechanism (HMAC scheme — no key partition)
- The XTS-AES-256 keys that encrypt NVS (a 512-bit key set) are derived at runtime from the 256-bit KEY4 (`ESP_EFUSE_KEY_PURPOSE_HMAC_UP`). Software never reads the raw key — the HMAC peripheral derives the NVS keys on demand. No `nvs_keys` partition is needed (unlike the flash-encryption-based NVS scheme, which requires a `data`/`nvs_keys` partition).
- Configuration:

```
CONFIG_NVS_ENCRYPTION=y
CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC=y   # HMAC scheme (not the flash-encryption scheme)
CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=4        # BLOCK_KEY4
```

- Registration: `nvs_sec_provider_register_hmac()` → `nvs_flash_read_security_cfg_v2()` → `nvs_flash_secure_init()`.

#### 3c. Notes
- **All-or-nothing:** unlike anti-phishing (which falls back to a deterministic salt if the HMAC peripheral is unavailable), NVS encryption has no plaintext fallback — once KEY4 is burned and NVS is encrypted, that is permanent.
- **Independent of flash encryption:** flash encryption (Phase 4) deliberately leaves `nvs` unencrypted anyway (NVS's wear-levelled writes are incompatible with the block cipher), so NVS encryption is the mechanism that protects the PIN hash at rest whether or not flash encryption is used.
- Anti-phishing words are unaffected (KEY5 is permanent and independent of KEY4).

### Phase 4 — Flash Encryption (development mode) + FE Key Provisioning

**Profile B only; serial-provisioned.** Precedes secure boot (Phase 5) so the flash-encryption key is read-protected before `RD_DIS` locks. Flash encryption runs in **development mode** here — serial recovery stays available; the irreversible serial-disable is deferred to Phase 7. See [Enablement Mechanics & Deployment Profiles](#enablement-mechanics--deployment-profiles).

**Irreversible eFuse commitment — practice on a dev board first.**

#### 4a. Flash-encryption key provisioning
- Provision the **flash-encryption XTS key**: preferably via the ESP32-P4 **Key Manager** (`CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE`), keeping XTS-AES-256 with the key outside the shared blocks; fallback is **XTS-AES-128** in eFuse KEY3. Decide and validate before committing.
- KEY4 (NVS, Phase 3) and KEY5 (anti-phishing, Phase 2) are already burned.

#### 4b. Enable flash encryption (development mode)
- `CONFIG_SECURE_FLASH_ENC_ENABLED` with **XTS-AES-256**; key size / source per 4a.
- **Not an on-device toggle**: flash an FE-built, signed bootloader over serial; the bootloader self-encrypts flash (bootloader + app + `encrypted` partitions) *in place* on first boot (~1 min). **Do not interrupt power** — a partial pass corrupts flash.
- Development mode retains serial fallback for re-flashing/recovery.
- PSRAM encryption is enabled automatically — protects runtime key material in external RAM.
- Verify encrypted flash contents are unreadable via physical extraction.

### Phase 5 — Secure Boot

**Irreversible eFuse commitment — practice on a dev board first.** All read-protected keys (KEY4, KEY5, and the flash-encryption key) were burned in Phases 2–4, so it is safe for secure boot to write-protect `RD_DIS` here. For the full mechanics, key ceremony, rotation, and on-device lockdown flow, see [secure-boot.md](secure-boot.md).

#### 5a. Key generation and management
- Generate three RSA-3072 signing keys: `espsecure generate-signing-key --version 2 --scheme rsa3072`
- Key backup strategy: offline, encrypted, redundant storage (per key)
- Burn digests into KEY0 (primary), KEY1 (rotation #1), and KEY2 (rotation #2)
- Sign the **bootloader with all three keys** (it is frozen at flash time and must survive rotations); the app is signed with the current primary key
- Document eFuse programming workflow and recovery procedures

#### 5b. Build system integration
- `sdkconfig.secure` overlay with secure boot + anti-rollback config (`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y`)
- Leave `CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE` **off** — revoking a good key on one failed verification is a bricking hazard for a wallet
- CI pipeline: build unsigned, developer signs images offline as part of release
- Keep development builds unsigned (separate sdkconfig)
- Anti-rollback counter enabled — firmware includes monotonic security version
- Note ESP-IDF 6.0 API renames: `esp_secure_boot_verify_signature_block()` removed (use `esp_secure_boot_verify_rsa_signature_block()`); `esp_flash_encryption_enabled()` deprecated (use `esp_efuse_is_flash_encryption_enabled()`)

### Phase 6 — Air-Gapped SD Card Updates

**Critical**: Must complete and validate before Phase 7 release lockdown, which permanently disables serial flashing.

#### 6a. Partition table redesign ✅
- Factory + dual OTA layout implemented (see Partition Table section above)
- `otadata` partition added for OTA slot tracking
- `factory` partition as known-good fallback
- App partitions 64KB-aligned, offsets contiguous, total fits 16MB flash

#### 6b. SD card firmware update page
- Settings → Firmware Update → browse SD card for signed `.bin` files
- Firmware signed offline: `espsecure sign-data --version 2 --keyfile <key> firmware.bin`
- Update flow using ESP-IDF OTA API (`esp_ota_ops.h`):
  1. `esp_ota_begin()` — allocate OTA slot
  2. `esp_ota_write()` — stream firmware from SD card in chunks
  3. `esp_ota_end()` — verify signature (secure boot) + anti-rollback version
  4. Success → `esp_ota_set_boot_partition()` → confirm → reboot
  5. Failure at any step → stay on current firmware, show error
- Anti-rollback enforced: OTA rejects firmware with security version lower than current eFuse counter

#### 6c. Validation
- Test update cycle: install v1 → update to v2 via SD → verify v2 running
- Test rollback: install bad firmware → verify device stays on previous slot
- Test anti-rollback: attempt downgrade → verify rejection
- **All tests must pass before proceeding to Phase 7 release lockdown**

### Phase 7 — Release Lockdown

**The point of no return — only after Phase 6 SD updates are proven reliable.** This is the single unrecoverable step; everything before it allowed serial recovery.

- Switch flash encryption from development to **release mode**: write-protects `SPI_BOOT_CRYPT_CNT` and burns `DIS_DOWNLOAD_MANUAL_ENCRYPT` — flashing plaintext firmware over serial is no longer possible.
- Restrict UART ROM download to **secure download mode** (or disable it), and confirm JTAG is locked down.
- After this, the device is fully locked: firmware updates only via signed SD card OTA (Phase 6).
- Verify: unsigned/plaintext serial flash is rejected; SD OTA still works; a power-loss during an SD update still boots the previous slot.

### Phase 8 (Future) — TEE / World Controller

- Investigate ESP32-P4 World Controller / PMS maturity in ESP-IDF
- Goal: signing operations in World0 (secure), UI in World1 (non-secure)
- Most complex and least mature — watch Espressif's ESP-TEE progress
- Pragmatic measures (secure_memzero, PSRAM encryption, session-only keys) provide good coverage meanwhile
