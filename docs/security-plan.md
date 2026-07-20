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
| PIN-counter rewind | Snapshot/restore of external flash to reset failure counter | **Residual risk — PIN entropy is the backstop (see below)** |
| Fault injection | Voltage/EM glitching of boot or PIN checks | **Residual risk — not a secure element (see below)** |

### Accepted Residual Risks

The ESP32-P4 is not a secure element; two physical attacks remain open by construction and are accepted with mitigations rather than eliminated:

- **NVS replay (PIN-counter rewind).** XTS encryption provides confidentiality, not integrity or freshness. The flash is an external chip: an attacker who can rewrite it can snapshot the encrypted `nvs` partition, spend N−1 PIN attempts, restore the snapshot, and repeat — resetting the failure counter and exponential backoff indefinitely, even with NVS encryption, flash encryption, and secure boot all enabled. Wipe-after-N-failures and backoff therefore only hold against attackers who cannot rewrite flash. The backstop is PIN entropy: the device-bound PBKDF2 salt (eFuse KEY5) forces every guess through this specific chip, so a long PIN stays strong even against counter rewind.
- **Fault injection / glitching.** Voltage and EM glitching have a public history on earlier ESP32 generations; the ESP32-P4 has no proven resistance and no anti-glitch hardware guarantees. Mitigations that limit the payoff: mnemonics exist only in RAM (session-only) or KEF-encrypted at rest, and the PIN itself is never stored — only its PBKDF2 hash.
- **Plaintext SPIFFS residue.** Flash encryption never covers the `storage` partition (SPIFFS is incompatible with encrypted partitions — see [Cross-Phase Security Dependencies](#cross-phase-security-dependencies)). Mnemonics are always stored as KEF envelopes, but descriptors saved unencrypted (`.txt`), file names/sizes, and KEF header metadata (version, iterations, user-chosen label) remain readable via physical flash extraction even after full Phase 7 lockdown. This leaks xpubs and wallet structure — a privacy exposure, not key material.

## ESP32-P4 Security Hardware Summary

### Usable for Kern
- **Secure Boot v2** — **RSA-3072 (RSA-PSS)**, up to 3 key digest slots in eFuse. Kern burns all 3 (KEY0/1/2) to allow two key rotations. **ECDSA is not used**: ECDSA-based Secure Boot v2 is non-functional on ESP32-P4 silicon (chip errata; would require `CONFIG_SECURE_BOOT_INSECURE`). RSA-3072 is also the faster verifier here (~14.8 ms vs ~61.1 ms). See [secure-boot.md](secure-boot.md).
- **Flash Encryption** — XTS-AES-128/256, auto-encrypts PSRAM too. On ESP32-P4 the **Key Manager** can hold the XTS key outside the shared eFuse key blocks (Kconfig choice `SECURE_FLASH_ENCRYPTION_KEY_SOURCE`, option `..._KEY_MGR`), which is what lets Kern keep XTS-AES-256 while spending KEY0–KEY2 on secure boot digests.
- **NVS Encryption** — HMAC-based key derivation from eFuse (no separate key partition needed); independent of flash encryption
- **RSA/MPI + Digital Signature peripherals** — hardware-accelerated RSA; used by Secure Boot v2 RSA-3072 verification at boot
- **HMAC peripheral** — computes HMAC-SHA256 using eFuse keys without exposing them to software; used for anti-phishing word derivation (`esp_hmac_calculate()` with `HMAC_KEY5` purpose) and NVS key derivation (KEY4)
- **AES/SHA hardware accelerators** — transparent via mbedTLS, useful for KEF and general crypto
- **TRNG** — hardware entropy source for random numbers generation (mix with additional sources)
- **Anti-rollback** — security version counter in eFuse
- **JTAG/UART lockdown** — automatic only when the *stock bootloader* enables the security features; Kern's on-device lockdown flow must burn the same eFuse set itself (JTAG-disable set, download-mode restriction — see [secure-boot.md §5a](secure-boot.md#5-user-scenarios))

### NOT usable for Bitcoin
- **ECDSA peripheral** — P-192/P-256 only, **secp256k1 not supported**. All Bitcoin signing uses software libsecp256k1 via libwally-core. (Separate from the ECDSA *secure-boot verification* defect noted above — that is a boot-ROM issue, this is about the signing curve.)
- **Digital Signature peripheral** — RSA-based, no Bitcoin application. (Still used indirectly: it is the RSA engine behind Secure Boot v2.)

### Future potential
- **World Controller / PMS** — two-world privilege separation (secure vs non-secure). ESP-IDF support for ESP32-P4 TEE still maturing. Could isolate signing operations from UI.

### eFuse Key Block Allocation

| Block | Purpose | Phase |
|-------|---------|-------|
| KEY0 (BLK4) | Secure Boot Digest 0 (primary) | Phase 6 |
| KEY1 (BLK5) | Secure Boot Digest 1 (rotation #1) | Phase 6 |
| KEY2 (BLK6) | Secure Boot Digest 2 (rotation #2) | Phase 6 |
| KEY3 (BLK7) | Flash Encryption XTS-AES key (see note) | Phase 5 |
| KEY4 (BLK8) | HMAC for NVS encryption (HMAC_UP) | Phase 3 |
| KEY5 (BLK9) | HMAC for anti-phishing words (HMAC_UP) | Phase 2 |

All 6 key blocks allocated. Kern spends **three** blocks on secure-boot digests (KEY0–KEY2) so it can rotate a compromised key twice instead of once. Because all three digest *slots* are populated, no free slot remains for an attacker to inject a rogue signing key. Both HMAC keys (KEY4, KEY5) use the `HMAC_UP` purpose — software can request HMAC computations but never reads the raw key material.

**Flash-encryption note:** With three digest slots taking KEY0–KEY2, only one key block (KEY3) is left, but XTS-AES-256 normally needs two. Kern keeps 256-bit strength by deploying the flash-encryption key through the ESP32-P4 **Key Manager** (Kconfig choice `SECURE_FLASH_ENCRYPTION_KEY_SOURCE`, option `..._KEY_MGR`), which stores the key outside the shared eFuse blocks (leaving KEY3 spare). The fallback, if the Key Manager path is not adopted, is **XTS-AES-128** stored in KEY3 (single block). This is finalized in Phase 5.

## Partition Table

### Current layout (pre-Phase 3)

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

### Target layout (Phase 3 migration)

Phase 3 replaces the layout above with an OTA-only table:

```
# Name    Type  SubType  Offset     Size       (Human)
nvs       data  nvs      0x9000     0x15000    (84K)
otadata   data  ota      0x1E000    0x2000     (8K)
ota_0     app   ota_0    0x20000    0x600000   (6M)
ota_1     app   ota_1    0x620000   0x600000   (6M)
storage   data  spiffs   0xC20000   0x3E0000   (~3.9M)
```

**Why factory is dropped**: ESP-IDF's anti-rollback (Phase 6) assumes an OTA-only table — `bootloader_utility.c` states it outright: "When CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is enabled factory partition should not be in partition table, only two ota_app are there." A factory image is frozen at flash time with security version 0, so the first eFuse counter increment would make it unbootable — the "known-good fallback" guarantee silently dies. The fallback role moves to the *previous OTA slot*: the SD update flow must self-test and call `esp_ota_mark_app_valid_cancel_rollback()`, otherwise the bootloader rolls back (see Phase 4). With empty `otadata`, the bootloader boots `ota_0` directly, which is where serial flashing writes the app.

**Why the migration happens at Phase 3**: a partition table can only be rewritten over serial — OTA never touches it — and it is frozen for the life of the device once secure boot (Phase 6) restricts serial to signed images and release lockdown (Phase 7) disables serial entirely. Phase 3 already forces the one disruptive event for alpha testers (NVS wipe + fresh PIN + KEY4 burn), so the table migration rides the same re-flash instead of adding a second one.

**Layout choices**:

- `ota_0` inherits the old `factory` offset (0x20000) — serial flashing lands the app at the same address as before.
- `storage` keeps its exact offset and size — KEF-encrypted mnemonics/descriptors already saved to SPIFFS survive the migration untouched.
- App slots grow 4MB → 6MB. The app is ~1.7MB today, but the table is permanent after Phase 6, so the headroom (fonts, languages, assets) is free insurance — the space comes from the dropped factory partition.
- NVS grows 24KB → 84KB, filling the space up to `ota_0` exactly. More pages improve wear-leveling for the failure-counter write on every PIN attempt. Note that old NVS content **survives** the resize: NVS pages are self-contained 4K units, so the old pages parse fine inside the larger partition, and flashing never writes the `nvs` region. A pre-existing plaintext PIN is therefore still present after the update — handled by the firmware-side migration in 3a.
- `phy_init` is dropped — the ESP32-P4 has no radio, no `CONFIG_ESP_PHY*` option is set, and the partition was never read.

## Phase Ordering Rationale

The lockdown phases are ordered so that the **roadmap order is also the safe, irreversible eFuse burn order** — there is no separate "burn order" to track. Every read-protected key (KEY5, KEY4, the flash-encryption key) is burned in Phases 2, 3 and 5, all *before* secure boot (Phase 6) write-protects `RD_DIS`; Phase 4 (SD updates) burns nothing:

1. **Phase 2 (PIN + anti-phishing)** — pure software except one eFuse burn: KEY5 (anti-phishing HMAC), read-protected at burn time, provisioned during first PIN setup.

2. **Phase 3 (NVS encryption)** — coupled to PIN setup, on-device. Burns KEY4 and encrypts the `nvs` partition so the PIN hash is stored at rest. Independent of flash encryption; KEY4 is read-protected here, before secure boot. Phase 3 also carries the one-time **partition-table migration** (factory dropped for anti-rollback — see [Partition Table](#partition-table)): the last cheap moment for it, since a partition table can only change over serial and is frozen once Phase 6 locks the device.

3. **Phase 4 (SD updates) before any irreversible step** — signature verification does **not** require secure boot: `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT` makes the OTA path verify Secure Boot v2 RSA-3072 signatures against the public keys embedded in the running app — pure software, no eFuse burns, fully reversible. Implementing it first field-proves the only post-lockdown update channel while serial recovery still exists, and pulls the signing-key ceremony forward (the same keys become the Phase 6 eFuse digests).

4. **Phase 5 (flash encryption + FE key) before Phase 6 (secure boot)** — enabling secure boot write-protects `RD_DIS`, after which no other key block can be read-protected. So the flash-encryption XTS key must be burned in Phase 5. Flash encryption runs in **development mode** here, keeping serial recovery; it is serial-provisioned (Profile B).

5. **Phase 6 (secure boot) before Phase 7 (release lockdown)** — secure boot upgrades the Phase 4 signature check from update-time-only to boot-time enforcement and arms eFuse anti-rollback. Release lockdown permanently disables serial flashing, so the Phase 4 validation suite must be re-run and pass under secure boot before Phase 7.

6. **Phase 7 (release lockdown) last** — the only irreversible-and-*unrecoverable* step: flash-encryption release mode + disabling serial download. Everything before it is recoverable (development mode allows re-flashing over serial).

### Cross-Phase Security Dependencies

Some features only reach their full security guarantee when combined with later phases. Until those phases are complete, certain attack vectors remain open:

| Feature (Phase) | Depends on | Gap until dependency is met |
|-----------------|------------|----------------------------|
| Anti-phishing words (2) | Secure Boot (6) | Anti-phishing detects a *different chip* (eFuse mismatch), but an attacker who controls the firmware can bypass the check entirely — malicious firmware on the *same chip* can fake the words or exfiltrate the PIN. Secure boot closes this by ensuring only signed firmware runs. |
| Anti-phishing words (2) | Flash Encryption (5) | Without flash encryption, an attacker with physical access can read the firmware binary and app partitions and clone them to another board. Flash encryption makes those unreadable. (The PIN hash and split position live in `nvs` — that is protected by NVS encryption, Phase 3, not by flash encryption.) |
| PIN hash in NVS (2) | NVS Encryption (3) | The PBKDF2 hash is stored in NVS. Until NVS encryption, physical flash extraction exposes it to offline brute-force (limited by 100k PBKDF2 iterations and the device-bound salt, but still a risk for weak PINs). NVS encryption removes this vector — and, being coupled to PIN setup, is the default for any PIN user. |
| PIN hash in NVS (2) | NVS Encryption (3), **not** Flash Encryption (5) | Common misconception: flash encryption does **not** encrypt the `nvs` partition — ESP-IDF excludes it because NVS's wear-levelled writes are incompatible with the block cipher. NVS encryption (Phase 3) is what protects the PIN hash at rest, independent of flash encryption. |
| KEF storage on SPIFFS (1) | **not** Flash Encryption (5) | Same misconception for the `storage` partition: flash encryption never covers it — ESP-IDF's SPIFFS driver is incompatible with encrypted partitions (SPIFFS progressively programs NOR bits in already-written pages, which XTS's write-once 16-byte blocks cannot express), and `storage` carries no `encrypted` flag. KEF (Phase 1) is the at-rest protection for mnemonics/descriptors there, independent of flash encryption. |
| NVS encryption (3) | Secure Boot (6) | `HMAC_UP` computations are software-invokable: until secure boot, attacker firmware on the *same chip* can drive the HMAC peripheral to derive the NVS keys and decrypt a dumped `nvs` partition (PIN hash included). Without the chip, the keys stay out of reach either way. |
| Wipe-after-N-failures (2) | Secure Boot (6) | Custom firmware could reset the failure counter or skip the wipe check. Secure boot prevents running unauthorized firmware. |
| SD card OTA (4) | Secure Boot (6) | The OTA path already verifies Secure Boot v2 RSA-3072 signatures via `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`, trusting the public keys embedded in the running app — but nothing verifies firmware at *boot*, so an attacker with serial access can still flash unsigned firmware directly. Secure boot closes the serial path and upgrades the software downgrade check to the eFuse anti-rollback counter. |
| Session timeout (2) | Flash Encryption (5) | After timeout, keys are wiped from RAM, but PSRAM contents could theoretically be probed. Flash encryption auto-enables PSRAM encryption, closing this gap. |

**In summary**: Phase 2 provides strong *usability-layer* security (PIN gating, anti-phishing UX, auto-wipe), and Phase 3 encrypts the PIN hash at rest by default — but tamper-detection guarantees are only as strong as firmware integrity. Secure boot (Phase 6) and flash encryption (Phase 5) are what turn anti-phishing from "detects accidental device swaps" into "cryptographically proves device authenticity".

## Enablement Mechanics & Deployment Profiles

The lockdown phases (3–7) are sequenced so the roadmap order **is** the safe eFuse burn order. What still needs spelling out is *how* each feature activates — which determines whether it can be a tools-free on-device action or needs serial provisioning — and the one hardware constraint that fixes the order.

### Deployment profiles

Not every user wants the full lockdown. Two supported profiles:

- **Profile A — On-device (tools-free).** PIN + anti-phishing (Phase 2), **NVS encryption** (Phase 3), and **Secure Boot** (Phase 6), all driven from on-device flows — no serial tools. The read-protected keys (KEY5, KEY4) are burned during PIN setup, before secure boot locks `RD_DIS`. This protects firmware integrity, the PIN hash at rest, and clone detection — the fully self-sovereign path. It omits flash encryption (which needs serial) and release lockdown.
- **Profile B — Fully locked (serial-provisioned).** Profile A **plus** Flash Encryption (Phase 5) and Release Lockdown (Phase 7). Because flash encryption cannot be a UI toggle (below), this profile adds a one-time serial provisioning step while serial still works.

### On-device vs. serial activation

| Feature | How it activates | Self-transforms flash? | Brick risk |
|---------|------------------|------------------------|------------|
| NVS Encryption (3) | **On-device, coupled to PIN setup** — app burns KEY4, then `nvs_flash_secure_init()`; the new PIN hash is written into encrypted NVS | No — the `nvs` partition is erased and re-initialized encrypted | Low: recoverable; worst case NVS re-init → PIN re-setup. Device still boots |
| SD card updates (4) | **Build config only** — signed-app verification on update (`SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`); no eFuse touched, reversible | No — writes only to the inactive OTA slot | Low: a failed update stays on the current slot; rollback confirm guards a broken image |
| Secure Boot (6) | **On-device UI** — app burns the three digests, the hardening set (JTAG disable, `DIS_DIRECT_BOOT`, secure download mode), `SECURE_BOOT_EN`, and write-protects `RD_DIS`; already-signed images stay valid | No | Only if lockdown runs while firmware that is unsigned — or signed with keys not matching the digests — is on flash (guarded in Phase 6) |
| Flash Encryption (5) | **Serial only** — enabled by the *bootloader* on first boot; requires a bootloader built with `CONFIG_SECURE_FLASH_ENC_ENABLED`, flashed over serial | **Yes** — bootloader encrypts bootloader + app + `encrypted` partitions *in place* on first boot (up to ~1 min) | Real: power loss during the first-boot pass corrupts flash. Recoverable in development mode; release mode (Phase 7) makes serial recovery impossible |

**Consequence:** the tools-free on-device flows cover NVS encryption and secure boot (all of Profile A). Flash encryption **cannot** be a UI toggle — there is no supported API for a running app to enable flash encryption over a non-FE bootloader, and forcing the eFuse would brick. Profile B therefore adds serial provisioning.

### The hard constraint: read-protected keys before secure boot

Per Espressif's security-features workflow, **Flash Encryption must be enabled before Secure Boot** — which is why Phase 5 precedes Phase 6. Enabling secure boot **write-protects `RD_DIS`** (so the secure-boot digests stay readable for the ROM to verify). Once `RD_DIS` is write-protected, read-protection can **no longer be set on any other key block** — including the flash-encryption XTS key and the NVS-encryption HMAC key. A key left software-readable defeats its own purpose.

**Rule: every read-protected key is burned *and* read-protected before `SECURE_BOOT_EN` is set in Phase 6.** The phase order guarantees this:

- KEY5 (anti-phishing HMAC) — Phase 2, during PIN setup.
- KEY4 (NVS HMAC) — Phase 3, during PIN setup.
- Flash-encryption XTS key — Phase 5. The ESP32-P4 **Key Manager** path may store this key outside a shared eFuse block; confirm on a dev board.

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
- Enforcement is firmware/flash-level only — an attacker who can rewrite the external flash can rewind the counter by restoring an NVS snapshot (see [Accepted Residual Risks](#accepted-residual-risks)); PIN entropy is the ultimate backstop

**What anti-phishing detects today**: device swap (different eFuse → different words), flash chip cloned to new board. **What it does NOT yet detect**: firmware tampering on the same chip — malicious firmware could fake the anti-phishing display. This gap closes with secure boot (Phase 6), which ensures only signed firmware runs. See "Cross-Phase Security Dependencies" above.

### Phase 3 — NVS Encryption + Partition Migration (coupled to PIN setup)

**On-device, no serial tools — part of Profile A.** NVS encryption protects the PIN hash (and settings) at rest. It is independent of flash encryption: its keys derive from an eFuse HMAC key (KEY4), not from anything in flash, so a flash dump yields only ciphertext. Its only ordering constraint is that KEY4 must be burned before secure boot (Phase 6) write-protects `RD_DIS` — naturally satisfied, since this phase runs during PIN setup (right after Phase 2).

**Why couple it to the PIN:** enabling NVS encryption erases and re-initializes the `nvs` partition, which would wipe an existing PIN hash. Doing it *as part of setting the PIN* removes that chicken-and-egg — KEY4 is burned and NVS is re-initialized encrypted *before* the new PIN hash is written, so the hash lands directly in encrypted storage. It also makes at-rest protection the **default** for any PIN user (rather than an optional late step), and mirrors the anti-phishing self-provisioning (KEY5, Phase 2b).

#### 3a. Partition-table migration (rides the Phase 3 firmware update)

The Phase 3 rollout replaces the partition table with the OTA-only layout (see [Partition Table](#partition-table)): factory and `phy_init` dropped, app slots grown to 6MB, NVS grown to 84KB, `storage` untouched. Alpha testers already update over serial (no SD OTA until Phase 4), so the migration adds no extra step — the NVS-encryption *feature* itself stays tools-free.

Migration flow for alpha testers:

1. Warn up front: **settings and PIN are wiped** during the migration (NVS is erased and re-initialized encrypted). SPIFFS-stored encrypted mnemonics/descriptors survive (`storage` offset/size unchanged), but confirm QR/SD backups exist anyway.
2. One serial `just flash` — writes bootloader, new partition table, initial `otadata`, and the app to `ota_0`. Flashing does **not** erase NVS: the old plaintext pages remain valid in the resized partition (see Partition Table above).
3. The firmware closes the gap: if a PIN is configured while NVS is still plaintext, the first successful unlock triggers a one-time prompt that routes into fresh PIN setup, which runs the provisioning below. Declining removes the PIN (a stored PIN implies encrypted NVS). Either way, no device keeps a plaintext PIN hash — there is no plaintext-NVS long tail.

**PIN remains optional.** The forced re-setup above only applies to migrated users who *had* a PIN — they must set one up again (or decline and lose it); it does not make PIN mandatory. A user without a PIN simply runs plaintext NVS holding nothing sensitive (settings only, no hash), same as a fresh no-PIN device; KEY4 is never burned without the consent dialog in 3b. The boot-time NVS branch therefore keys off **KEY4 presence, not PIN presence** — this also covers the PIN-set-then-disabled state, where NVS stays encrypted (3d) with no PIN hash in it.

#### 3b. PIN-triggered provisioning
- Setting a PIN (first setup, PIN change, or disable→re-enable) runs — after an explicit warning that this is a **permanent OTP write and clears current NVS settings**:
  1. Burn **KEY4** (256-bit TRNG key, purpose `HMAC_UP`, read- and write-protected) — idempotent, mirroring `pin_efuse_provision()` for KEY5.
  2. Encrypt and re-initialize the `nvs` partition (`nvs_flash_secure_init()`, HMAC scheme).
  3. Write the new PIN hash into the now-encrypted NVS.
- The partition migration (3a) wipes NVS on every device, so all alpha testers go through this fresh setup — the PIN-change/re-enable trigger remains as the code path for any later device that somehow still has a plaintext NVS.
- **Implementation note:** provisioning runs **in session**, not via burn-then-reboot: after the consent dialog, the firmware burns KEY4, closes the only two NVS handle owners (`pin`, `settings`), then `nvs_flash_deinit()` → erase → encrypted re-init → reopens the handles, and PIN setup continues straight into writing the hash. A reboot-based flow was rejected because nothing survives the NVS wipe to tell the firmware to *resume* PIN setup — the user would have to redo the whole flow. Crash-safety comes from the boot path instead: if power is cut after the burn but before the migration completes, boot sees KEY4 present, fails to secure-init the plaintext partition, erases it, and lands on empty encrypted NVS.
- **Guard the stock auto-burn path:** `nvs_sec_provider`'s HMAC key generation (`generate_keys_hmac()`) burns the eFuse key itself whenever the block is empty — a default `CONFIG_NVS_ENCRYPTION` init would burn KEY4 with no user consent. NVS init must be explicit and branch on KEY4 presence: KEY4 absent → plain `nvs_flash_init()` and never touch the keygen/secure path until the consent dialog; KEY4 present → `nvs_flash_secure_init()`.

#### 3c. Mechanism (HMAC scheme — no key partition)
- The XTS-AES-256 keys that encrypt NVS (a 512-bit key set) are derived at runtime from the 256-bit KEY4 (`ESP_EFUSE_KEY_PURPOSE_HMAC_UP`). Software never reads the raw key — the HMAC peripheral derives the NVS keys on demand. No `nvs_keys` partition is needed (unlike the flash-encryption-based NVS scheme, which requires a `data`/`nvs_keys` partition).
- Configuration:

```
CONFIG_NVS_ENCRYPTION=y
CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC=y   # HMAC scheme (not the flash-encryption scheme)
CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=4        # BLOCK_KEY4
```

- Registration of the HMAC scheme is automatic at startup (`nvs_sec_provider`'s `ESP_SYSTEM_INIT_FN`, harmless — burns nothing); the boot path is `nvs_flash_read_security_cfg_v2(nvs_flash_get_default_security_scheme(), &cfg)` → `nvs_flash_secure_init(&cfg)`, implemented in `core/nvs_secure.c`.

#### 3d. Notes
- **All-or-nothing:** unlike anti-phishing (which falls back to a deterministic salt if the HMAC peripheral is unavailable), NVS encryption has no plaintext fallback — once KEY4 is burned and NVS is encrypted, that is permanent. The same rule applies at setup time: if provisioning fails or KEY4 is unusable, PIN setup is aborted without writing a hash — a PIN hash is never stored in plaintext NVS.
- **Independent of flash encryption:** flash encryption (Phase 5) deliberately leaves `nvs` unencrypted anyway (NVS's wear-levelled writes are incompatible with the block cipher), so NVS encryption is the mechanism that protects the PIN hash at rest whether or not flash encryption is used.
- Anti-phishing words are unaffected (KEY5 is permanent and independent of KEY4).

### Phase 4 — Air-Gapped SD Card Updates

**Deliberately before secure boot.** ESP-IDF's *signed-app verification without secure boot* (`CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT` + `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`, RSA scheme) makes the OTA path perform full Secure Boot v2 RSA-3072 signature verification, trusting the public keys embedded in the *currently running* app's signature block. No eFuses are burned and nothing is irreversible — serial recovery stays available while the update path is developed and field-proven, which is exactly the guarantee Phase 7 needs before it disables serial forever. The signing format is identical to secure boot's: when Phase 6 burns the key digests, the same keys and the same OTA code carry over unchanged — the eFuse burn just upgrades update-time verification to boot-time enforcement.

**Scope of the guarantee:** until Phase 6, signature checking protects the *SD update path only* — an attacker with serial access can still flash arbitrary firmware (the status quo today, nothing regresses). See [Cross-Phase Security Dependencies](#cross-phase-security-dependencies).

#### 4a. Partition table redesign ✅ (superseded by Phase 3 migration)
- Factory + dual OTA layout was implemented first; the Phase 3 migration replaces it with the OTA-only target layout (see Partition Table section above) for anti-rollback compatibility
- `otadata` partition for OTA slot tracking; with factory gone, the known-good fallback is the previous OTA slot (rollback confirm required — see 4c)
- App partitions 64KB-aligned, offsets contiguous, total fits 16MB flash

#### 4b. Signing keys + signed-update build
- The signing-key ceremony moves up from the secure-boot phase: generate all three RSA-3072 keys (`espsecure generate-signing-key --version 2 --scheme rsa3072`) with offline, encrypted, redundant backups — these same keys become the Phase 6 eFuse digests, so full key-ceremony rigor applies now, not later.
- **Signing policy: key0 only.** Every release is signed with key0; key1/key2 stay sealed offline backups, never entering the signing workflow — their value is being clean if key0 leaks. If key0 is lost or compromised before Phase 6, rotation needs a **dual-signed transition release** (`espsecure sign-data --append-signatures`, key0 + key1) so the running-app trust anchor learns the new key; once Phase 6 burns all three digests, eFuse anchors every key and transition releases become unnecessary (see secure-boot.md §6).
- **Trust anchor / bootstrap:** without secure boot, the OTA path trusts the public keys embedded in the *running* app's signature blocks — an unsigned app can verify nothing. The first SD-update-capable release must therefore itself be signed and delivered over serial; SD updates verify from then on.
- Build config: `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y` — app images carry a signature block, verification happens on update only; no bootloader or eFuse change.
- `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` — required for the self-test/confirm safety net (4c step 5).
- eFuse anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`) is deferred to Phase 6; until then the downgrade check is enforced in software by the pre-flight validation (4c).
- Release images signed offline with the current primary key: `espsecure sign-data --version 2 --keyfile <key> firmware.bin`; add a `just` signing recipe.

#### 4c. SD card firmware update page
- Settings → Firmware Update → browse SD card for signed `.bin` files
- **Pre-flight validation, streamed from the SD file before any flash write** — a bad image is rejected with a precise error before `esp_ota_begin()` erases the OTA slot:
  1. Image header: magic byte, `chip_id` == ESP32-P4
  2. `esp_app_desc_t` (file offset 32): magic word; `project_name` matches the running app; `version` shown in the confirm dialog ("Update 0.0.13 → 0.1.0?"); `secure_version` not lower than the running app's (software anti-rollback until Phase 6)
  3. Full signature check: SHA-256 over the image portion, verify the appended signature sector with `esp_secure_boot_verify_sbv2_signature_block()`, and require the signer's key digest to match `esp_secure_boot_get_signature_blocks_for_running_app()`
- Update flow using ESP-IDF OTA API (`esp_ota_ops.h`):
  1. `esp_ota_begin()` — allocate OTA slot
  2. `esp_ota_write()` — stream firmware from SD card in chunks
  3. `esp_ota_end()` — re-verifies the signature on the flash copy (defense in depth; from Phase 6 on, also what the bootloader enforces at every boot)
  4. Success → `esp_ota_set_boot_partition()` → reboot
  5. New image self-tests and calls `esp_ota_mark_app_valid_cancel_rollback()` — without the confirm, the bootloader rolls back to the previous slot. With no factory partition, this rollback **is** the safety net, so the confirm step is mandatory, not optional.
  6. Failure at any step → stay on current firmware, show error
- Layer split per the architecture rules: `core/fw_update.c` (UI-free pre-flight validation + OTA streaming, callback-driven progress), a settings page wires it to the storage browser.

#### 4d. Validation
- Test update cycle: install v1 → update to v2 via SD → verify v2 running
- Test rollback: install bad firmware → verify device stays on previous slot
- Test rollback confirm: power-cycle a freshly updated device *before* it calls `esp_ota_mark_app_valid_cancel_rollback()` → verify it returns to the previous slot
- Test downgrade rejection: older `secure_version` → rejected in pre-flight, OTA slot untouched
- Test unsigned, wrong-key, and corrupted images → rejected in pre-flight, OTA slot untouched
- **Re-run this entire suite after Phase 6 (secure boot + eFuse anti-rollback) — all tests must pass again before Phase 7 release lockdown**

### Phase 5 — Flash Encryption (development mode) + FE Key Provisioning

**Profile B only; serial-provisioned.** Precedes secure boot (Phase 6) so the flash-encryption key is read-protected before `RD_DIS` locks. Flash encryption runs in **development mode** here — serial recovery stays available; the irreversible serial-disable is deferred to Phase 7. See [Enablement Mechanics & Deployment Profiles](#enablement-mechanics--deployment-profiles).

**Irreversible eFuse commitment — practice on a dev board first.**

#### 5a. Flash-encryption key provisioning
- Provision the **flash-encryption XTS key**: preferably via the ESP32-P4 **Key Manager** (`CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE_KEY_MGR`), keeping XTS-AES-256 with the key outside the shared blocks; fallback is **XTS-AES-128** in eFuse KEY3. Decide and validate before committing.
- KEY4 (NVS, Phase 3) and KEY5 (anti-phishing, Phase 2) are already burned.
- **Key Manager caveats to validate on the dev board:** the KM key is device-internal (HUK-derived) — the host can never learn it, so `esptool`-style pre-encrypted flashing does not exist with a KM key; confirm what development-mode serial recovery actually looks like in practice. Also check whether the KM path removes the `RD_DIS` ordering constraint entirely (the key never occupies an eFuse block that needs read-protection) — if so, a later Profile A → B upgrade (flash encryption *after* secure boot) may still be possible. Document the result either way.

#### 5b. Enable flash encryption (development mode)
- `CONFIG_SECURE_FLASH_ENC_ENABLED` with **XTS-AES-256**; key size / source per 5a.
- **Not an on-device toggle**: flash an FE-built, signed bootloader over serial; the bootloader self-encrypts flash (bootloader + app + `encrypted` partitions) *in place* on first boot (~1 min). **Do not interrupt power** — a partial pass corrupts flash.
- Development mode retains serial fallback for re-flashing/recovery.
- PSRAM encryption is enabled automatically — protects runtime key material in external RAM.
- The `storage` (SPIFFS) partition stays **plaintext**: SPIFFS does not support flash encryption, so the first-boot pass skips it (no `encrypted` flag). Mnemonics there are always KEF envelopes, so nothing key-critical depends on this — see [Cross-Phase Security Dependencies](#cross-phase-security-dependencies) and [Accepted Residual Risks](#accepted-residual-risks).
- Verify encrypted flash contents are unreadable via physical extraction.

### Phase 6 — Secure Boot

**Irreversible eFuse commitment — practice on a dev board first.** All read-protected keys (KEY4, KEY5, and the flash-encryption key) were burned in Phases 2–5, so it is safe for secure boot to write-protect `RD_DIS` here. For the full mechanics, key ceremony, rotation, and on-device lockdown flow, see [secure-boot.md](secure-boot.md).

#### 6a. Key management
- The three RSA-3072 signing keys already exist and are in active use — generated with full ceremony in Phase 4b, releases signed with the primary since then
- Burn digests into KEY0 (primary), KEY1 (rotation #1), and KEY2 (rotation #2)
- Sign the **bootloader with all three keys** (it is frozen at flash time and must survive rotations); the app is signed with the current primary key
- Document eFuse programming workflow and recovery procedures

#### 6b. Build system integration
- `sdkconfig.secure` overlay with secure boot + anti-rollback config (`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y`) — replaces the Phase 4 signed-on-update-only config
- Leave `CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE` **off** — revoking a good key on one failed verification is a bricking hazard for a wallet
- CI pipeline: build unsigned, developer signs images offline as part of release
- **Reproducible builds are a prerequisite for the first signed release**: with CI building unsigned and the developer signing offline, users can only verify that a signed release matches the source if they can reproduce the unsigned image bit-for-bit. Pin toolchain/IDF versions and document the build recipe.
- Keep development builds unsigned (separate sdkconfig)
- Anti-rollback counter enabled (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`) — firmware includes monotonic security version; supersedes the Phase 4 software downgrade check
- Note ESP-IDF 6.0 API renames: `esp_secure_boot_verify_signature_block()` removed (use `esp_secure_boot_verify_rsa_signature_block()`); `esp_flash_encryption_enabled()` deprecated (use `esp_efuse_is_flash_encryption_enabled()`)
- Re-run the Phase 4d validation suite under secure boot before Phase 7

### Phase 7 — Release Lockdown

**The point of no return — only after the Phase 4 SD update path has been re-validated under secure boot (Phase 6).** This is the single unrecoverable step; everything before it allowed serial recovery.

- Switch flash encryption from development to **release mode**: write-protects `SPI_BOOT_CRYPT_CNT` and burns `DIS_DOWNLOAD_MANUAL_ENCRYPT` — flashing plaintext firmware over serial is no longer possible.
- Restrict UART ROM download to **secure download mode** (or disable it), and confirm JTAG is locked down. (Secure download mode is already burned by the Phase 6 lockdown flow; Phase 7 optionally disables download mode entirely.)
- Runtime APIs exist for all of this — `esp_flash_encryption_set_release_mode()` and `esp_efuse_disable_rom_download_mode()` (disable download mode *before* release mode, per the API docs) — so Phase 7 can be an **on-device menu action** for Profile B devices, mirroring the Phase 6 lockdown flow.
- After this, the device is fully locked: firmware updates only via signed SD card OTA (Phase 4).
- Verify: unsigned/plaintext serial flash is rejected; SD OTA still works; a power-loss during an SD update still boots the previous slot.

### Phase 8 (Future) — TEE / World Controller

- Investigate ESP32-P4 World Controller / PMS maturity in ESP-IDF
- Goal: signing operations in World0 (secure), UI in World1 (non-secure)
- Most complex and least mature — watch Espressif's ESP-TEE progress
- Pragmatic measures (secure_memzero, PSRAM encryption, session-only keys) provide good coverage meanwhile
