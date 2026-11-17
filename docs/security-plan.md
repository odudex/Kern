# Kern Security Model & Implementation Plan

This is a research plan. It documents the hardening approaches Kern explores on the ESP32-P4 and the status of each. It is not a certification path: completing a phase does not make Kern suitable for real savings.

## Baseline

- **Air-gapped by design**: no radio on ESP32-P4, QR-only I/O
- **Session-only keys**: mnemonics and private keys live in internal SRAM only, wiped on unload, lock, power-off and reboot (see [0c](#0c-secrets-in-ram-))
- **libwally-core**: proven Bitcoin cryptographic primitives
- **Entropy validation**: Shannon entropy threshold for camera-based seed generation

## Threat Model

| Threat | Attack vector | Mitigation |
|--------|--------------|------------|
| Firmware tampering | Malicious flash via UART/JTAG | **Secure Boot + JTAG lockdown** |
| Flash readout | Physical extraction of flash chip | **Nothing secret is stored in plaintext: NVS encryption (PIN hash), KEF (mnemonics); the firmware is public. Flash encryption is not used ([Phase 5](#phase-5-flash-encryption-dropped))** |
| Evil maid / stolen device | Physical access while powered off | **PIN + encrypted storage** |
| Device swap / evil maid | Replace device with lookalike | **Anti-phishing words (eFuse HMAC)** |
| Evil maid tampering | "Evil maid" tamper device | **Anti-phishing words + secure boot** |
| Shoulder surfing/theft at rest | Backup QR codes or stored data | **KEF encrypted backups** |
| Firmware downgrade | Flash older vulnerable version | **Anti-rollback (eFuse counter)** |
| Firmware downgrade via SD | Load older vulnerable firmware via update | **Anti-rollback (eFuse counter)** |
| Updates after lockdown | Only signed images boot | **Air-gapped SD card updates; signed releases over USB** |
| RAM snooping via PSRAM | Probing external PSRAM bus | **Secrets allocated in internal SRAM (0c); working buffers in PSRAM are an accepted risk (see below)** |
| Cold boot / remanence | Reading RAM after power-off | **Secure memory wiping + session teardown (0c)** |
| PIN-counter rewind | Snapshot/restore of external flash to reset failure counter | **Residual risk: PIN entropy is the backstop (see below)** |
| Fault injection | Voltage/EM glitching of boot or PIN checks | **Residual risk: not a secure element (see below)** |

### Accepted Residual Risks

The ESP32-P4 is not a secure element, and Kern does not encrypt flash or PSRAM. These exposures remain and are accepted with mitigations rather than eliminated:

- **NVS replay (PIN-counter rewind).** XTS encryption provides confidentiality, not integrity or freshness. The flash is an external chip: an attacker who can rewrite it can snapshot the encrypted `nvs` partition, spend N−1 PIN attempts, restore the snapshot, and repeat, resetting the failure counter and exponential backoff indefinitely, even with NVS encryption and secure boot enabled. Wipe-after-N-failures and backoff therefore only hold against attackers who cannot rewrite flash. The backstop is PIN entropy: the device-bound PBKDF2 salt (eFuse KEY5) forces every guess through this specific chip, so a long PIN stays strong even against counter rewind.
- **Fault injection / glitching.** Voltage and EM glitching have a public history on earlier ESP32 generations; the ESP32-P4 has no proven resistance and no anti-glitch hardware guarantees. Mitigations that limit the payoff: mnemonics exist only in RAM (session-only) or KEF-encrypted at rest, and the PIN itself is never stored, only its PBKDF2 hash.
- **Plaintext flash.** A physical flash dump yields the firmware (public), the encrypted `nvs` partition, and the `storage` partition. Mnemonics in `storage` are always KEF envelopes, but descriptors saved unencrypted (`.txt`), file names and sizes, and KEF header metadata (version, iterations, user-chosen label) are readable. This leaks xpubs and wallet structure: a privacy exposure, not key material. Flash encryption would not have covered `storage` either (SPIFFS is incompatible with it).
- **Plaintext PSRAM.** Secrets are kept in internal SRAM (0c), but working buffers that can carry secret-bearing data (compression state, QR/cUR payloads, camera and display frames, including SeedQR display and scan moments) may sit in external PSRAM while the device is powered and unlocked. Reading them takes probing the PSRAM bus of a running, unlocked device. Session teardown wipes them.

## ESP32-P4 Security Hardware Summary

### Usable for Kern
- **Secure Boot v2**: **RSA-3072 (RSA-PSS)**, up to 3 key digest slots in eFuse. Kern burns all 3 (KEY0/1/2) to allow two key rotations. **ECDSA is not used**: ECDSA-based Secure Boot v2 is non-functional on ESP32-P4 silicon (chip errata; would require `CONFIG_SECURE_BOOT_INSECURE`). RSA-3072 is also the faster verifier here (~14.8 ms vs ~61.1 ms). See [secure-boot.md](secure-boot.md).
- **NVS Encryption**: HMAC-based key derivation from eFuse (no separate key partition needed)
- **RSA/MPI + Digital Signature peripherals**: hardware-accelerated RSA; used by Secure Boot v2 RSA-3072 verification at boot
- **HMAC peripheral**: computes HMAC-SHA256 using eFuse keys without exposing them to software; used for anti-phishing word derivation (`esp_hmac_calculate()` with `HMAC_KEY5` purpose) and NVS key derivation (KEY4)
- **AES/SHA hardware accelerators**: transparent via mbedTLS for AES and one-shot hashing. Not for iterated hashing: mbedTLS takes the shared SHA/AES crypto mutex, enables the bus clock and pulses the peripheral reset around every hash update crossing a block, roughly 6800 cycles of setup around 1150 cycles of work. PBKDF2 therefore drives the accelerator directly (`main/core/pbkdf2.c`), holding it across batches of iterations and reloading precomputed HMAC ipad/opad midstates: measured 12.2x on wave_4b, taking a 100k-iteration KEF or PIN derivation from 8.07 s to 0.66 s
- **TRNG**: hardware entropy source for random numbers generation (mix with additional sources)
- **Anti-rollback**: security version counter in eFuse
- **JTAG/UART lockdown**: automatic only when the *stock bootloader* enables the security features; Kern's on-device lockdown flow must burn the same eFuse set itself (JTAG-disable set, download-mode restriction; see [secure-boot.md §5a](secure-boot.md#5-user-scenarios))

### Available but not used
- **Flash Encryption** (XTS-AES, also encrypts PSRAM): dropped, see [Phase 5](#phase-5-flash-encryption-dropped).

### NOT usable for Bitcoin
- **ECDSA peripheral**: P-192/P-256 only, **secp256k1 not supported**. All Bitcoin signing uses software libsecp256k1 via libwally-core. (Separate from the ECDSA *secure-boot verification* defect noted above: that is a boot-ROM issue, this is about the signing curve.)
- **Digital Signature peripheral**: RSA-based, no Bitcoin application. (Still used indirectly: it is the RSA engine behind Secure Boot v2.)

### Future potential
- **World Controller / PMS**: two-world privilege separation (secure vs non-secure). ESP-IDF support for ESP32-P4 TEE still maturing. Could isolate signing operations from UI.

### eFuse Key Block Allocation

| Block | Purpose | Phase |
|-------|---------|-------|
| KEY0 (BLK4) | Secure Boot Digest 0 (primary) | Phase 6 |
| KEY1 (BLK5) | Secure Boot Digest 1 (rotation #1) | Phase 6 |
| KEY2 (BLK6) | Secure Boot Digest 2 (rotation #2) | Phase 6 |
| KEY3 (BLK7) | Unused | — |
| KEY4 (BLK8) | HMAC for NVS encryption (HMAC_UP) | Phase 3 |
| KEY5 (BLK9) | HMAC for anti-phishing words (HMAC_UP) | Phase 2 |

Kern spends **three** blocks on secure-boot digests (KEY0–KEY2) so it can rotate a compromised key twice instead of once. Because all three digest *slots* are populated, no free slot remains for an attacker to inject a rogue signing key. Both HMAC keys (KEY4, KEY5) use the `HMAC_UP` purpose: software can request HMAC computations but never reads the raw key material. KEY3 was reserved for the flash-encryption key and stays empty; after lockdown only signed firmware runs and secure download mode gives no eFuse access, so nothing can burn it.

## Partition Table

### Current layout (pre-Phase 3)

The live layout in [`partitions.csv`](../partitions.csv) (`CONFIG_PARTITION_TABLE_CUSTOM=y`), factory + dual OTA:

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

### Target layout (Phase 3 migration; since revised, see the bootloader-headroom revision below)

Phase 3 replaces the layout above with an OTA-only table:

```
# Name    Type  SubType  Offset     Size       (Human)
nvs       data  nvs      0x9000     0x15000    (84K)
otadata   data  ota      0x1E000    0x2000     (8K)
ota_0     app   ota_0    0x20000    0x600000   (6M)
ota_1     app   ota_1    0x620000   0x600000   (6M)
storage   data  spiffs   0xC20000   0x3E0000   (~3.9M)
```

**Why factory is dropped**: ESP-IDF's anti-rollback (Phase 6) assumes an OTA-only table; `bootloader_utility.c` states it outright: "When CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is enabled factory partition should not be in partition table, only two ota_app are there." A factory image is frozen at flash time with security version 0, so the first eFuse counter increment would make it unbootable: the "known-good fallback" guarantee silently dies. The fallback role moves to the *previous OTA slot*: the SD update flow must self-test and call `esp_ota_mark_app_valid_cancel_rollback()`, otherwise the bootloader rolls back (see Phase 4). With empty `otadata`, the bootloader boots `ota_0` directly, which is where serial flashing writes the app.

**Why the migration happens at Phase 3**: a partition table can only be rewritten over serial (OTA never touches it) and it should be treated as frozen once secure boot (Phase 6) is on: apps built for one layout cannot run on another, and SD updates can never move it. Phase 3 already forces the one disruptive event for alpha testers (NVS wipe + fresh PIN + KEY4 burn), so the table migration rides the same re-flash instead of adding a second one.

**Layout choices**:

- `ota_0` inherits the old `factory` offset (0x20000), so serial flashing lands the app at the same address as before.
- `storage` keeps its exact offset and size, so KEF-encrypted mnemonics/descriptors already saved to SPIFFS survive the migration untouched.
- App slots grow 4MB → 6MB. The app is ~1.7MB today, but the table is permanent after Phase 6, so the headroom (fonts, languages, assets) is free insurance; the space comes from the dropped factory partition.
- NVS grows 24KB → 84KB, filling the space up to `ota_0` exactly. More pages improve wear-leveling for the failure-counter write on every PIN attempt. Note that old NVS content **survives** the resize: NVS pages are self-contained 4K units, so the old pages parse fine inside the larger partition, and flashing never writes the `nvs` region. A pre-existing plaintext PIN is therefore still present after the update, handled by the firmware-side migration in 3a.
- `phy_init` is dropped: the ESP32-P4 has no radio, no `CONFIG_ESP_PHY*` option is set, and the partition was never read.

### Bootloader-headroom revision (July 2026): current layout

The Phase 3 layout kept the partition table at the default offset 0x8000, capping the bootloader at 24KB. The plain bootloader had grown to within 320 bytes of that cap, and the Phase 6 secure-boot bootloader (~44KB) does not fit. The offset was moved to **0x10000** before any device was locked:

```
# Name    Type  SubType  Offset     Size       (Human)
nvs       data  nvs      0x11000    0xD000     (52K)
otadata   data  ota      0x1E000    0x2000     (8K)
ota_0     app   ota_0    0x20000    0x600000   (6M)
ota_1     app   ota_1    0x620000   0x600000   (6M)
storage   data  spiffs   0xC20000   0x3E0000   (~3.9M)
```

- `CONFIG_PARTITION_TABLE_OFFSET=0x10000` (in `sdkconfig.defaults`): the bootloader slot grows 24KB → 56KB.
- The shift is absorbed entirely by `nvs` (moved to 0x11000, shrunk 84KB → 52KB, still ample for the PIN hash and settings); `otadata`, both app slots, and `storage` keep their exact offsets, so OTA app images and SPIFFS contents survive.
- Cost for already-flashed devices: one serial re-flash plus an NVS wipe (PIN/settings re-setup); apps and `storage` are untouched.
- This is a single global move for **all boards**: `CONFIG_PARTITION_TABLE_OFFSET` is compiled into the app, so an app built for one offset cannot run on a device whose table sits elsewhere, and a mixed fleet would invite bricking mismatches through the SD update path.

## Phase Ordering Rationale

The phases are ordered so that the **roadmap order is also the safe eFuse burn order**. The read-protected keys (KEY5, KEY4) are burned in Phases 2 and 3, *before* secure boot (Phase 6) write-protects `RD_DIS`; Phase 4 burns nothing. Phases 5 and 7 were dropped (see [Phase 5](#phase-5-flash-encryption-dropped)); the numbers are kept so existing references stay valid.

1. **Phase 2 (PIN + anti-phishing)**: pure software except one eFuse burn: KEY5 (anti-phishing HMAC), read-protected at burn time, provisioned during first PIN setup.

2. **Phase 3 (NVS encryption)**: coupled to PIN setup, on-device. Burns KEY4 and encrypts the `nvs` partition so the PIN hash is protected at rest. Phase 3 also carried the one-time **partition-table migration** (factory dropped for anti-rollback, see [Partition Table](#partition-table)).

3. **Phase 4 (SD updates) before any irreversible step**: signature verification does **not** require secure boot: `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT` makes the OTA path verify Secure Boot v2 RSA-3072 signatures against the public keys embedded in the running app: pure software, no eFuse burns, fully reversible. Implementing it first field-proves the main post-lockdown update channel while unrestricted serial flashing still exists, and pulls the signing-key ceremony forward (the same keys become the Phase 6 eFuse digests).

4. **Phase 6 (secure boot) last**: it upgrades the Phase 4 signature check from update-time-only to boot-time enforcement, disables JTAG, restricts the ROM to secure download mode, and can arm eFuse anti-rollback. It is the final lockdown step. A locked device still updates over SD and can be reflashed with a signed release over USB.

### Cross-Phase Security Dependencies

Some features only reach their full security guarantee when combined with later phases. Until those phases are complete, certain attack vectors remain open:

| Feature (Phase) | Depends on | Gap until dependency is met |
|-----------------|------------|----------------------------|
| Anti-phishing words (2) | Secure Boot (6) | Anti-phishing detects a *different chip* (eFuse mismatch), but an attacker who controls the firmware can bypass the check entirely: malicious firmware on the *same chip* can fake the words or exfiltrate the PIN. Secure boot closes this by ensuring only signed firmware runs. |
| PIN hash in NVS (2) | NVS Encryption (3) | The PBKDF2 hash is stored in NVS. Until NVS encryption, physical flash extraction exposes it to offline brute-force (limited by 100k PBKDF2 iterations and the device-bound salt, but still a risk for weak PINs). NVS encryption removes this vector and, being coupled to PIN setup, is the default for any PIN user. |
| NVS encryption (3) | Secure Boot (6) | `HMAC_UP` computations are software-invokable: until secure boot, attacker firmware on the *same chip* can drive the HMAC peripheral to derive the NVS keys and decrypt a dumped `nvs` partition (PIN hash included). Without the chip, the keys stay out of reach either way. |
| Wipe-after-N-failures (2) | Secure Boot (6) | Custom firmware could reset the failure counter or skip the wipe check. Secure boot prevents running unauthorized firmware. |
| SD card OTA (4) | Secure Boot (6) | The OTA path already verifies Secure Boot v2 RSA-3072 signatures via `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`, trusting the public keys embedded in the running app, but nothing verifies firmware at *boot*, so an attacker with serial access can still flash unsigned firmware directly. Secure boot closes the serial path and upgrades the software downgrade check to the eFuse anti-rollback counter. |

**In summary**: Phase 2 provides strong *usability-layer* security (PIN gating, anti-phishing UX, auto-wipe), and Phase 3 encrypts the PIN hash at rest by default, but tamper-detection guarantees are only as strong as firmware integrity. Secure boot (Phase 6) is what turns anti-phishing from "detects accidental device swaps" into "cryptographically proves device authenticity". A flash dump cloned onto another board already fails the anti-phishing check, since the words come from that chip's KEY5.

## Enablement Mechanics

There is one deployment path, and every step of it runs on the device. The only tool involved is the USB install that puts Kern on the device in the first place.

| Feature | How it activates | Brick risk |
|---------|------------------|------------|
| NVS Encryption (3) | **On-device, coupled to PIN setup**: app burns KEY4, then `nvs_flash_secure_init()`; the new PIN hash is written into encrypted NVS | Low: worst case NVS re-init → PIN re-setup. Device still boots |
| SD card updates (4) | **Build config only**: signed-app verification on update (`SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`); no eFuse touched | Low: a failed update stays on the current slot; rollback confirm guards a broken image |
| Secure Boot (6) | **On-device menu**: app burns the three digests, the hardening set (JTAG disable, `DIS_DIRECT_BOOT`, secure download mode), `SECURE_BOOT_EN`, and write-protects `RD_DIS`. Needs the frozen bootloader (Phase 6d) on flash, which only a USB install of a lockable release puts there | Only if lockdown runs while an app or bootloader that is unsigned (or signed with other keys) is on flash; the menu verifies both against the embedded keys first |

### The hard constraint: read-protected keys before secure boot

Enabling secure boot **write-protects `RD_DIS`** (so the secure-boot digests stay readable for the ROM to verify). After that, read-protection can no longer be set on any key block. A key left software-readable defeats its own purpose.

**Rule: KEY5 (anti-phishing HMAC, Phase 2) and KEY4 (NVS HMAC, Phase 3) are burned and read-protected before `SECURE_BOOT_EN` is set.** Both happen during PIN setup, and the Secure Boot menu refuses to proceed unless a PIN is configured and both keys are sealed.

## Implementation Phases

### Phase 0: Foundations ✅

#### 0a. Secure memory primitives ✅
- `secure_memzero()` that can't be optimized away (`volatile` barrier)
- `secure_mem.h`: `secure_memzero()`, `secure_memcmp()` (constant-time comparison)
- Audited paths in `key.c` and `wallet.c` where seeds/keys exist on stack or heap

#### 0b. AES encryption utility ✅
- `crypto_utils.c` wrapping ESP-IDF's mbedTLS AES (uses hardware accelerator transparently)
- Functions: `aes_encrypt_buffer()`, `aes_decrypt_buffer()`, `pbkdf2_derive_key()`
- Building block for KEF, PIN-protected storage, etc.

#### 0c. Secrets in RAM ✅
Rules for any code that touches mnemonics, private keys, passphrases, PINs or KEF passwords (mechanics in `components/secure_memory/README.md`):
- **Placement.** Secret objects are allocated with `kern_secret_alloc()`: internal SRAM only, no PSRAM fallback, and allocation failure is an error shown to the user, never a silent downgrade. libwally calls that produce such objects go through the `kern_` adapters in `components/libwally-core/kern_wally.h`, never the raw allocating APIs. Public data (PSBTs, descriptors, images) stays off the secret allocator. The default heap is internal-first below 16 KiB (`SPIRAM_MALLOC_ALWAYSINTERNAL`), so small public allocations land in internal RAM too and can drain the 32 KiB internal reserve: the reserve does not protect secrets. A parsed PSBT is thousands of small blocks, about 2-4 times its serialized size, so parsing and cloning one runs in a scope that prefers PSRAM (`kern_psbt_*` adapters).
- **Release.** Every heap free and realloc is wrapped to zero the whole block, padding included, and write PSRAM ranges back before release; realloc copies then wipes rather than resizing in place. Stack and static secrets, and buffers whose apparent length changed (tokenised strings), are still wiped explicitly with the original length.
- **Ownership.** A page or flow that holds a secret copy registers its destructor with `session_cleanup_register()` before allocating and unregisters at the top of its idempotent destroy. `session_lock_now()` (timeout, power-off, reboot) joins workers, runs those destructors child-first, unloads the wallet, clears the screen and scrubs draw and panel buffers before rendering the lock face. `wallet_unload()` alone is not a session teardown.
- **Producers stop first.** Camera and display buffers are wiped only after their DMA writers stop. Workers suspend on completion and are joined and deleted by the UI thread so their stacks are wiped synchronously, never left to the idle task.
- **Inputs.** Secret textareas are cleared with `ui_secure_clear_textarea()`; setting an empty string alone leaves LVGL copies behind.

Accepted: a live secret can be observed while in use, and compression state, cUR buffers, camera and display pixels (SeedQR display and scan moments) and NVS cipher contexts keep default placement, which may be PSRAM. Cleanup shortens retention; it does not protect live data.

Accepted until libwally signs from a caller's key: `wally_psbt_sign` copies each input's signing key into a default-heap `ext_key` (wiped on release). Wrapping the call in the secret allocator would place the whole PSBT in internal RAM and make large PSBTs fail.

Open: validate PSRAM write-back and power-off remanence on hardware; move zlib, cUR and NVS cipher state to internal RAM if capacity allows. The release policy's time cost is settled (wipes run at 99 MiB/s in PSRAM and 270 MiB/s internally; a scanner close or session lock spends under 100 ms in it); the constraint is internal heap headroom, which copy-on-realloc lowers by about 60 KiB, so check the internal heap low-water mark on device before adding internal-only allocations.

### Phase 1: KEF Encryption ✅

- `kef.c/h` in `main/core/`: 12 encryption versions, AES-256 + PBKDF2
- QR scanner pipeline: detect KEF-encrypted QR, prompt for password, decrypt
- QR export: encrypted mnemonic/descriptor QRs
- Storage: save/load encrypted mnemonics and descriptors to SPIFFS and SD card

### Phase 2: Split PIN with Anti-Phishing Words ✅

**Goal**: PIN authentication with tamper detection. User can verify they're interacting with their own device, not a replacement or clone.

**Mechanism**: The ESP32-P4 HMAC peripheral computes HMAC-SHA256 using an eFuse key that software can never read directly (`HMAC_UP` purpose). Each physical chip produces unique outputs: a cloned flash on a different chip produces different words.

#### 2a. PIN entry UI and basic authentication ✅
- Text input page with virtual keyboard and eye toggle (`pages/pin/pin_page.c`)
- PIN: 6-16 characters, alphanumeric + symbols
- PBKDF2-HMAC-SHA256 (100k iterations) hash stored in NVS
  - Salt derived from `HMAC(KEY5, SHA256("C-Krux-PIN-salt-v1"))`, a device-bound salt without exposing eFuse key
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
- No manufacturing step required: each device self-provisions during first PIN setup
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
- Enforcement is firmware/flash-level only: an attacker who can rewrite the external flash can rewind the counter by restoring an NVS snapshot (see [Accepted Residual Risks](#accepted-residual-risks)); PIN entropy is the ultimate backstop

**What anti-phishing detects today**: device swap (different eFuse → different words), flash chip cloned to new board. **What it does NOT yet detect**: firmware tampering on the same chip; malicious firmware could fake the anti-phishing display. This gap closes with secure boot (Phase 6), which ensures only signed firmware runs. See "Cross-Phase Security Dependencies" above.

### Phase 3: NVS Encryption + Partition Migration (coupled to PIN setup)

**On-device, no serial tools.** NVS encryption protects the PIN hash (and settings) at rest. Its keys derive from an eFuse HMAC key (KEY4), not from anything in flash, so a flash dump yields only ciphertext. Its only ordering constraint is that KEY4 must be burned before secure boot (Phase 6) write-protects `RD_DIS`, which is naturally satisfied since this phase runs during PIN setup (right after Phase 2).

**Why couple it to the PIN:** enabling NVS encryption erases and re-initializes the `nvs` partition, which would wipe an existing PIN hash. Doing it *as part of setting the PIN* removes that chicken-and-egg: KEY4 is burned and NVS is re-initialized encrypted *before* the new PIN hash is written, so the hash lands directly in encrypted storage. It also makes at-rest protection the **default** for any PIN user (rather than an optional late step), and mirrors the anti-phishing self-provisioning (KEY5, Phase 2b).

#### 3a. Partition-table migration (rides the Phase 3 firmware update)

The Phase 3 rollout replaces the partition table with the OTA-only layout (see [Partition Table](#partition-table)): factory and `phy_init` dropped, app slots grown to 6MB, NVS grown to 84KB, `storage` untouched. Alpha testers already update over serial (no SD OTA until Phase 4), so the migration adds no extra step; the NVS-encryption *feature* itself stays tools-free.

Migration flow for alpha testers:

1. Warn up front: **settings and PIN are wiped** during the migration (NVS is erased and re-initialized encrypted). SPIFFS-stored encrypted mnemonics/descriptors survive (`storage` offset/size unchanged), but confirm QR/SD backups exist anyway.
2. One serial `just flash`: writes bootloader, new partition table, initial `otadata`, and the app to `ota_0`. Flashing does **not** erase NVS: the old plaintext pages remain valid in the resized partition (see Partition Table above).
3. The firmware closes the gap: if a PIN is configured while NVS is still plaintext, the first successful unlock triggers a one-time prompt that routes into fresh PIN setup, which runs the provisioning below. Declining removes the PIN (a stored PIN implies encrypted NVS). Either way, no device keeps a plaintext PIN hash; there is no plaintext-NVS long tail.

**PIN remains optional.** The forced re-setup above only applies to migrated users who *had* a PIN: they must set one up again (or decline and lose it); it does not make PIN mandatory. A user without a PIN simply runs plaintext NVS holding nothing sensitive (settings only, no hash), same as a fresh no-PIN device; KEY4 is never burned without the consent dialog in 3b. The boot-time NVS branch therefore keys off **KEY4 presence, not PIN presence**; this also covers the PIN-set-then-disabled state, where NVS stays encrypted (3d) with no PIN hash in it.

#### 3b. PIN-triggered provisioning
- Setting a PIN (first setup, PIN change, or disable→re-enable) runs, after an explicit warning that this is a **permanent OTP write and clears current NVS settings**:
  1. Burn **KEY4** (256-bit TRNG key, purpose `HMAC_UP`, read- and write-protected), idempotent, mirroring `pin_efuse_provision()` for KEY5.
  2. Encrypt and re-initialize the `nvs` partition (`nvs_flash_secure_init()`, HMAC scheme).
  3. Write the new PIN hash into the now-encrypted NVS.
- The partition migration (3a) wipes NVS on every device, so all alpha testers go through this fresh setup; the PIN-change/re-enable trigger remains as the code path for any later device that somehow still has a plaintext NVS.
- **Implementation note:** provisioning runs **in session**, not via burn-then-reboot: after the consent dialog, the firmware burns KEY4, closes the only two NVS handle owners (`pin`, `settings`), then `nvs_flash_deinit()` → erase → encrypted re-init → reopens the handles, and PIN setup continues straight into writing the hash. A reboot-based flow was rejected because nothing survives the NVS wipe to tell the firmware to *resume* PIN setup; the user would have to redo the whole flow. Crash-safety comes from the boot path instead: if power is cut after the burn but before the migration completes, boot sees KEY4 present, fails to secure-init the plaintext partition, erases it, and lands on empty encrypted NVS.
- **Guard the stock auto-burn path:** `nvs_sec_provider`'s HMAC key generation (`generate_keys_hmac()`) burns the eFuse key itself whenever the block is empty, so a default `CONFIG_NVS_ENCRYPTION` init would burn KEY4 with no user consent. NVS init must be explicit and branch on KEY4 presence: KEY4 absent → plain `nvs_flash_init()` and never touch the keygen/secure path until the consent dialog; KEY4 present → `nvs_flash_secure_init()`.

#### 3c. Mechanism (HMAC scheme, no key partition)
- The XTS-AES-256 keys that encrypt NVS (a 512-bit key set) are derived at runtime from the 256-bit KEY4 (`ESP_EFUSE_KEY_PURPOSE_HMAC_UP`). Software never reads the raw key: the HMAC peripheral derives the NVS keys on demand. No `nvs_keys` partition is needed (unlike the flash-encryption-based NVS scheme, which requires a `data`/`nvs_keys` partition).
- Configuration:

```
CONFIG_NVS_ENCRYPTION=y
CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC=y   # HMAC scheme (not the flash-encryption scheme)
CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=4        # BLOCK_KEY4
```

- Registration of the HMAC scheme is automatic at startup (`nvs_sec_provider`'s `ESP_SYSTEM_INIT_FN`, harmless, burns nothing); the boot path is `nvs_flash_read_security_cfg_v2(nvs_flash_get_default_security_scheme(), &cfg)` → `nvs_flash_secure_init(&cfg)`, implemented in `core/nvs_secure.c`.

#### 3d. Notes
- **All-or-nothing:** unlike anti-phishing (which falls back to a deterministic salt if the HMAC peripheral is unavailable), NVS encryption has no plaintext fallback: once KEY4 is burned and NVS is encrypted, that is permanent. The same rule applies at setup time: if provisioning fails or KEY4 is unusable, PIN setup is aborted without writing a hash; a PIN hash is never stored in plaintext NVS.
- Anti-phishing words are unaffected (KEY5 is permanent and independent of KEY4).

### Phase 4: Air-Gapped SD Card Updates

**Deliberately before secure boot.** ESP-IDF's *signed-app verification without secure boot* (`CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT` + `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`, RSA scheme) makes the OTA path perform full Secure Boot v2 RSA-3072 signature verification, trusting the public keys embedded in the *currently running* app's signature block. No eFuses are burned and nothing is irreversible: unrestricted serial flashing stays available while the update path is developed and field-proven. The signing format is identical to secure boot's: when Phase 6 burns the key digests, the same keys and the same OTA code carry over unchanged; the eFuse burn just upgrades update-time verification to boot-time enforcement.

**Scope of the guarantee:** until Phase 6, signature checking protects the *SD update path only*; an attacker with serial access can still flash arbitrary firmware (the status quo today, nothing regresses). See [Cross-Phase Security Dependencies](#cross-phase-security-dependencies).

#### 4a. Partition table redesign ✅ (superseded by Phase 3 migration)
- Factory + dual OTA layout was implemented first; the Phase 3 migration replaces it with the OTA-only target layout (see Partition Table section above) for anti-rollback compatibility
- `otadata` partition for OTA slot tracking; with factory gone, the known-good fallback is the previous OTA slot (rollback confirm required, see 4c)
- App partitions 64KB-aligned, offsets contiguous, total fits 16MB flash

#### 4b. Signing keys + signed-update build
- The signing-key ceremony moves up from the secure-boot phase: generate all three RSA-3072 keys (`espsecure generate-signing-key --version 2 --scheme rsa3072`) with offline, encrypted, redundant backups. These same keys become the Phase 6 eFuse digests, so full key-ceremony rigor applies now, not later.
- **Signing policy: key0 only.** Every release is signed with key0; key1/key2 stay sealed offline backups, never entering the signing workflow; their value is being clean if key0 leaks. If key0 is lost or compromised before Phase 6, rotation needs a **dual-signed transition release** (`espsecure sign-data --append-signatures`, key0 + key1) so the running-app trust anchor learns the new key; once Phase 6 burns all three digests, eFuse anchors every key and transition releases become unnecessary (see secure-boot.md §6).
- **Trust anchor / bootstrap:** without secure boot, the OTA path trusts the public keys embedded in the *running* app's signature blocks, and an unsigned app can verify nothing. The first SD-update-capable release must therefore itself be signed and delivered over serial; SD updates verify from then on.
- Build config: `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y`: app images carry a signature block, verification happens on update only; no bootloader or eFuse change.
- `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`: required for the self-test/confirm safety net (4c step 5).
- eFuse anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`) is deferred to Phase 6; until then the downgrade check is enforced in software by the pre-flight validation (4c).
- Release images signed offline with the current primary key: `espsecure sign-data --version 2 --keyfile <key> firmware.bin`; add a `just` signing recipe.

#### 4c. SD card firmware update page
- Settings → Firmware Update → browse SD card for signed `.bin` files
- **Pre-flight validation, streamed from the SD file before any flash write**: a bad image is rejected with a precise error before `esp_ota_begin()` erases the OTA slot:
  1. Image header: magic byte, `chip_id` == ESP32-P4
  2. `esp_app_desc_t` (file offset 32): magic word; `project_name` matches the running app; `version` shown in the confirm dialog ("Update 0.0.13 → 0.1.0?"); `secure_version` not lower than the running app's (software anti-rollback until Phase 6)
  3. Full signature check: SHA-256 over the image portion, verify the appended signature sector with `esp_secure_boot_verify_sbv2_signature_block()`, and require the signer's key digest to match `esp_secure_boot_get_signature_blocks_for_running_app()`
- Update flow using ESP-IDF OTA API (`esp_ota_ops.h`):
  1. `esp_ota_begin()`: allocate OTA slot
  2. `esp_ota_write()`: stream firmware from SD card in chunks
  3. `esp_ota_end()`: re-verifies the signature on the flash copy (defense in depth; from Phase 6 on, also what the bootloader enforces at every boot)
  4. Success → `esp_ota_set_boot_partition()` → reboot
  5. New image self-tests and calls `esp_ota_mark_app_valid_cancel_rollback()`: without the confirm, the bootloader rolls back to the previous slot. With no factory partition, this rollback **is** the safety net, so the confirm step is mandatory, not optional.
  6. Failure at any step → stay on current firmware, show error
- Layer split per the architecture rules: `core/fw_update.c` (UI-free pre-flight validation + OTA streaming, callback-driven progress), a settings page wires it to the storage browser.

#### 4d. Validation
- Test update cycle: install v1 → update to v2 via SD → verify v2 running
- Test rollback: install bad firmware → verify device stays on previous slot
- Test rollback confirm: power-cycle a freshly updated device *before* it calls `esp_ota_mark_app_valid_cancel_rollback()` → verify it returns to the previous slot
- Test downgrade rejection: older `secure_version` → rejected in pre-flight, OTA slot untouched
- Test unsigned, wrong-key, and corrupted images → rejected in pre-flight, OTA slot untouched
- **Re-run this entire suite on a locked device (Phase 6): all tests must pass again before the first lockable release**

### Phase 5: Flash Encryption (dropped)

**Dropped November 2026. Kern does not use flash encryption, and no other phase depends on it.**

What it was: XTS-AES encryption of the bootloader and app partitions, and of PSRAM, with a key generated inside the chip. It had to be enabled over serial, before secure boot.

Why it was dropped:

- **It protects little here.** It never covers `nvs` or `storage`, which have their own encryption (NVS encryption, KEF). The firmware is public. A flash clone on another chip already fails the anti-phishing check. Firmware integrity is secure boot's job. The one real gain is PSRAM encryption, and the camera and display buffers would have to be exempted from it, leaving SeedQR frames in plaintext anyway.
- **An encrypted ESP32-P4 cannot be reflashed over USB.** Download-mode encryption uses a per-session key instead of the eFuse key and writes ciphertext the ROM cannot decrypt (measured on a wave_4b, rev v1.0, August 2026; ESP-IDF documents the command as working). The only recovery is a once-per-chip `SPI_BOOT_CRYPT_CNT` disable.
- **It takes a secure-boot key slot.** The bootloader puts its key in the first free block, KEY0, leaving two digests and one rotation. The alternative is generating the key off-chip. The Key Manager path that avoids both needs chip revision v3.
- **It does not run cleanly with the display and camera.** DMA peripherals need an unencrypted PSRAM carve-out (`CONFIG_SPIRAM_ENC_EXEMPT`, IDF 6.1). The camera side needs esp_video 2.4, which Kern cannot use, and the DSI framebuffer has no hook for it at all.
- **It doubles the release work.** It needs its own frozen bootloaders (Phase 6d), serial provisioning with a power-loss brick window, and a second device profile to test and support.

What dropping it costs: working buffers in PSRAM stay plaintext while the device is powered and unlocked (see [Accepted Residual Risks](#accepted-residual-risks)). The choice is final for a locked device: flash encryption cannot be enabled after secure boot.

What is left over:

- The `feat/flash-encryption-61` branch (overlay and recipes) is kept for reference and not maintained.
- The wave_4b used for the tests has a flash-encryption key in KEY0 and its one disable spent. The Secure Boot menu will refuse it (KEY0 is taken), so the lockdown tests need another board.
- The 0x10000 partition-table offset, chosen partly for the larger flash-encryption bootloader, stays.

### Phase 6: Secure Boot

**Irreversible eFuse commitment: practice on a dev board first.** The read-protected keys (KEY4, KEY5) were burned during PIN setup (Phases 2–3), so it is safe for secure boot to write-protect `RD_DIS` here. This is the last lockdown step in the plan. For the full mechanics, key ceremony, rotation, and on-device lockdown flow, see [secure-boot.md](secure-boot.md).

#### 6a. Key management
- The three RSA-3072 signing keys already exist and are in active use, generated with full ceremony in Phase 4b, releases signed with the primary since then
- Burn digests into KEY0 (primary), KEY1 (rotation #1), and KEY2 (rotation #2)
- The app is signed with the current primary key at every release. The **bootloader is signed with all three keys, once**, and then frozen (see [6d](#6d-frozen-bootloader)): it cannot be replaced by an SD update and must survive rotations, and signing it per release would pull keys 1 and 2 out of cold storage every time
- Document eFuse programming workflow and recovery procedures

#### 6b. Build system integration
- `sdkconfig.secure` overlay (`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y`, `CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y` so that no app burns secure download mode at startup): replaces the Phase 4 signed-on-update-only config. Done, with anti-rollback on at security version 0 (6c)
- `bootloader_components/secure_boot_opt_in`: a stock `CONFIG_SECURE_BOOT` bootloader enables secure boot by itself on first boot, burning the digests of whatever signed it. The component wraps that call so the bootloader verifies apps once secure boot is on but never turns it on; the Settings menu does. Done, with a virtual-eFuse dry run (`just sbtest-flash`); not yet run on hardware
- Releases build with `sdkconfig.release` + `sdkconfig.secure` and ship the frozen bootloader, not the built one (6d)
- Leave `CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE` **off**: revoking a good key on one failed verification is a bricking hazard for a wallet
- CI pipeline: build unsigned, developer signs the app offline as part of release; CI checks the frozen bootloaders against the public keys and, when its ESP-IDF version matches, against a rebuild from the freeze tag
- **Reproducible builds are a prerequisite for the first signed release**: with CI building unsigned and the developer signing offline, users can only verify that a signed release matches the source if they can reproduce the unsigned image bit-for-bit. Pin toolchain/IDF versions and document the build recipe. The bootloader already meets this: its unsigned image is identical across build directories, which is what lets anyone check a frozen bootloader against its tag.
- Keep development builds unsigned (separate sdkconfig)
- Anti-rollback counter enabled (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`): firmware carries a monotonic security version enforced from eFuse; it **backs** the Phase 4 software downgrade check rather than replacing it (see [6c](#6c-anti-rollback-efuse-security-version) for the full plan)
- Note ESP-IDF 6.0 API renames: `esp_secure_boot_verify_signature_block()` removed (use `esp_secure_boot_verify_rsa_signature_block()`); `esp_flash_encryption_enabled()` deprecated (use `esp_efuse_is_flash_encryption_enabled()`)
- Re-run the Phase 4d validation suite on a locked device before the first lockable release

#### 6c. Anti-rollback (eFuse security version)

**Decided November 2026: on, in the secure-boot overlay at security version 0, ahead of the first bootloader freeze (6d).** The boot-time refusal of an older app is bootloader code, so a bootloader frozen without anti-rollback could only gain it through a re-freeze and a USB reflash of each device, and the older bootloader would stay valid for as long as its keys are. Anti-rollback is what stops an attacker (or a careless user) from installing a genuinely signed *older* Kern release to reopen a fixed vulnerability. On a device without it, a downgrade is refused only by our own pre-flight check running inside the firmware being replaced, which an attacker with serial access simply flashes over.

##### What already exists

- `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` (`sdkconfig.defaults`): the Kconfig dependency of `BOOTLOADER_APP_ANTI_ROLLBACK` is already satisfied.
- OTA-only partition table, no `factory`: the layout anti-rollback requires (see [Partition Table](#partition-table)); this was settled in Phase 3.
- `core/fw_update.c` rejects an image whose `secure_version` is below the running app's, with the user-visible error "Older security version rejected", and calls `esp_ota_mark_app_valid_cancel_rollback()` after a successful update, the self-confirm that makes the previous slot a valid fallback.
- Development builds leave `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` unset, so `CONFIG_BOOTLOADER_APP_SECURE_VERSION` is invisible to Kconfig and `esp_app_desc.c` compiles `.secure_version = 0` into them. Builds with the overlay below set it, also to 0. **The Phase 4 software check is therefore a no-op today**, comparing 0 against 0, and only becomes meaningful with the first bump.

##### The eFuse field is a 16-shot budget

On ESP32-P4 `SECURE_VERSION` is **16 bits** in BLK0 (bits 137–152) and is **unary-encoded**: `esp_efuse_read_secure_version()` returns the *popcount* of the field, and writing version N burns N bits. The maximum security version is 16: **the device gets 16 increments for its entire lifetime, and there is no un-burn**. `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD` must be pinned at 16 and never changed afterwards: it is the build-time interpretation of the field, so lowering it on a later release silently re-reads already-burned bits.

Policy, to be recorded in the release checklist: the security version is **not** the app version. `version.txt` moves every release; the security version moves only when running an older release is unacceptable, meaning a key-handling, PIN, signing, or update-path vulnerability. At a realistic worst case of one bump a year, 16 bits outlast the hardware; spending them on routine releases does not.

##### Who burns the counter, and exactly when

Three sites, all worth knowing before the first burn:

1. **The app**, in `esp_ota_mark_app_valid_cancel_rollback()` → `esp_ota_set_anti_rollback()` → `esp_efuse_update_secure_version()` (IDF `esp_ota_ops.c`), reads the *running* partition's descriptor. This is Kern's own call in `core/fw_update.c`.
2. **The bootloader**, when the active otadata state is already `ESP_OTA_IMG_VALID` (`bootloader_utility.c`, `update_anti_rollback()`). An image still in `PENDING_VERIFY` does **not** burn, which is the ordering we want: the new firmware must confirm itself before the counter moves.
3. **The bootloader again, on a fresh serial flash**: when otadata is empty or invalid it writes an otadata entry as `VALID` and burns immediately. So `just flash` of a bumped image on a wiped device moves the counter on first boot with **no self-test gate at all**. This is the path alpha testers use, and the reason a bump must be bench-validated before release.

##### One-way consequences to accept before the first bump

- **A confirmed bump destroys the fallback slot.** `esp_ota_check_rollback_is_possible()` only accepts the other slot if its `secure_version` still passes the eFuse check, so after the counter moves, the previous release stops being a rollback target. A security-bump release ships without a safety net, and everything else in Phase 4 assumes there is one.
- `esp_ota_set_boot_partition()` on a too-old image **erases that partition** and returns `ESP_ERR_OTA_SMALL_SEC_VER`. Kern's pre-flight check normally rejects first, so this is the second line, not the visible one.
- The bootloader refuses any slot below the eFuse value (`check_anti_rollback()`, wrapped in an `ESP_FAULT_ASSERT` anti-FI double read).
- Downgrade becomes physically impossible **for the developer too**: no debug path, no serial escape. Keep a never-bumped unit for reproducing old-version bug reports.
- **Never run `espefuse write_protect_efuse SECURE_VERSION`.** `WR_DIS.SECURE_VERSION` (BLK0 bit 18) would freeze the counter and disable every future bump. Nothing in the secure-boot flow burns it; this is a manual footgun only.
- Visibility: a bootloader that logs at INFO prints `Secure version (from eFuse) = N` on every boot, and `espefuse summary` shows `SECURE_VERSION` on a device that is not locked. A locked release device offers neither: its bootloader logs at WARN and secure download mode refuses `espefuse`. There the Secure Boot page shows the counter.

##### Implementation, in the secure-boot overlay

In `sdkconfig.secure` since November 2026. All of it belongs there alongside 6b, never in `sdkconfig.defaults`: a `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` on master would start burning counters on every device that flashes a master build:

```
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SECURE_VERSION=0
CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16
```

The first signed release goes out at **security version 0**, which burns zero bits: the feature is armed and enforcing, but the budget is untouched until a real vulnerability calls for the first bump. Note that both value symbols `depend on BOOTLOADER_APP_ANTI_ROLLBACK`, so they cannot be pre-pinned on master, since Kconfig drops invisible symbols. What *can* be done on master ahead of time is documentation-only: record the bump policy in the release checklist, and surface `secure_version` in the SD-update confirm dialog whenever it differs from the running app, so a bump is never a silent property of an update.

##### Validation

Two tiers, in this order.

**(a) Emulated, no permanent burns.** `CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE=y` selects `EFUSE_VIRTUAL` + `EFUSE_VIRTUAL_KEEP_IN_FLASH` and needs a partition entry `emul_efuse, data, efuse, , 0x2000`. Two warnings: it virtualizes **all** eFuse operations, so PIN provisioning (KEY4/KEY5), flash encryption, and secure boot all become fake on that build; and it requires its own partition CSV, so it is not the frozen production table. Bench-only, never signed, never handed to a user.

**(b) Real burns on the board sacrificed for the lockdown tests** (6d). Each test bump permanently spends one of its 16 bits: acceptable on the mule, never on a user device.

The matrix, in order:

1. Fresh serial flash at version 0 → eFuse popcount stays 0.
2. SD OTA 0 → 1, self-confirm succeeds → popcount becomes 1; bootloader log reports `Secure version (from eFuse) = 1`.
3. SD OTA 1 → 0 → rejected by the `fw_update` pre-flight with the existing error, before anything is written; confirm no partition was erased.
4. Same downgrade with the pre-flight check stubbed out (debug build) → `esp_ota_set_boot_partition()` returns `ESP_ERR_OTA_SMALL_SEC_VER` and erases the target slot; the device still boots version 1.
5. **The test that proves the feature**: serial-flash version 0 onto the device with eFuse = 1 → the bootloader refuses to boot it. This is the attack anti-rollback exists to stop; confirm the device stays recoverable by reflashing version 1.
6. Rollback still works between equal versions: OTA 1 → 1′, fail the self-confirm, verify the device returns to the previous slot.
7. After a confirmed bump, verify the previous slot is no longer a rollback target, the expected loss of the safety net, documented here so it is a decision and not a surprise.

Re-run this matrix as part of the Phase 4d suite on a locked device.

#### 6d. Frozen bootloader

**Decided November 2026.** After lockdown the bootloader on a device is fixed: SD updates write only the app slot, and the ROM accepts a replacement only if a non-revoked key signed it. It also needs all three signatures so that no rotation can strand it, and the lockdown menu verifies exactly that against the embedded keys before burning anything. Producing three signatures per release is not acceptable (keys 1 and 2 are cold), so the bootloader is signed once and reused. Full procedure in [secure-boot.md §4a](secure-boot.md#4a-the-frozen-bootloader).

- **Four variants, not one per board.** The bootloader is independent of display, touch and camera. It splits on chip revision range (v1.x / v3.x) and flash mode (wave_35 is DIO, the rest QIO). Measured: wave_4b, wave_5 and crowpanel release bootloaders are byte-identical; wave_35 differs. The staging step confirms the rest.
- **Stored in the repository**: `kern_secure_boot/bootloaders/<variant>/bootloader-signed.bin` plus a `BOOTLOADERS` manifest (freeze number, git tag, ESP-IDF version, boards, unsigned SHA-256), covered by the existing `SHA256SUMS.sig`.
- **Freeze ceremony** (rare, air-gapped, all three keys): stage the unsigned bootloaders from a tagged commit, sign each with keys 0, 1 and 2, verify against the published public keys, commit, tag `bootloader-<N>`. `CONFIG_BOOTLOADER_PROJECT_VER` carries N.
- **Each release** (key 0 only): `release.sh` packages the frozen bootloader for the board's variant and warns when the freshly built one differs; `sign_release.sh` refuses a bootloader that does not verify against all three public keys.
- **Compatibility rule**: every release must boot on every frozen bootloader still in the field. A change that breaks this is a re-freeze, and reaches a locked device only through a USB reflash by its owner.
- **Fixed by a freeze**: the ESP-IDF version of the bootloader, the opt-in wrapper, anti-rollback on or off (6c), bootloader log level.
- **Existing devices** got their bootloader from an earlier release and SD updates never changed it. They need one USB install of a lockable release; it preserves NVS and storage. The menu detects the old bootloader and says so.
- **Web flasher**: must write the bootloader without rewriting its header and must work in secure download mode, so a locked device can still take a signed release over USB. There the flash size has to be given explicitly (16MB): the ROM cannot detect it and otherwise refuses writes past 2 MB. Done and verified on a locked v1.x board. On v3.1 and v3.2 chips the flash power-on in download mode needs register writes that secure download mode refuses (measured on v3.2), so the Secure Boot page refuses to lock those revisions until a USB path exists for them.
- **Self-built firmware** follows the same model with the user's keys: replace the three digest files, sign their own bootloader with their three keys, and the menu checks against those.

Order of work:

1. Tooling that needs no private key: `just bootloader-stage`, the manifest, `scripts/freeze_bootloader.sh`, `just bootloader-import`, the `release.sh` / `sign_release.sh` changes and the web flasher changes (done), then the CI checks.
2. Hardware: the virtual-eFuse dry run, then a real lockdown on a sacrificial board, followed by an SD update and a USB reflash on it.
3. The anti-rollback decision (6c). Taken: on.
4. The freeze ceremony.
5. The first lockable release.

### Phase 7: Release Lockdown (dropped)

**Dropped with Phase 5.** It had three parts:

- Flash-encryption release mode: gone with flash encryption.
- Secure download mode and JTAG disable: burned by the Phase 6 lockdown.
- Disabling ROM download mode entirely: not planned. Secure download mode already refuses flash readout, and unsigned code does not boot. A full disable would add little and would remove USB recovery and the only way to replace a frozen bootloader.

### Phase 8 (Future): TEE / World Controller

- Investigate ESP32-P4 World Controller / PMS maturity in ESP-IDF
- Goal: signing operations in World0 (secure), UI in World1 (non-secure)
- Most complex and least mature; watch Espressif's ESP-TEE progress
- Pragmatic measures (secure_memzero, secrets in internal SRAM, session-only keys) provide good coverage meanwhile
