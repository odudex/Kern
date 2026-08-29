# Changelog

## [Unreleased]

### Fixed
- Camera preview flicker in bright areas on CrowPanel (SC2336): esp_ipa 2.2.0 hunts around the AE target where 2.1.0 did not. The SC2336 tuning now widens the AGC dead band from roughly ±3.5 to ±10 luma around the target, slows the increase and decrease speeds, and recomputes exposure every third frame instead of every frame. A scanner is better served by steady exposure than by precise exposure, and the result is calmer than 0.0.18 was

### Changed
- Updated to ESP-IDF 6.1 and newer managed components (esp_video 2.3.0, esp_lvgl_adapter 0.6.4, esp_cam_sensor 2.3.0). esp_video is held at 2.3.x deliberately: 2.4+ requires esp_ipa 2.3, whose prebuilt ESP32-P4 blob is built with the RISC-V B extension this core lacks, which crashes any board running the ISP pipeline controller. No source changes were needed: of 6.1's breaking changes, the deprecated MIPI DSI `on_refresh_done` callback is handled inside the LVGL adapter, the UART wakeup API is unused here, and the ESP32-P4 default-revision move to v3.0 was already covered by the existing `CONFIG_ESP32P4_SELECTS_REV_LESS_V3` setting that keeps v1.x boards supported

## [0.0.18] - 2026-08-28

### Added
- PSBT version 2. A v2 PSBT carries no global transaction, so every output classified as somebody else's and the review screen could not be built at all; the transaction is now extracted for either version, which also resolves BIP-370's per-input required locktimes into the transaction's own. Signing additionally clears BIP-370's tx-modifiable flags, which libwally's own signing path never reaches — leaving them set invites the next tool in the chain to add inputs or outputs that would silently invalidate the signature just produced. Trim declines v2, since it rebuilds through a constructor that only produces v0

### Changed
- PBKDF2 drives the SHA accelerator directly instead of going through PSA, which rebuilt a fresh HMAC per iteration and took the shared SHA/AES crypto mutex, enabled the bus clock and pulsed the peripheral reset around every hash update crossing a block — roughly 6800 cycles of setup around 1150 cycles of work. Holding the peripheral across batches of iterations and reloading precomputed HMAC ipad/opad midstates measures 12.2x on wave_4b: a KEF decrypt or a PIN check at 100,000 iterations drops from 8.07 s to 0.66 s. Output is byte-identical to the PSA path, which stays compiled in as the fallback; every call first runs a known-answer vector through the accelerated code and reverts to PSA if it disagrees
- The PSBT review screen surfaces nLockTime and nSequence, which appeared nowhere before, so a transaction that cannot be broadcast for years and one that is replaceable no longer both read as ordinary. Outputs below the relay dust threshold are marked rather than shown as ordinary spends; the threshold follows Bitcoin Core's GetDustThreshold, giving the familiar 294 / 330 / 546 values
- KEF is covered by cross-implementation vectors for all twelve format versions. Six are the envelopes Krux's own suite pins down; the other six had none published, so they come from an independent reference that reproduces those six byte-for-byte first — every version now decrypts against externally-derived bytes rather than Kern's own output
- Updated libwally-core

### Fixed
- Encrypted QR codes the device had just exported were rejected when scanned back in: Kern armors KEF as base64 on SD but base43 in a QR, and the shared detector only knew base64. The login and load-mnemonic scanners no longer need their own base43 probes either
- A KEF envelope could declare its own PBKDF2 work factor without limit. The 3-byte field encodes up to 100,000,000 — 1000x the app's own setting — so a scanned envelope could park the device in key derivation for minutes with the idle watchdog deliberately off, or declare 0 and skip key stretching entirely. The count is now bounded at the single read choke point and again on write, and a zero-length payload reports an auth failure instead of an allocation error
- Both KEF pages kept the crypto worker's task handle and deleted it on teardown. The worker self-deletes once done, so that handle goes stale for a poll interval; killing it mid-derivation also skipped the re-subscribe that restores the core-1 idle watchdog, silently disabling it for the rest of the boot
- Outputs adding up to more than the inputs cannot happen on chain, but the review screen clamped the fee to zero and then rendered no fee row at all, so a PSBT with an understated input or an inflated output showed no fee and no warning. It is now refused, guarded on every input having supplied an amount since a missing one counts as zero and produces the same shape honestly; where that guard applies the absent fee is named rather than left blank
- A correct PIN entered on the final allowed attempt was wiped instead of accepted, because the wipe threshold was applied before the comparison. A corrupted threshold is now clamped rather than treated as a wipe — which had destroyed the seed even when the entered PIN was right — and one rule applies at all four sites that read it, where previously only the post-comparison decision honoured the range
- A hostile PMOFN or BBQr sequence could grow retained allocations before any final assembly check ran, and the metadata parsers used `strstr`/`atoi` over a buffer they were handed with an explicit length. Insertion is capped at 1024 parts and 1 MiB, PMOFN metadata is validated with overflow-safe decimal parsing, totals and encoding are bound to the first accepted frame, and a violation enters a terminal failure state so the scan fails closed instead of hanging
- `sd_card_read_file()` allocated whatever `st_size` reported, so a hostile card could make the device chase a multi-gigabyte read before anything looked at the content. Reads are capped at 1 MB, far above any descriptor, PSBT or mnemonic backup

## [0.0.17] - 2026-08-24

### Added
- Support for Waveshare ESP32-P4-WiFi6-Touch-LCD-7B (wave_7b, 1024x600 MIPI DSI, EK79007)
- Entropy quality checks on the two user-supplied sources: dice rolls pair a Shannon histogram estimate with a consecutive-difference pattern check, and camera capture folds the hardware RNG into the frame digest by hashing. The estimates describe the observed distribution, not cryptographic entropy; dice deliberately stays reproducible so the derivation can be verified off-device
- An auxiliary entropy pool behind the hardware RNG, fed by touch timing and camera sensor noise and folded into `crypto_random_bytes` by hashing rather than XOR, so a worthless or attacker-known pool leaves the output exactly as strong as the RNG alone. Extraction ratchets the pool, so a later compromise cannot recover the state behind bytes already handed out
- The mnemonic backup QR viewer navigates zoomed regions by swipe, one axis at a time, and drags the zoomed region under the finger
- Icons on the mnemonic and descriptor source menus

### Changed
- The BIP39 passphrase was the only secret entered in plaintext, with the confirm dialog echoing it back verbatim. It is now masked like PIN and KEF-key entry, with the same eye toggle, and confirmed by the fingerprint transition it produces (current > with-passphrase): a typo still looks like plausible dots either way, but it derives a different wallet, which a mismatched fingerprint makes visible. Wallet Settings now shows only the currently-active fingerprint
- Every keypad marks its backspace/OK key with a solid orange fill, so the primary action is distinct at rest instead of only flashing on press; regular keys move to an orange outline
- Addresses viewer uses the screen space more efficiently
- Updated cUR and k_quirc

### Fixed
- `warn_unused_result` is enforced across `core/`, `qr/` and `utils/`, which surfaced 42 discarded results. The one that mattered: `pin_init()`'s failure was dropped in both `app_main()` and the simulator, and `pin_is_configured()` returns false when the module is not initialized, so a failed init booted a device that has a PIN set straight past its own PIN gate. Both now fail closed. `pin_wipe_all()` ignored every step of the anti-brute-force wipe and restarted regardless; `storage_sanitize_id()` formatted an uninitialised hash buffer into a name shown in the UI and used to build a filename
- `crypto_random_bytes` returned void, so failure was structurally invisible: `pin.c` and `nvs_secure.c` would have burned a key made of stack garbage into eFuse. It now returns a checked status and rejects an all-zero draw
- The SAR ADC entropy source is off at app start on the ESP32-P4, leaving `esp_random()` without physical noise; it is now enabled around RNG reads

## [0.0.16] - 2026-08-11

### Added
- PSBT review shows the fee as a percentage of the total inputs and flags it in red at or above 10%, so an outsized fee no longer reads like a normal one
- Signing reports inputs that did not receive a signature: cleared inputs are counted against inputs that actually gained one (ECDSA map, taproot key signature and leaf signatures diffed rather than trusting the return code), and the scan page names the shortfall before offering export
- Project landing page at `site/index.html`, with the web flasher moved under `site/flash/`; `just site` stages branding plus locally built firmware exactly the way CI does and serves it on localhost, so a board can be flashed from the local copy before anything is pushed

### Changed
- New devices default to testnet. Consolidating Kern as a research platform, experimentation is the out-of-box state instead of a setting to find first
- The unproven-fee confirmation behind Sign is dropped; both fee warnings now live on the review screen itself
- Dev tools and the QR decode debug scaffolding are removed, both gates were permanently compiled out and k_quirc's own test harness covers the capture/decode pages
- Updated k_quirc and cUR

### Fixed
- An input Kern refused could still collect a signature: libwally signs every input whose keypath names the key it is given, so a UTXO of ours listed under someone else's fingerprint was shown as external while its signature was harvested anyway. Classification now runs up front, refused inputs are snapshotted and restored around signing, and discarded signatures are counted and reported
- Sighash flags other than ALL are refused, in the review gate and again per-input inside signing; under NONE, SINGLE or ANYONECANPAY the outputs and fee on screen are not what gets broadcast
- Input amounts are verified against the prevout txid instead of trusting whichever utxo the PSBT offered: amounts are classified as proven, asserted, invalid or missing, the proven value wins for display, and contradictory data is refused before the review screen. Unproven amounts still sign, coordinators trim the previous transaction for air-gapped transfers, but the fee is marked unproven

## [0.0.15] - 2026-07-24

### Added
- PSBT signing: when a transaction cannot be verified because no matching descriptor is loaded, the scan flow offers to load one on the fly instead of dead-ending
- The ESP32-C6 Wi-Fi/BT co-processor is held in reset on every board, so the radio never comes up on this air-gapped signer

### Changed
- **Partition table moved from 0x8000 to 0x10000**, enlarging the bootloader slot to 56KB — headroom the future flash-encryption and secure-boot bootloaders will need (the plain bootloader was already 320 bytes short of the old 24KB cap). NVS absorbs the shift — it moves to 0x11000 and shrinks from 84KB to 52KB; otadata, both app slots, and storage keep their offsets. **Existing devices need one serial reflash and NVS re-setup (PIN and settings); SD-card and OTA updates cannot cross this change.**
- Every build now carries a Secure Boot v2 signature block: IDF aborts at boot when the running app is unsigned, so dev builds are auto-signed with a per-clone throwaway key (generated on first build, gitignored) and releases re-sign the retained unsigned image offline with the real key
- Updated libwally


## [0.0.14] - 2026-07-20

### Added
- SD card firmware updates (security roadmap Phase 4): Settings → Firmware Update installs signed firmware from the SD card; the image is fully validated before any flash write (chip, project, version downgrade check, Secure Boot v2 RSA-3072 signature against the running app's keys), and the new image must self-confirm on first boot or the bootloader rolls back to the previous slot

### Changed
- App images carry Secure Boot v2 signature blocks; OTA updates are verified via signed-app-on-update (no secure boot eFuses involved yet), serial flashing unaffected
- The release single-file image is now a sparse Intel HEX (`kern-v<ver>.hex`) that preserves NVS (PIN, settings) and stored data when reflashing, replacing the raw merged `.bin`

### Fixed
- Release merged image placed OTA data at the pre-migration offset (0xf000), overwriting part of the NVS partition; corrected to 0x1e000 (same fix in the web flasher's fallback offsets)

## [0.0.13] - 2026-07-17

### Added
- NVS encryption (security roadmap Phase 3): PIN and settings are stored encrypted at rest with keys derived from a new eFuse HMAC key; provisioning is consent-gated during PIN setup, and devices with a pre-existing PIN run a one-time migration after unlock (declining removes the PIN)
- BIP322 message signing through PSBT-based signing requests
- Step progress bar in the PIN setup flow
- QR viewer: orientation-aware layout with density, brightness, and frame-rate settings
- Screensaver timeout configurable independently of the session timeout
- Simulator uses the webcam by default; `just sim-no-cam` runs without it

### Changed
- Partition table migrated to an OTA-only layout (NVS grown to 84K, dual 6MB app slots, factory and phy_init dropped) in preparation for anti-rollback; updating wipes NVS (PIN and settings) while SPIFFS storage survives
- Anti-phishing identicon color is drawn from a curated 12-color palette of nameable colors instead of a continuous hue
- Change PIN no longer asks for the current PIN a second time (entering PIN settings already verifies it)
- Scan pipeline: triple-buffered frame lease for the decoder, ROI-tracked decoding, progress UI moved off the decode task
- Crypto utilities ported to the PSA Crypto API
- Compression consolidated on zlib; BBQr streams unpadded base32 and the viewer retains generated parts
- Camera preview and animated QR frames count as session activity, preventing mid-scan lockouts
- UI rendering: shared reusable widget styles, optimized Sankey rendering, batched menu layout updates
- Updated k_quirc, cUR (P4 SIMD fountain XOR; decoder state machine surfaces terminal checksum failures), and libwally

### Fixed
- Loading a PSBT without a key loaded warns instead of failing silently
- Undecodable BBQr PSBT payloads are rejected instead of falling through to text detectors
- KEF envelope detection requires a printable ASCII ID, avoiding false positives on plaintext QR codes
- Camera: custom SC2336 IPA tuning anchors black level and softens gamma
- PSBT review: address-index cap applies to outputs only, and non-standard inputs are rendered
- Settings menu buttons are laid out correctly after PIN flows

## [0.0.12] - 2026-07-03

### Added
- Taproot miniscript: tr() script-path descriptors accepted at load, with the internal (key-path) key classified as ours / NUMS / external and unprovable internal keys rejected
- Taproot script type in the miniscript wallet export, seeding the BIP48-style 3h path
- Mnemonic entry by BIP39 word numbers (1-2048) alongside direct word input
- Backup QR view modes: Standard, Regions, and Zoomed (magnified region with row/column labels) to aid hand-transcription
- Mnemonic backup word list with color-coded numbered rows for easier transcription
- Multicolor variant for the Waveshare 4.3" enclosure

### Changed
- SD card: descriptor load now browses the whole card with a shared file browser (KEF detected by content); mounting reuses a live mount and retries at lower speed to fix spurious "No SD card" failures
- Updated to ESP-IDF 6.0.2, LVGL 9.5, and latest managed components;
- libwally-core submodule pinned to custom fork; bumped to 1.5.4 + custom taproot and musig2 experimental support
- Build with standard libsecp256k1: MuSig2 and anti-exfil layers compiled out (schnorr/BIP341 unaffected)
- Per-board font sizes derived from a sublinear curve so larger panels show proportionally more content
- PSBT signing cache enabled, avoiding O(n^2) sighash work on many-input transactions
- Secure-boot guide migrated to RSA-3072 with three-key rotation (ECDSA Secure Boot v2 is non-functional on ESP32-P4); lockdown roadmap reordered to match the safe eFuse burn order


## [0.0.11] - 2026-06-16

### Added
- Miniscript policy support: new wallet policy type, indented policy view, custom derivation-path editor, and a file-tree nesting guide in the descriptor view
- Watch-only login: scan and load descriptors without entering a key or mnemonic
- Load files from SD card: browse and import PSBT, descriptor, mnemonic, message, or address files
- Public key page: save xpub with key origin to SD card, and a testnet indicator in the key info header
- Tap xpub and address QR codes to view them fullscreen
- PIN delay state: visual countdown arc with attempt-severity styling
- Power-off and back buttons on the PIN page
- Waveshare 4.3" enclosure
- UI design guidelines doc (colour, icons, typography, dialogs)

### Changed
- Public key page: replaced the multisig toggle row with a policy dropdown; confirm before accepting unhardened path nodes
- Settings: removed the default-wallet page; network now persists from wallet settings
- Theme: colours named by intent (encourage/discourage, good/bad); widget factory split into theme_widgets
- Compact text keyboard on all boards, covering the full printable ASCII set
- Shared smart QR encoding across all UI QR codes

### Fixed
- Descriptors: handle large wsh scripts and enforce generation limits at load
- PSBT/scan: save the full untrimmed PSBT to SD card; default to UR encoding when exporting a file-loaded PSBT; return home after a signed-PSBT export
- KEF encrypt: keep the key-strength label clear of the keyboard at any resolution
- Camera: clamp PPA snap-crop fallback to crop_max
- PIN anti-phishing words: stack vertically and distribute evenly on narrow displays
- UI layout: constrain and wrap page/menu titles to avoid corner-button overlap; standardize header positions; prevent menu label clipping; tighten icon-to-text gap
- Wallet settings: remove needless scrollbar; destroy back button on exit

## [0.0.10] - 2026-05-30

### Added
- Login screen branding: pulsing logo, dice icon, and an About info button in the top-right corner
- Menu items can carry an icon
- CrowPanel 10.1 case

### Changed
- Landscape layouts for square devices, menus, and the public key page (2x2 grid)
- Harmonized page titles, corner buttons, two-tier buttons, and theme-based dialog spacing
- Danger dialogs use a warning icon and semantic colours
- Bumped libwally-core to 1.5.3

### Fixed
- Taproot PSBTs: testnet is detected correctly (no longer misread as mainnet) and change/self-transfer outputs are recognized instead of being treated as spends
- Theme paddings and button widths scale to the smallest screen dimension
- Mnemonic word-grid and battery icon alignment
- About page logo/QR sizing in landscape

## [0.0.9] - 2026-05-23

### Fixed
- Camera: recover from a stop timeout instead of leaking the stream task, which left the scanner unable to start after entropy capture (wave_35)

## [0.0.8] - 2026-05-22

### Added
- Support for CrowPanel 10.1 (ESP32-P4 board, EK79007 panel, GT911 touch)
- Web flasher deployment with CrowPanel 10.1 included
- Simulator now uses production storage with a file-backed SPIFFS shim
- Optional 4-bit custom GPIO routing for SD card (D1/D2/D3 Kconfig); defaults preserve the SDMMC IOMUX fast path
- Camera: SC2336 image sensor auto-detected alongside OV5647 (some CrowPanel modules ship with SC2336)
- Advanced Tools menu with BIP85 → BIP39 child mnemonic derivation (12/24 words, configurable child index)


### Fixed
- wave_4b: use internal LVGL draw buffer to avoid DMA2D copy window overlapping LCD draws
- Addresses page: align cropped address rows
- Scan: preserve address tip highlighting across wraps
- Scan: show network-mismatch error for cross-network addresses
- Scan: suppress QR format error on cancel
- Camera: show error and bail when camera unavailable
- Public key page layout
- Mnemonic QR layout on portrait devices

## [0.0.7] - 2026-05-15

### Added
- Descriptors can be loaded into the current session and used for PSBT/address matching; explicit flash/SD save/load remains available for backups.
- Session descriptor actions are now descriptor-scoped: view, export QR, save to flash/SD, or remove from session after selecting the descriptor.
- Permissive signing mode (opt-in in settings): allows signing PSBTs whose key paths are not matched by any loaded session descriptor.
- PSBT review now shows signing policy, per-source input totals, and highlights external inputs in the Sankey diagram.
- Public key export now supports script type and account selection, plus BIP48 multisig cosigner xpub export.
- Support for Waveshare ESP32-P4-WiFi6-Touch-LCD-4.3 (wave_43, 480x800 MIPI DSI, ST7701)
- Simulator webcam capture is available on macOS and Linux.

### Changed
- Removed the policy-selection step from the signing flow. Any BIP-44/49/84/86 account that matches a whitelisted descriptor is accepted directly.
- Account derivation is now inferred from the PSBT key path rather than a manual user setting. Existing PSBTs continue to sign correctly.
- Descriptor registration is disabled until encrypted descriptor backups are available; loaded descriptors are session-only, while explicit flash/SD storage remains a backup/import feature.
- Session descriptor details now use a full-screen viewer for long descriptor text instead of a modal dialog.
- Battery status is shown with icon glyphs instead of text percentages.
- Updated project target to ESP-IDF v6.0.1.

### Fixed
- Descriptor duplicate detection catches equivalent QR/storage loads that differ only by checksum or hardened-path notation.
- Descriptor loads with the wrong network now report a network mismatch instead of a generic parse error.
- Encrypted descriptor backups loaded from storage return cleanly after confirmation.
- Wallet settings apply network and passphrase changes immediately.
- Address and PSBT review controls fit better on narrow screens, including wrapped policy chips and scaled Sankey diagrams.
- Avoid VFS slot exhaustion when reinitializing camera/storage paths.

### Migration notes
- Devices upgrading in-place have their legacy `def_pol` NVS key (the old default-wallet-policy setting) automatically erased on first boot. No user action required.

## [0.0.6] - 2026-04-25

### Changed
- Address scan: progress dialog during sweep; per-round batch raised from 50 to 100
- Compact keypad layout on wave_35
- `just`: isolated per-board build dirs (`build_<board>/`); new `submodules` command
- CI runs on every commit of a PR
- Updated cUR submodule

### Fixed
- Camera luminance pulsing (disable ESP32-P4 ISP AE loop; widen OV5647 stable band)
- Scanner settings overlay caused white flashes on wave_5
- Focus-motor V4L2 probe spammed logs on boards without DW9714
- Splash screen artifact on warm reset (stale framebuffer)
- Wallet settings: Apply button cropped; pending edits preserved across descriptor manager trip
- PIN error modal disappearing on mismatch / wrong PIN
- PIN anti-phishing reveal hidden behind keyboard on wave_35; now requires explicit Continue
- Derivation path parser rejects `H` as hardened marker

## [0.0.5] - 2026-04-16

### Added
- Support for Waveshare ESP32-P4-WiFi6-Touch-LCD-5 (wave_5, 720x1280 MIPI DSI)

### Changed
- Updated k_quirc submodule
- Mnemonic storage: show name/ID after saving; larger delete button

### Fixed
- Entropy capture camera preview too zoomed in on small displays; uses PPA downscale instead of center crop
- KEF encrypt strength label overlapping keypad on wave_35

## [0.0.4] - 2026-04-13

### Fixed
- Scanner PPA Q4.4 quantization
- Screen rotation, not working with lgvl_adapter, was removed
- Dice rolls label overflowing the keypad on wave_35; truncates with "..." indicator when full

## [0.0.3] - 2026-04-13

### Added
- Multi-device support: Waveshare ESP32-P4-WiFi6-Touch-LCD-3.5 (wave_35, 320x480 SPI)
- Linux simulator with V4L2 webcam support for QR scanning and entropy capture
- PMIC support (AXP2101) with battery level indicator and power-off
- Camera settings overlay with adjustable exposure, focus, and autofocus controls
- Persistent camera AE target and focus position (NVS)
- CI jobs for automated builds
- BIP32 derivation path parser tests

### Changed
- Upgraded camera resolution to 1280x960
- Improved QR decoder performance; max QR version raised to 25
- Migrated wave_4b BSP to esp_lv_adapter and trimmed display API
- Bumped ESP-IDF to early 6.1 with relevant bugfixes
- Gated dev tools behind build configuration
- Addresses page: replaced Receive/Change toggle with dropdown
- Added processing dialog during PSBT signing
- Larger button surfaces on UI

### Fixed
- QR alignment pattern detection: use centroid instead of region seed
- BIP32 derivation path parsing
- Dialog titles better fit within bounds
- Watchdog timeout increased to accommodate PIN PBKDF2 processing
- Simulator PIN behavior aligned with device
- Correct BTN_COUNT macro calculation in keyboard

## [0.0.2]

### Added
- OTA-ready partition table (factory + dual OTA slots, 16MB flash)
- Message signing (prove address ownership)
- Smart Scanner: unified scan on home page handles PSBTs, messages, addresses, descriptors, and mnemonics
- Display rotation setting (0/90/180/270) with PPA hardware counter-rotation for camera
- PPA-accelerated bilinear downscaling for QR decoding
- Blue Wallet multisig descriptor parsing

### Changed
- Migrated to ESP-IDF v6.0
- Replaced local ST7703 fork with upstream Espressif component v2.0.2
- Larger button surfaces for improved UX
- Code quality improvements (cppcheck, clang-tidy)
