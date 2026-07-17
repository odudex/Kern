# Changelog

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
