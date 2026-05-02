# Changelog

## [Unreleased]

### Added
- Support for Waveshare ESP32-P4-WiFi6-Touch-LCD-4.3 (wave_43, 480x800 MIPI DSI, ST7701)

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
