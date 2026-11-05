# Roadmap

Kern is a research and development project. This list tracks what has been explored and what is still open: research directions, not a release schedule.

- ✅ Basic UI
- ✅ Multi-board support
- ✅ Camera video pipeline
- ✅ Static QR codes
  - ✅ Scan
  - ✅ Display
- Animated QR Codes
  - Scan, parse and export
    - ✅ UR
    - ✅ pMofN
    - ✅ BBQr
- New Mnemonic
  - ✅ From dice rolls
  - ✅ From words
  - ✅ From camera
- Load Mnemonic
  - ✅ From manual input (typing words)
  - From QR codes
    - ✅ Plain
    - ✅ SeedQR
    - ✅ Compact SeedQR
  - Encrypted
    - ✅ Flash
    - ✅ SD Card
- Back up
  - ✅ Words
  - ✅ QR codes
  - ❌ Binary Grids
  - ✅ Encrypted
- ✅ Passphrases
- Networks
  - ✅ Mainnet
  - ✅ Testnet
- ✅ Account (any BIP44/49/84/86 account 0–100, no per-session selection required)
- ✅ BIP85 deterministic entropy
- Policy types
  - ✅ Single-sig (BIP44/49/84/86 whitelist; no policy setting required)
  - ✅ Multisig (session-loaded or registered descriptors)
  - ✅ Miniscript (Native Segwit and Taproot)
- Descriptors
  - ✅ Loading
  - ✅ Exporting
  - ✅ Saving
  - ✅ Encrypting/Decrypting
  - ✅ Persistent registration with encrypted descriptor backups on flash or SD card, using the public keys inside the descriptor as keys (BIP138)
- Script type
  - ✅ Legacy
  - ✅ Native Segwit (P2WPKH, BIP84)
  - ✅ Nested Segwit (P2SH-P2WPKH, BIP49)
  - ✅ Taproot (P2TR, BIP86)
- ✅ Message signing (BIP137 and PSBT-based BIP322)
- ✅ Address exploration and verification (scan to verify)

- Security
  - ✅ KEF encryption
  - ✅ PIN (with anti-phishing identicon)
  - ✅ SD card air-gapped updates with signature verification
  - ✅ Encrypted NVS storage (eFuse-derived keys)
  - ✅ Session lock with auto-timeout
  - ❌ OTP based secure boot
  - ❌ Flash/RAM encryption
  - ❌ Option to disable USB-serial and JTAG

- Easy Installer
  - ✅ Flasher
  - ❌ Secure boot activation
  - ❌ Flash/RAM encryption activation

- Reliability
  - ✅ Simulator (desktop, with webcam QR scanning)
  - ✅ Auto tests
    - ✅ Host tests on every commit in CI
    - ✅ Fuzzing and sanitizer builds
    - ✅ On-device self test (known-answer checks)

- ❌ User's documentation
