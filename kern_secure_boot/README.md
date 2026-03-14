# Kern Secure Boot Public Keys

This folder contains the **public** key material for Kern's Secure Boot v2 (ECDSA-P256). These files are safe to distribute, they contain no private key material.

## Contents

| File | Description |
|------|-------------|
| `kern-sb-key0-pub.pem` | Public key 0 (primary signing key) |
| `kern-sb-key1-pub.pem` | Public key 1 (backup/rotation key) |
| `kern-sb-digest0.bin` | SHA-256 digest of public key 0 (32 bytes, burned into eFuse KEY0) |
| `kern-sb-digest1.bin` | SHA-256 digest of public key 1 (32 bytes, burned into eFuse KEY1) |
| `SHA256SUMS` | SHA-256 checksums of all files above |
| `SHA256SUMS.sig` | GPG detached signature of `SHA256SUMS` |

## Expected Digest Values

These are the hex representations of the digest files. When activating secure boot on-device via **Settings > Secure Boot > Lock with Developer Keys**, the device will display these values for visual verification.

```
Digest 0: 110aa1fbb55cac594223f34bbbbbaa6ec4019b5a5490b0976398ea42d3df5e87
Digest 1: ae4ffa65b66f66e0ca9e28e6b805d7b5fdec4d283f025dcd86aea723f7f95e8c
```

Compare the digests shown on screen against the values above (and against those published in the release notes) before confirming the lockdown.

## Verifying These Files

Before trusting these keys, verify the GPG signature and checksums:

```bash
# 1. Verify the GPG signature on SHA256SUMS
gpg --verify SHA256SUMS.sig SHA256SUMS

# 2. Verify all file checksums match
sha256sum -c SHA256SUMS
```

You can also compute the hex representation of the `.bin` digest files to compare against the expected values above:

```bash
xxd -p kern-sb-digest0.bin | tr -d '\n' && echo
xxd -p kern-sb-digest1.bin | tr -d '\n' && echo
```

## On-Device Secure Boot Activation

When you navigate to **Settings > Secure Boot > Lock with Developer Keys**, the device will:

1. Display the hex values of Digest 0 and Digest 1 (from constants embedded in the firmware).
2. Show a warning that this action is **irreversible** (eFuses are permanently burned).
3. Require PIN entry to proceed.
4. Burn the digests into eFuse KEY0 and KEY1, then set the `SECURE_BOOT_EN` bit.

**Before confirming**, verify that the digests shown on screen match the values in this README and in the release notes. This ensures the firmware you are running contains the authentic developer keys.

After lockdown, only firmware signed with the corresponding private keys will boot on the device.

## More Information

See [docs/secure-boot.md](../docs/secure-boot.md) for the full secure boot guide, including key rotation, anti-rollback, manual lockdown via `espefuse.py`, and self-sovereign builds with your own keys.
