# Kern Secure Boot Public Keys

This folder holds the **public** key material for Kern's Secure Boot v2 (**RSA-3072 / RSA-PSS**). These files are safe to distribute — they contain no private key material.

> **No keys are published yet.** The placeholder keys that previously lived here were never used for a real release and have been removed. The authentic public keys and digests below will be added — and this README's expected-digest values filled in — as part of the first signed release, following the key ceremony in [docs/secure-boot.md](../docs/secure-boot.md#3e-key-ceremony-checklist). Do not trust any keys in this folder until they arrive with a matching `SHA256SUMS.sig` from the developer's published GPG/SSH key.

## Why RSA-3072 (not ECDSA)

ECDSA-based Secure Boot v2 is **not functional on ESP32-P4 silicon** (chip errata — enabling it would require `CONFIG_SECURE_BOOT_INSECURE`). Kern therefore signs with RSA-3072, which on ESP32-P4 is also the faster verifier. See [docs/secure-boot.md §2](../docs/secure-boot.md#2-algorithm-choice).

## Three keys, two rotations

Kern burns **three** signing-key digests into eFuse (KEY0/KEY1/KEY2), so a compromised or lost key can be rotated out up to twice. Released firmware is normally signed with the primary key only; the second-stage bootloader is signed with all three keys so it survives future rotations.

## Contents (once published)

| File | Description |
|------|-------------|
| `kern-sb-key0-pub.pem` | Public key 0 (primary signing key) |
| `kern-sb-key1-pub.pem` | Public key 1 (rotation #1) |
| `kern-sb-key2-pub.pem` | Public key 2 (rotation #2) |
| `kern-sb-digest0.bin` | SHA-256 digest of public key 0 (32 bytes, burned into eFuse KEY0) |
| `kern-sb-digest1.bin` | SHA-256 digest of public key 1 (32 bytes, burned into eFuse KEY1) |
| `kern-sb-digest2.bin` | SHA-256 digest of public key 2 (32 bytes, burned into eFuse KEY2) |
| `SHA256SUMS` | SHA-256 checksums of all files above |
| `SHA256SUMS.sig` | GPG detached signature of `SHA256SUMS` |

## Expected Digest Values

These are the hex representations of the digest files. When activating secure boot on-device via **Settings > Secure Boot > Lock with Developer Keys**, the device displays these values for visual verification.

```
Digest 0: <published with the first signed release>
Digest 1: <published with the first signed release>
Digest 2: <published with the first signed release>
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
for n in 0 1 2; do xxd -p kern-sb-digest${n}.bin | tr -d '\n' && echo; done
```

## On-Device Secure Boot Activation

When you navigate to **Settings > Secure Boot > Lock with Developer Keys**, the device will:

1. Display the hex values of Digest 0, Digest 1, and Digest 2 (from constants embedded in the firmware).
2. Show a warning that this action is **irreversible** (eFuses are permanently burned).
3. Require PIN entry to proceed.
4. Burn the three digests into eFuse KEY0/KEY1/KEY2, then set the `SECURE_BOOT_EN` bit.

**Before confirming**, verify that the digests shown on screen match the values in this README and in the release notes. This ensures the firmware you are running contains the authentic developer keys.

After lockdown, only firmware signed with one of the corresponding private keys will boot on the device.

## More Information

See [docs/secure-boot.md](../docs/secure-boot.md) for the full secure boot guide, including key rotation, anti-rollback, manual lockdown via `espefuse`, and self-sovereign builds with your own keys.
