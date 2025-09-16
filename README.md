# Derive-Key-AES-GCM

AES-GCM is a very common choice of authenticated encryption algorithm.

Unfortunately, it has some [pretty low usage limits](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/).

Using it with a large amount of messages requires extra care to ensure that nonces never repeat, and that keys are frequently rotated.

The TLS protocol hides that complexity, but applications using AES-GCM directly need to be aware of these limitations in order to use AES-GCM safely.

Ideally, nonces should be large, allowing applications to safely generate them randomly, with a negligible collision probability. But AES-GCM, as commonly implemented and required by IETF protocols, is limited to 96-bit (12 bytes) nonces, which is not enough to avoid collisions. AES-GCM keys are also expected to be replaced way before 2^32 messages have been encrypted.

During the 2023 NIST Workshop on Block Ciphers, Shay Gueron presented a clever way to overcome these limitations, and extend a key lifetime to "forever": the [Derive-Key-AES-GCM](https://csrc.nist.gov/csrc/media/Presentations/2023/constructions-based-on-the-aes-round/images-media/sess-5-gueron-bcm-workshop-2023.pdf) construction. This work has been formalized in the [IETF draft specification](https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/).

This construction allows larger nonces to be used with AES-GCM, thus extending the key lifetime. With AES-256 and 192-bit nonces, a practically unlimited number of messages can be encrypted using a single key, and with nonces that can be randomly generated.

It significantly improves the safety of AES-GCM with minor overhead.

The `Double-Nonce-Derive-Key` (DNDK) construction for `AES-256` derives a fresh `AES-256` encryption key from a root key and a nonce. The nonce can be either:
- 12 bytes (96 bits) - standard AES-GCM nonce size
- 24 bytes (192 bits) - extended nonce for enhanced security

The derived encryption key is then used with `AES-256-GCM` along with a static nonce (or the NTail portion from the specification), guaranteeing that keys will never repeat.

## Implementations

This repository contains implementations of the DNDK-GCM construction in multiple languages:

### Rust
- `nonce-extension`: Core DNDK-GCM implementation for AES-256
  - `dndk_derive()`: Full implementation with optional key commitment as per [IETF draft-gueron-cfrg-dndkgcm-03](https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/03/)
  - `nonce_extension_aes256()`: Convenience function for key derivation without key commitment
  - Supports both 12-byte and 24-byte nonces
  - Includes official IETF test vectors
- `xaes-gcm`: High-level wrapper providing `XAes256Gcm` for easy use
  - Automatic 24-byte nonce generation
  - Simple encrypt/decrypt API with associated data support

### Zig
- Full DNDK-GCM implementation with key commitment support
  - AES-256 implementation matching the IETF specification
  - Supports variable nonce lengths (12-27 bytes)
  - Optional key commitment for enhanced security
  - Uses parallel encryption with `encryptWide` for optimal performance
  - Includes official IETF test vectors
  - Compatible with Zig 0.15

## License

ISC License - See [LICENSE](LICENSE) file for details
