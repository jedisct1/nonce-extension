# Derive-Key-AES-GCM

AES-GCM is a very common choice of authenticated encryption algorithm.

Unfortunately, it has some [pretty low usage limits](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/).

Using it with a large amount of messages requires extra care to ensure that nonces never repeat, and that keys are frequently rotated.

The TLS protocol hides that complexity, but applications using AES-GCM directly need to be aware of these limitations in order to use AES-GCM safely.

Ideally, nonces should be large, allowing applications to safely generate them randomly, with a negligible collision probability. But AES-GCM, as commonly implemented and required by IETF protocols, is limited to 96-bit (12 bytes) nonces, which is not enough to avoid collisions. AES-GCM keys are also expected to be replaced way before 2^32 messages have been encrypted.

During the 2023 NIST Workshop on Block Ciphers, Shay Gueron presented a clever way to overcome these limitations, and extend a key lifetime to "forever": the [Derive-Key-AES-GCM](https://csrc.nist.gov/csrc/media/Presentations/2023/constructions-based-on-the-aes-round/images-media/sess-5-gueron-bcm-workshop-2023.pdf) construction.

This construction allows larger nonces to be used with AES-GCM, thus extending the key lifetime. With AES-256 and 192-bit nonces, a practically unlimited number of messages can be encrypted using a single key, and with nonces that can be randomly generated.

It significantly improves the safety of AES-GCM with minor overhead.

When instantiated with `AES-128`, the `Derive-Key` construction derives a fresh `AES-128` encryption key from a key and a nonce that can be up to 120 bits (theorically 126, but 120 for practical purposes). That encryption key can then be used with `AES-128-GCM`, along with a static nonce.

When instantiated with `AES-256`, the `Double-Nonce-Derive-Key` construction derives a fresh `AES-256` encryption key from a key and a nonce that can be up to 232 bits (but 192 is enough for all practical purposes). That encryption key can then be used with `AES-128-GCM`, along with a static nonce, and the guarantee that keys will never repeat.

This repository contains easy-to-use implementations of these constructions (`aes256-gcm-dndk`, `aes128-gcm-dndk`).