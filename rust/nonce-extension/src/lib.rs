#![no_std]

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

pub mod reexports {
    pub use aes;
}

/// Derive-Key-AES nonce extension mechanisms.
///
/// Extends the lifeftime of a cipher's secret key by deriving a new key from it and a nonce.
///
/// Usage with AES-128 (Derive-Key-AES-GCM):
///
/// ```rust
/// use nonce_extension::*;
/// let key = "128-bit key here";
/// let nonce = "extended nonce!";
/// let encryption_key = nonce_extension_aes128(key, nonce);
/// let zero_nonce = [0u8; 12];
/// // encrypt with `AES-GCM-128` using `encryption_key` and `zero_nonce`.
/// ```
///
/// The nonce can be any length up to 120 bits (15 bytes).
///
/// This significantly extends the key lifetime and improves the security bounds of AES-GCM.
///
/// The nonce can be any length up to 232 bits, but for practical purposes, 192 bits (24 bytes)
/// is recommended.
///
/// This allows the key to be reused without any practical limits on the number of messages,
/// and nonce can be generated randomly without any risk of collision.
///
/// `key`: the secret key to derive from.
/// `nonce`: the nonce to derive with.
///
/// Returns the derived key, suitable for AES-128-GCM and other AES-128 based ciphers.
pub fn nonce_extension_aes128(key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> [u8; 16] {
    let key = key.as_ref();
    let nonce = nonce.as_ref();
    const KEY_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 16;
    let nonce_length = nonce.len();

    debug_assert!(KEY_LENGTH >= BLOCK_LENGTH);
    debug_assert_eq!(KEY_LENGTH % BLOCK_LENGTH, 0);

    let key_blocks = KEY_LENGTH / BLOCK_LENGTH;

    let ks = Aes128::new(GenericArray::from_slice(key));
    if key_blocks == 1 {
        debug_assert!(nonce_length < BLOCK_LENGTH);
        let z = GenericArray::from([0u8; 16]);
        let mut blocks = [z; 3];
        for (i, block) in blocks.iter_mut().enumerate() {
            block[..nonce_length].copy_from_slice(nonce);
            block[nonce_length] = i as _;
        }
        ks.encrypt_blocks(&mut blocks);
        let x = u128::from_ne_bytes(blocks[0].into())
            ^ u128::from_ne_bytes(blocks[1].into())
            ^ u128::from_ne_bytes(blocks[2].into());
        x.to_ne_bytes()
    } else {
        unreachable!("Nonce extension mechanism is incompatible with that key size")
    }
}

/// Double-Nonce-Derive-Key-AES nonce extension mechanism.
///
/// Extends the lifeftime of a cipher's secret key by deriving a new key from it and a nonce.
///
/// Usage with AES-256 (Double-Nonce-Derive-Key-AES-GCM):
///
/// ```rust
/// use nonce_extension::*;
/// let key = "-------- A 256-bit key! --------";
/// let nonce = "*A random 192-bit nonce*";
/// let encryption_key = nonce_extension_aes256(key, nonce);
/// let zero_nonce = [0u8; 12];
/// // encrypt with `AES-GCM-256` using `encryption_key` and `zero_nonce`.
/// ```
///
/// The nonce can be any length up to 232 bits, but for practical purposes, 192 bits (24 bytes)
/// is recommended.
///
/// This allows the key to be reused without any practical limits on the number of messages,
/// and nonce can be generated randomly without any risk of collision.
///
/// `key`: the secret key to derive from.
/// `nonce`: the nonce to derive with.
///
/// Returns the derived key, suitable for AES-256-GCM and other AES-256 based ciphers
pub fn nonce_extension_aes256(key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> [u8; 32] {
    let key = key.as_ref();
    let nonce = nonce.as_ref();
    const KEY_LENGTH: usize = 32;
    const BLOCK_LENGTH: usize = 16;
    let nonce_length = nonce.len();

    debug_assert!(KEY_LENGTH >= BLOCK_LENGTH);
    debug_assert_eq!(KEY_LENGTH % BLOCK_LENGTH, 0);

    let key_blocks = KEY_LENGTH / BLOCK_LENGTH;

    let ks = Aes256::new(GenericArray::from_slice(key));
    if key_blocks == 2 {
        debug_assert!(nonce_length < BLOCK_LENGTH * 2);
        let z = GenericArray::from([0u8; 16]);
        let n0 = &nonce[..nonce_length / 2];
        let n1 = &nonce[nonce_length / 2..];
        let mut blocks = [z; 6];
        for i in 0..3 {
            {
                let block0 = &mut blocks[i];
                block0[..n0.len()].copy_from_slice(n0);
                block0[BLOCK_LENGTH - 1] = i as _;
            }
            {
                let block1 = &mut blocks[i + 3];
                block1[..n1.len()].copy_from_slice(n1);
                block1[BLOCK_LENGTH - 1] = i as u8 + 4;
            }
        }
        ks.encrypt_blocks(&mut blocks);
        let x0 = u128::from_ne_bytes(blocks[0].into())
            ^ u128::from_ne_bytes(blocks[1].into())
            ^ u128::from_ne_bytes(blocks[2].into());
        let x1 = u128::from_ne_bytes(blocks[3].into())
            ^ u128::from_ne_bytes(blocks[4].into())
            ^ u128::from_ne_bytes(blocks[5].into());
        let mut dk = [0u8; KEY_LENGTH];
        dk[..BLOCK_LENGTH].copy_from_slice(&x0.to_ne_bytes());
        dk[BLOCK_LENGTH..].copy_from_slice(&x1.to_ne_bytes());
        dk
    } else {
        unreachable!("Nonce extension mechanism is incompatible with that key size")
    }
}

#[test]
fn nonce_derive_aes128() {
    use ct_codecs::{Decoder, Hex};
    let nonce = Hex::decode_to_vec("0123456789abcdeffedcba98765432", None).unwrap();
    let key = Hex::decode_to_vec("0123456789abcdeffedcba9876543210", None).unwrap();
    let dk = nonce_extension_aes128(key, nonce);
    let expected_dk = Hex::decode_to_vec("5f52f039f349f01c7969019c0d19878d", None).unwrap();
    assert_eq!(&dk[..], &expected_dk);
}

#[test]
fn nonce_derive_aes256() {
    use ct_codecs::{Decoder, Hex};
    let nonce =
        Hex::decode_to_vec("0123456789abcdeffedcba987654321089abcdeffedcba98", None).unwrap();
    let key = Hex::decode_to_vec(
        "0123456789abcdeffedcba9876543210123456789abcdeffedcba9876543210f",
        None,
    )
    .unwrap();
    let dk = nonce_extension_aes256(key, nonce);
    let expected_dk = Hex::decode_to_vec(
        "545e7f545b925d46212c50e7df5ad33b8e650482a8e6476899ed6bb6f418e6d0",
        None,
    )
    .unwrap();
    assert_eq!(&dk[..], &expected_dk);
}
