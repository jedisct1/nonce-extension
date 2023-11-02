use nonce_extension::nonce_extension_aes256;

pub mod reexports {
    pub use nonce_extension;
}
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use getrandom::getrandom;

/// A decryption error.
#[derive(Debug)]
pub struct Error;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error")
    }
}

/// Double-Nonce-Derive-Key-AES-256-GCM: AES-256-GCM with a 192-bit nonce.
///
/// ```rust
/// use xaes_gcm::*;
///
/// let key = XAes256Gcm::keygen();
/// let plaintext = b"hello world";
/// let ciphertext = XAes256Gcm::encrypt(&key, plaintext, None);
/// let decrypted = XAes256Gcm::decrypt(&key, &ciphertext, None).unwrap();
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
pub struct XAes256Gcm;

impl XAes256Gcm {
    /// Generates a random AES-256 key.
    pub fn keygen() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom(&mut key).unwrap();
        key
    }

    /// Encrypts a message with AES-256-GCM.
    /// The nonce and tag are included in the output.
    pub fn encrypt(
        key: &[u8; 32],
        plaintext: impl AsRef<[u8]>,
        associated_data: Option<&[u8]>,
    ) -> Vec<u8> {
        let plaintext = plaintext.as_ref();
        let mut nonce = [0u8; 24];
        getrandom(&mut nonce).unwrap();
        let dk = nonce_extension_aes256(key, nonce);
        let ks = Aes256Gcm::new((&dk).into());
        let mut out = Vec::with_capacity(nonce.len() + plaintext.len() + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        out.extend_from_slice(&[0u8; 16]);
        let associated_data = associated_data.unwrap_or(&[]);
        let zero_nonce = Nonce::from([0u8; 12]);
        let tag = ks
            .encrypt_in_place_detached(
                &zero_nonce,
                associated_data,
                &mut out[nonce.len()..][0..plaintext.len()],
            )
            .unwrap();
        out[nonce.len() + plaintext.len()..].copy_from_slice(tag.as_slice());
        out
    }

    /// Decrypts a message with AES-256-GCM.
    /// Returns `Err` if the ciphertext is too short or invalid.
    /// Returns the plaintext otherwise.
    pub fn decrypt(
        key: &[u8; 32],
        ciphertext: impl AsRef<[u8]>,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() < 24 + 16 {
            return Err(Error);
        }
        let nonce = &ciphertext[..24];
        let dk = nonce_extension_aes256(key, nonce);
        let ks = Aes256Gcm::new((&dk).into());
        let plaintext_len = ciphertext.len() - (24 + 16);
        let mut out = ciphertext[24..][0..plaintext_len].to_vec();
        let associated_data = associated_data.unwrap_or(&[]);
        let mut tag = Tag::default();
        tag.as_mut_slice()
            .copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
        let zero_nonce = Nonce::from([0u8; 12]);
        ks.decrypt_in_place_detached(&zero_nonce, associated_data, &mut out, &tag)
            .map_err(|_| Error)?;
        Ok(out)
    }
}

#[test]
fn test() {
    let key = XAes256Gcm::keygen();
    let plaintext = b"hello world";
    let ciphertext = XAes256Gcm::encrypt(&key, plaintext, None);
    let decrypted = XAes256Gcm::decrypt(&key, ciphertext, None).unwrap();
    assert_eq!(plaintext, &decrypted[..]);
}
