//! AES-256-GCM encryption for OrchardPay's `contactAnchor` payloads.
//!
//! Unlike DashPay's ECB/CBC helpers (`src/backend_task/dashpay/encryption.rs`),
//! which key directly off an HD-derived key, this module is keyed by an
//! ECDH-derived shared secret (still produced by DashPay's existing
//! `generate_ecdh_shared_key` — reused as-is, not reimplemented). The
//! shared secret itself *is* the AES-256 key; there is no password/Argon2
//! step, since it's never entered by a user.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use bip39::rand::RngCore;
use bip39::rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// 96-bit AES-GCM nonce, per the standard AES-GCM construction.
const NONCE_SIZE: usize = 12;

/// A failure encrypting or decrypting a `contactAnchor` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrchardPayCryptoError {
    /// The AES-256-GCM cipher failed to encrypt the plaintext.
    #[error("The contact request could not be encrypted. Please try again.")]
    Encryption,
    /// The AEAD tag did not verify — wrong key or tampered ciphertext. Also
    /// returned when a document is too short to even contain a nonce.
    #[error(
        "This contact request could not be read. It may not have been intended for this identity."
    )]
    Decryption,
    /// Decryption succeeded but the plaintext bytes don't decode as a
    /// [`ContactAnchorPayload`] (or whatever type the caller expected).
    #[error("This contact request appears to be damaged and could not be read.")]
    Malformed,
}

/// Encrypt `plaintext` under a 32-byte ECDH shared secret, returning
/// `nonce (12 bytes) ‖ ciphertext-with-AEAD-tag`.
pub fn encrypt(shared_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, OrchardPayCryptoError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(shared_key).map_err(|_| OrchardPayCryptoError::Encryption)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| OrchardPayCryptoError::Encryption)?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`] under the same 32-byte shared secret.
pub fn decrypt(shared_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, OrchardPayCryptoError> {
    if data.len() < NONCE_SIZE {
        return Err(OrchardPayCryptoError::Decryption);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);

    let cipher =
        Aes256Gcm::new_from_slice(shared_key).map_err(|_| OrchardPayCryptoError::Decryption)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| OrchardPayCryptoError::Decryption)
}

/// Decrypted contents of a `contactAnchor`'s `data`/`anchorData` field. See
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Payload shape" section — only
/// `reference_id` is mandatory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContactAnchorPayload {
    pub reference_id: [u8; 32],
    /// Encrypted the same way DashPay's legacy contact-key exchange does it
    /// (`encrypt_extended_public_key` in `src/backend_task/dashpay/
    /// encryption.rs`), reused unmodified — this field carries that
    /// function's own output, not raw xpub bytes.
    pub core_payment_xpub: Option<Vec<u8>>,
    /// Design-only per the protocol doc; not populated by any code path
    /// yet, but round-trips if present.
    pub dedicated_shielded_address: Option<Vec<u8>>,
    pub initial_message: Option<Vec<u8>>,
}

impl ContactAnchorPayload {
    /// Serialize with bincode (matching `src/wallet_backend/kv.rs`'s
    /// convention), then AES-256-GCM encrypt under `shared_key`.
    pub fn encrypt(&self, shared_key: &[u8; 32]) -> Result<Vec<u8>, OrchardPayCryptoError> {
        let plaintext = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|_| OrchardPayCryptoError::Malformed)?;
        encrypt(shared_key, &plaintext)
    }

    /// Decrypt and deserialize a payload produced by [`Self::encrypt`].
    pub fn decrypt(shared_key: &[u8; 32], data: &[u8]) -> Result<Self, OrchardPayCryptoError> {
        let plaintext = decrypt(shared_key, data)?;
        let (payload, _) =
            bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())
                .map_err(|_| OrchardPayCryptoError::Malformed)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_through_encrypt_decrypt() {
        let shared_key = [7u8; 32];
        let payload = ContactAnchorPayload {
            reference_id: [1u8; 32],
            core_payment_xpub: Some(vec![2u8; 96]),
            dedicated_shielded_address: None,
            initial_message: Some(b"hi".to_vec()),
        };

        let encrypted = payload.encrypt(&shared_key).expect("encrypt succeeds");
        let decrypted =
            ContactAnchorPayload::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");

        assert_eq!(payload, decrypted);
    }

    #[test]
    fn decrypt_fails_under_wrong_key() {
        let payload = ContactAnchorPayload {
            reference_id: [1u8; 32],
            core_payment_xpub: None,
            dedicated_shielded_address: None,
            initial_message: None,
        };
        let encrypted = payload.encrypt(&[7u8; 32]).expect("encrypt succeeds");

        let result = ContactAnchorPayload::decrypt(&[8u8; 32], &encrypted);
        assert_eq!(result, Err(OrchardPayCryptoError::Decryption));
    }

    #[test]
    fn decrypt_rejects_too_short_input() {
        let result = ContactAnchorPayload::decrypt(&[7u8; 32], &[0u8; 4]);
        assert_eq!(result, Err(OrchardPayCryptoError::Decryption));
    }
}
