//! AES-256-GCM encryption for OrchardPay's `contactAnchor` and
//! `encryptedMessage` payloads.
//!
//! Different fields, different key sources, because they have different
//! readers — see `docs/orchardpay/PROTOCOL_DESIGN.md`:
//!
//! - `data` and `encryptedMessage.msgData` ([`MessageContent`]) are read by
//!   *two* parties (the owner and the counterparty), so [`ContactAnchorPayload`]
//!   and [`MessageContent`] both stay keyed by an ECDH-derived shared secret
//!   (still produced by DashPay's existing `generate_ecdh_shared_key` in
//!   `src/backend_task/dashpay/encryption.rs` — reused as-is, not
//!   reimplemented). The shared secret itself *is* the AES-256 key; there
//!   is no password/Argon2 step, since it's never entered by a user. See
//!   `backend_task::orchardpay::messages` for how a message's ECDH secret is
//!   derived from the counterparty pubkeys cached on
//!   `OrchardPayContactState::Established` — no network call needed per
//!   message.
//! - `anchorData` is read by exactly *one* party — the document's own
//!   owner, writing notes to their future self — so [`AnchorDataRecord`]
//!   uses a single fixed, wallet-local, HD-derived AES-256 key instead
//!   (`WalletBackend::orchardpay_anchor_data_key`, `m/420'/coin_type'/1'`).
//!   No ECDH, no network dependency, no exposure to the counterparty's key
//!   lifecycle. See "`anchorData`: a wallet-local recovery record" in the
//!   protocol doc for the full reasoning, including why reusing one key
//!   across every anchor is safe under AES-256-GCM at this call volume.
//!
//! All three types use the same `encrypt`/`decrypt` primitives below — only
//! the key source differs.

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

/// Decrypted contents of a `contactAnchor`'s `anchorData` field — the
/// owner's own durable, wallet-local recovery record for this relationship.
/// See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "`anchorData`: a wallet-local
/// recovery record" for the full design. Encrypted under
/// `WalletBackend::orchardpay_anchor_data_key`, never ECDH.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorDataRecord {
    /// Safe to store here in the clear (once decrypted) — this whole field
    /// is encrypted, so the top-level privacy constraint (no plaintext
    /// counterparty field on the document) is untouched.
    pub counterparty_identity_id: [u8; 32],
    /// DPNS name snapshot at the time contact was established. Not
    /// live-updated if the counterparty later renames — re-resolving on
    /// every read would reintroduce the network dependency this scheme
    /// exists to remove.
    pub counterparty_name_snapshot: Option<String>,
    /// Duplicated from this document's own `data` field, under a different
    /// key — the point is that this survives independently of whether
    /// `data` is still decryptable.
    pub my_reference_id: [u8; 32],
    /// `None` until the counterparty's return signal is decrypted.
    pub their_reference_id: Option<[u8; 32]>,
    /// Mirrors of `data`'s own optional fields — same rationale as
    /// `my_reference_id`: everything given to this contact should survive
    /// independently of the fragile ECDH path.
    pub my_initial_message: Option<Vec<u8>>,
    pub my_core_payment_xpub: Option<Vec<u8>>,
    pub my_dedicated_shielded_address: Option<Vec<u8>>,
    /// Cached ECDH *input* — the counterparty's ENCRYPTION public key
    /// bytes, not a derived shared secret. Lets a later read recompute
    /// `ECDH(my private key, this cached public key)` locally, with no
    /// network fetch, while keeping the actual shared secret out of any
    /// document. See the crypto module doc for why caching the public key
    /// instead of the secret was the deliberate choice.
    pub counterparty_encryption_pubkey: Option<Vec<u8>>,
    /// Same idea, for the other ECDH direction (encrypting messages I send
    /// them uses their DECRYPTION key).
    pub counterparty_decryption_pubkey: Option<Vec<u8>>,
}

impl AnchorDataRecord {
    /// Serialize with bincode (matching `src/wallet_backend/kv.rs`'s
    /// convention), then AES-256-GCM encrypt under the wallet's fixed
    /// `anchorData` key.
    pub fn encrypt(&self, anchor_data_key: &[u8; 32]) -> Result<Vec<u8>, OrchardPayCryptoError> {
        let plaintext = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|_| OrchardPayCryptoError::Malformed)?;
        encrypt(anchor_data_key, &plaintext)
    }

    /// Decrypt and deserialize a record produced by [`Self::encrypt`].
    pub fn decrypt(anchor_data_key: &[u8; 32], data: &[u8]) -> Result<Self, OrchardPayCryptoError> {
        let plaintext = decrypt(anchor_data_key, data)?;
        let (record, _) =
            bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())
                .map_err(|_| OrchardPayCryptoError::Malformed)?;
        Ok(record)
    }
}

/// Decrypted contents of an `encryptedMessage`'s `msgData` field. The
/// variant itself is the type tag — no separate plaintext or in-payload
/// `kind`/`type` field, so decoding is compiler-checked rather than
/// string-matched. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Message
/// content schema for the three in-scope kinds" for the full design,
/// including why `Payment`/`PaymentRequest` carry an `amount` that is never
/// trusted as authoritative on its own.
///
/// Encrypted under the relationship's ECDH shared secret — the same scheme
/// as `contactAnchor`'s `data` field, never the wallet-local `anchorData`
/// key, since a message must be readable by both parties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageContent {
    /// A plain text message. No reply-threading in this increment.
    Message { data: String },
    /// Documents a real value transfer that already happened (or, when
    /// answering a `PaymentRequest`, is implied by a bare memo-tagged
    /// transfer with no `Payment` document at all — see the protocol doc).
    /// `amount` is Platform credits, as claimed by the sender — the UI
    /// always sources the displayed amount from the recipient's own
    /// decrypted note and flags a mismatch against this field.
    Payment { amount: u64, memo: Option<String> },
    /// A standing request for payment. No transfer accompanies this by
    /// itself; no expiration field, no back-reference from `Payment` — a
    /// fulfilling transfer's on-chain memo references this document's own
    /// ID directly.
    PaymentRequest { amount: u64, memo: Option<String> },
}

impl MessageContent {
    /// Serialize with bincode (matching `src/wallet_backend/kv.rs`'s
    /// convention), then AES-256-GCM encrypt under this relationship's
    /// ECDH shared secret.
    pub fn encrypt(&self, shared_key: &[u8; 32]) -> Result<Vec<u8>, OrchardPayCryptoError> {
        let plaintext = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|_| OrchardPayCryptoError::Malformed)?;
        encrypt(shared_key, &plaintext)
    }

    /// Decrypt and deserialize a payload produced by [`Self::encrypt`].
    pub fn decrypt(shared_key: &[u8; 32], data: &[u8]) -> Result<Self, OrchardPayCryptoError> {
        let plaintext = decrypt(shared_key, data)?;
        let (content, _) =
            bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())
                .map_err(|_| OrchardPayCryptoError::Malformed)?;
        Ok(content)
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

    #[test]
    fn anchor_data_record_round_trips_through_encrypt_decrypt() {
        let anchor_data_key = [9u8; 32];
        let record = AnchorDataRecord {
            counterparty_identity_id: [3u8; 32],
            counterparty_name_snapshot: Some("bob.dash".to_string()),
            my_reference_id: [1u8; 32],
            their_reference_id: Some([2u8; 32]),
            my_initial_message: Some(b"hi".to_vec()),
            my_core_payment_xpub: Some(vec![4u8; 96]),
            my_dedicated_shielded_address: None,
            counterparty_encryption_pubkey: Some(vec![5u8; 33]),
            counterparty_decryption_pubkey: Some(vec![6u8; 33]),
        };

        let encrypted = record.encrypt(&anchor_data_key).expect("encrypt succeeds");
        let decrypted =
            AnchorDataRecord::decrypt(&anchor_data_key, &encrypted).expect("decrypt succeeds");

        assert_eq!(record, decrypted);
    }

    #[test]
    fn anchor_data_record_decrypt_fails_under_wrong_key() {
        let record = AnchorDataRecord {
            counterparty_identity_id: [3u8; 32],
            counterparty_name_snapshot: None,
            my_reference_id: [1u8; 32],
            their_reference_id: None,
            my_initial_message: None,
            my_core_payment_xpub: None,
            my_dedicated_shielded_address: None,
            counterparty_encryption_pubkey: None,
            counterparty_decryption_pubkey: None,
        };
        let encrypted = record.encrypt(&[9u8; 32]).expect("encrypt succeeds");

        let result = AnchorDataRecord::decrypt(&[10u8; 32], &encrypted);
        assert_eq!(result, Err(OrchardPayCryptoError::Decryption));
    }

    #[test]
    fn message_content_message_round_trips() {
        let shared_key = [11u8; 32];
        let content = MessageContent::Message {
            data: "hi there".to_string(),
        };

        let encrypted = content.encrypt(&shared_key).expect("encrypt succeeds");
        let decrypted = MessageContent::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");

        assert_eq!(content, decrypted);
    }

    #[test]
    fn message_content_payment_round_trips() {
        let shared_key = [12u8; 32];
        let content = MessageContent::Payment {
            amount: 100_000,
            memo: Some("for dinner".to_string()),
        };

        let encrypted = content.encrypt(&shared_key).expect("encrypt succeeds");
        let decrypted = MessageContent::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");

        assert_eq!(content, decrypted);
    }

    #[test]
    fn message_content_payment_request_round_trips() {
        let shared_key = [13u8; 32];
        let content = MessageContent::PaymentRequest {
            amount: 250_000,
            memo: None,
        };

        let encrypted = content.encrypt(&shared_key).expect("encrypt succeeds");
        let decrypted = MessageContent::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");

        assert_eq!(content, decrypted);
    }

    #[test]
    fn message_content_decrypt_fails_under_wrong_key() {
        let content = MessageContent::Message {
            data: "secret".to_string(),
        };
        let encrypted = content.encrypt(&[14u8; 32]).expect("encrypt succeeds");

        let result = MessageContent::decrypt(&[15u8; 32], &encrypted);
        assert_eq!(result, Err(OrchardPayCryptoError::Decryption));
    }
}
