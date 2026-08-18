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
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    /// The plaintext exceeds [`MAX_MESSAGE_PLAINTEXT_LEN`] — a defensive
    /// ceiling checked before encryption, independent of (and a backstop
    /// for) the model-layer character-count validators.
    #[error("This message is too large to send.")]
    PayloadTooLarge,
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

/// Context string domain-separating the `OPP2` "silent payment" memo's
/// authentication sub-key from the raw ECDH shared secret, which every other
/// use in this module consumes directly (with no KDF step) as the AES-256
/// key. Deriving a sub-key here — rather than reusing `shared_key` itself —
/// means the MAC key can never be confused with, or leak anything about,
/// the message-encryption key for the same relationship.
const OPP2_MAC_KEY_INFO: &[u8] = b"orchardpay-opp2-mac-v1";

/// Truncated HMAC-SHA256 tag length for an `OPP2` "silent payment" memo.
/// 28 bytes (224 bits) is far beyond the ~128-bit forgery-infeasibility
/// bar, chosen so the tag fills the remainder of the 32-byte memo payload
/// alongside the 4-byte sender timestamp (4 + 28 = 32) — see
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "silent payments" section.
pub const OPP2_MAC_LEN: usize = 28;

/// Derive the sub-key used to authenticate an `OPP2` "silent payment" memo,
/// via HKDF-SHA256 over the relationship's existing ECDH shared secret (the
/// same one [`MessageContent`] encrypts under directly) with a dedicated
/// context string ([`OPP2_MAC_KEY_INFO`]). Never use `shared_key` itself as
/// a MAC key — mixing one secret across two different cryptographic
/// purposes (an AEAD key here, a MAC key there) is exactly the anti-pattern
/// this domain-separation step exists to avoid. The ECDH secret is
/// symmetric, so both established parties derive the identical sub-key
/// regardless of which side computes it.
pub fn derive_opp2_mac_key(shared_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_key);
    let mut mac_key = [0u8; 32];
    hk.expand(OPP2_MAC_KEY_INFO, &mut mac_key)
        .expect("32 is a valid HKDF-SHA256 output length");
    Zeroizing::new(mac_key)
}

/// Compute the truncated HMAC-SHA256 tag over an `OPP2` memo's 4-byte
/// sender-timestamp field, under `mac_key` (from [`derive_opp2_mac_key`]).
/// The timestamp is authenticated *content*, not decoration: a party who
/// hasn't derived this key from the real per-relationship shared secret
/// cannot produce a tag the recipient will accept for any timestamp value,
/// closing off the forgery a raw (publicly-queryable) reference-ID prefix
/// would have allowed. See `docs/orchardpay/PROTOCOL_DESIGN.md`.
pub fn compute_opp2_mac(mac_key: &[u8; 32], timestamp: u32) -> [u8; OPP2_MAC_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&timestamp.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; OPP2_MAC_LEN];
    out.copy_from_slice(&full[..OPP2_MAC_LEN]);
    out
}

/// A short (12 hex chars, 48 bits) fingerprint identifying one `OPP2`
/// "silent payment" memo, derived from its timestamp + MAC tag — used as
/// the local cache's unique key suffix
/// (`WalletBackend::orchardpay_set_silent_payment`). 48 bits comfortably
/// exceeds any realistic per-relationship payment volume before a birthday
/// collision becomes plausible, while staying short enough that the full
/// cache key (prefix + contract ID + counterparty ID + this fingerprint)
/// stays well under `platform_wallet_storage::kv::MAX_KEY_LEN` (128) — see
/// `wallet_backend::orchardpay`'s own note on that same constraint. Not a
/// security property — just a compact, practically-unique identifier for a
/// note this scan (or the sender itself) already authenticated via its MAC.
pub fn opp2_memo_fingerprint(timestamp: u32, mac: &[u8; OPP2_MAC_LEN]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.to_be_bytes());
    hasher.update(mac);
    let digest = hasher.finalize();
    hex::encode(&digest[..6])
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
    /// The payer's own durable record of a `PaymentRequest` they paid,
    /// saved only when the payer opted in via the Pay confirmation
    /// modal's "Save Receipt" checkbox. Broadcast under the *payer's own*
    /// `refId` — the same one used for every other message/payment they
    /// send in this conversation — so it rides along in the normal thread
    /// query with no separate lookup. Never itself rendered as a thread
    /// bubble; `messages::load_thread` uses it only to detect and surface
    /// an alert if `original_document_id`'s `PaymentRequest` later goes
    /// missing, changes kind, or has its amount/memo silently rewritten.
    /// Named distinctly from the still-undesigned `Receipt` variant
    /// mentioned in `docs/orchardpay/PROTOCOL_DESIGN.md` (an unrelated,
    /// mutual purchase-receipt concept).
    PaymentRequestReceipt {
        /// The `PaymentRequest` document's own ID — the correlation key
        /// back to what this receipt is about.
        original_document_id: [u8; 32],
        amount: u64,
        memo: Option<String>,
        /// The original `PaymentRequest`'s own `$createdAt`, captured at
        /// pay-time. Not needed to locate the real payment (that's already
        /// independently locatable from `original_document_id` via
        /// `orchardpay_outgoing_payments_by_document`/`MEMO_TAG_PAYMENT`)
        /// — this is purely so a surfaced alert can still be placed at the
        /// right point in the conversation's timeline even after the
        /// original document (and its own `$createdAt`) is gone.
        original_created_at: Option<u64>,
    },
}

/// Defensive ceiling on a [`MessageContent`]'s serialized plaintext, checked
/// before encryption. Every current call site already validates via
/// `validate_message_text`/`validate_payment_memo` first, so this is a
/// backstop for a future caller (an MCP tool, a bulk-import path) that might
/// construct `MessageContent` directly and skip that layer — not a limit
/// reachable through the UI today. Comfortably below Platform's
/// `max_field_value_size` (5120 bytes) once the 28-byte nonce+tag overhead
/// is added back (5000 + 28 = 5028 < 5120).
const MAX_MESSAGE_PLAINTEXT_LEN: usize = 5000;

/// Padding floor for a [`MessageContent`] payload before encryption. Small
/// structured payloads (`Payment`/`PaymentRequest`/`PaymentRequestReceipt`
/// with no memo) are padded up to this many bytes so their ciphertext
/// length can't be told apart from a short `Message` — closing a
/// size-based kind-classification side channel for an outside Platform
/// observer. 64 bytes comfortably covers all four variants' memo-less/
/// shortest form, verified against bincode 2.0.1's actual varint encoding:
/// `PaymentRequestReceipt` has the tightest natural fit at ~49 bytes
/// (its mandatory 32-byte `original_document_id` plus an
/// `original_created_at` field that always needs the largest varint
/// encoding, since a millisecond Unix timestamp already exceeds
/// `u32::MAX`). See the 2026-07-27 adversarial audit's finding 7.
///
/// No decrypt-side change is needed for this: `bincode::serde::decode_from_slice`
/// returns `(value, bytes_consumed)` and already ignores trailing bytes
/// beyond what the decoded value needs, so the padding is a pure
/// encrypt-side addition.
const MESSAGE_PADDING_FLOOR: usize = 64;

impl MessageContent {
    /// Serialize with bincode (matching `src/wallet_backend/kv.rs`'s
    /// convention), pad to [`MESSAGE_PADDING_FLOOR`], then AES-256-GCM
    /// encrypt under this relationship's ECDH shared secret.
    pub fn encrypt(&self, shared_key: &[u8; 32]) -> Result<Vec<u8>, OrchardPayCryptoError> {
        let mut plaintext = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|_| OrchardPayCryptoError::Malformed)?;
        if plaintext.len() > MAX_MESSAGE_PLAINTEXT_LEN {
            return Err(OrchardPayCryptoError::PayloadTooLarge);
        }
        plaintext.resize(plaintext.len().max(MESSAGE_PADDING_FLOOR), 0);
        encrypt(shared_key, &plaintext)
    }

    /// Decrypt and deserialize a payload produced by [`Self::encrypt`].
    /// Any padding [`Self::encrypt`] added is silently ignored — bincode
    /// only reads as many bytes as the decoded value needs.
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
    fn message_content_payment_request_receipt_round_trips() {
        let shared_key = [16u8; 32];
        let content = MessageContent::PaymentRequestReceipt {
            original_document_id: [7u8; 32],
            amount: 250_000,
            memo: Some("for dinner".to_string()),
            original_created_at: Some(1_700_000_000_000),
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

    /// Ciphertext = nonce (12) + plaintext + AEAD tag (16). Padding every
    /// short variant up to the same floor means their ciphertexts land at
    /// the same length regardless of kind — this is finding 7's actual
    /// defense, so assert it directly rather than just checking round trip.
    #[test]
    fn short_payloads_of_every_kind_pad_to_the_same_ciphertext_length() {
        let shared_key = [20u8; 32];
        let expected_len = NONCE_SIZE + MESSAGE_PADDING_FLOOR + 16;

        let message = MessageContent::Message {
            data: "hi".to_string(),
        };
        let payment = MessageContent::Payment {
            amount: 100_000,
            memo: None,
        };
        let payment_request = MessageContent::PaymentRequest {
            amount: 100_000,
            memo: None,
        };
        let receipt = MessageContent::PaymentRequestReceipt {
            original_document_id: [1u8; 32],
            amount: 100_000,
            memo: None,
            original_created_at: Some(1_700_000_000_000),
        };

        for content in [message, payment, payment_request, receipt] {
            let encrypted = content.encrypt(&shared_key).expect("encrypt succeeds");
            assert_eq!(
                encrypted.len(),
                expected_len,
                "{content:?} did not pad to the shared floor"
            );
            let decrypted =
                MessageContent::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");
            assert_eq!(content, decrypted, "padding corrupted the round trip");
        }
    }

    #[test]
    fn long_payload_is_not_truncated_by_padding_logic() {
        let shared_key = [21u8; 32];
        let content = MessageContent::Message {
            data: "m".repeat(1000),
        };

        let encrypted = content.encrypt(&shared_key).expect("encrypt succeeds");
        assert!(
            encrypted.len() > NONCE_SIZE + MESSAGE_PADDING_FLOOR + 16,
            "a long message should exceed the padding floor, not be cut down to it"
        );
        let decrypted = MessageContent::decrypt(&shared_key, &encrypted).expect("decrypt succeeds");
        assert_eq!(content, decrypted);
    }

    #[test]
    fn oversized_payload_is_rejected_before_encryption() {
        let shared_key = [22u8; 32];
        let content = MessageContent::Message {
            data: "m".repeat(MAX_MESSAGE_PLAINTEXT_LEN),
        };

        let result = content.encrypt(&shared_key);
        assert_eq!(result, Err(OrchardPayCryptoError::PayloadTooLarge));
    }

    /// The ECDH shared secret is symmetric — both established parties must
    /// derive the identical `OPP2` MAC key from it regardless of which side
    /// computes it, and the same key + timestamp must always produce the
    /// same tag (deterministic, no nonce/randomness involved).
    #[test]
    fn opp2_mac_key_and_tag_are_deterministic() {
        let shared_key = [30u8; 32];
        let mac_key_a = derive_opp2_mac_key(&shared_key);
        let mac_key_b = derive_opp2_mac_key(&shared_key);
        assert_eq!(
            *mac_key_a, *mac_key_b,
            "same shared secret must derive the same MAC key every time"
        );

        let tag_a = compute_opp2_mac(&mac_key_a, 1_700_000_000);
        let tag_b = compute_opp2_mac(&mac_key_b, 1_700_000_000);
        assert_eq!(
            tag_a, tag_b,
            "same MAC key + timestamp must always produce the same tag"
        );
    }

    /// The MAC key must not equal the raw shared secret it was derived
    /// from — domain separation is the entire point of the HKDF step.
    #[test]
    fn opp2_mac_key_differs_from_raw_shared_secret() {
        let shared_key = [31u8; 32];
        let mac_key = derive_opp2_mac_key(&shared_key);
        assert_ne!(
            *mac_key, shared_key,
            "the derived MAC key must not equal the raw shared secret"
        );
    }

    /// A different shared secret (a different relationship) must derive a
    /// different MAC key, and a different timestamp must produce a
    /// different tag under the same key — both are required for the
    /// forgery-resistance this scheme is meant to provide.
    #[test]
    fn opp2_mac_is_sensitive_to_key_and_timestamp() {
        let mac_key_1 = derive_opp2_mac_key(&[32u8; 32]);
        let mac_key_2 = derive_opp2_mac_key(&[33u8; 32]);
        assert_ne!(
            *mac_key_1, *mac_key_2,
            "different shared secrets must derive different MAC keys"
        );

        let tag_same_key_diff_time_a = compute_opp2_mac(&mac_key_1, 1_700_000_000);
        let tag_same_key_diff_time_b = compute_opp2_mac(&mac_key_1, 1_700_000_001);
        assert_ne!(
            tag_same_key_diff_time_a, tag_same_key_diff_time_b,
            "different timestamps under the same key must produce different tags"
        );

        let tag_diff_key_same_time = compute_opp2_mac(&mac_key_2, 1_700_000_000);
        assert_ne!(
            tag_same_key_diff_time_a, tag_diff_key_same_time,
            "different keys must produce different tags for the same timestamp"
        );
    }

    #[test]
    fn opp2_memo_fingerprint_is_deterministic_and_sensitive_to_input() {
        let mac = [1u8; OPP2_MAC_LEN];
        let fp_a = opp2_memo_fingerprint(1_700_000_000, &mac);
        let fp_b = opp2_memo_fingerprint(1_700_000_000, &mac);
        assert_eq!(fp_a, fp_b, "same input must fingerprint identically");
        assert_eq!(fp_a.len(), 12, "fingerprint must be 12 hex chars (48 bits)");

        let fp_diff_time = opp2_memo_fingerprint(1_700_000_001, &mac);
        assert_ne!(
            fp_a, fp_diff_time,
            "a different timestamp must change the fingerprint"
        );

        let other_mac = [2u8; OPP2_MAC_LEN];
        let fp_diff_mac = opp2_memo_fingerprint(1_700_000_000, &other_mac);
        assert_ne!(
            fp_a, fp_diff_mac,
            "a different MAC must change the fingerprint"
        );
    }
}
