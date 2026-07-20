//! Stateless data types for OrchardPay's private contact/messaging
//! protocol. See `docs/orchardpay/PROTOCOL_DESIGN.md` for the full design
//! and `src/wallet_backend/orchardpay.rs` for the k/v sidecar that persists
//! [`OrchardPayContactState`].

use serde::{Deserialize, Serialize};

/// Per-counterparty contact-establishment state, matching the phases of
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s two-anchor handshake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrchardPayContactState {
    /// I generated my own ReferenceID and published my `contactAnchor`
    /// (`anchorData` still empty), then sent the anchor-signaling shielded
    /// transfer. Waiting to detect and decrypt the counterparty's return
    /// anchor.
    PendingOutbound {
        my_reference_id: [u8; 32],
        my_anchor_document_id: [u8; 32],
        /// Counterparty's DPNS name, snapshotted at the moment the request
        /// was sent (reusing the same resolution already done for
        /// `anchorData`'s own snapshot — no extra network call). `None` if
        /// resolution failed or this relationship predates this field.
        name: Option<String>,
        /// Platform-assigned `$createdAt` (ms since epoch) of my own anchor
        /// document — i.e. when I sent this request.
        created_at: Option<u64>,
    },
    /// I detected and decrypted an incoming `contactAnchor` (via a
    /// memo-tagged shielded transfer) but haven't decided to accept it yet
    /// — no anchor of my own exists for this relationship.
    PendingInboundUnaccepted {
        their_reference_id: [u8; 32],
        their_anchor_document_id: [u8; 32],
        /// Counterparty's DPNS name, snapshotted when the request was
        /// detected. `None` if resolution failed or this relationship
        /// predates this field.
        name: Option<String>,
        /// Platform-assigned `$createdAt` (ms since epoch) of their anchor
        /// document — i.e. when their request was sent.
        created_at: Option<u64>,
    },
    /// Both sides complete: my own anchor (published, `anchorData` filled
    /// in with their ReferenceID) and theirs are both known. Neither
    /// party's anchor document needs to be fetched again after this point.
    Established {
        my_reference_id: [u8; 32],
        my_anchor_document_id: [u8; 32],
        their_reference_id: [u8; 32],
        /// Counterparty's contract-bounded ENCRYPTION/DECRYPTION public key
        /// bytes, cached at the same moment they were fetched for the
        /// `contactAnchor` handshake's ECDH secrets (mirroring
        /// `AnchorDataRecord`'s own copy of the same bytes). Reading these
        /// from local state instead of re-fetching from Platform is what
        /// makes sending/reading `encryptedMessage` documents a zero-network-call
        /// operation — see `backend_task::orchardpay::messages`.
        counterparty_encryption_pubkey: Vec<u8>,
        counterparty_decryption_pubkey: Vec<u8>,
        /// Counterparty's DPNS name, snapshotted when the relationship was
        /// established (carried forward from whichever pending phase
        /// preceded it, or resolved fresh). `None` if resolution failed or
        /// this relationship predates this field.
        name: Option<String>,
        /// Platform-assigned `$createdAt` (ms since epoch) of my own
        /// original request — preserved from the `PendingOutbound`/
        /// `PendingInboundUnaccepted` phase, not overwritten when the
        /// relationship completes.
        created_at: Option<u64>,
    },
}
