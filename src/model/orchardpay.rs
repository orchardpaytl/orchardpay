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
    },
    /// I detected and decrypted an incoming `contactAnchor` (via a
    /// memo-tagged shielded transfer) but haven't decided to accept it yet
    /// — no anchor of my own exists for this relationship.
    PendingInboundUnaccepted {
        their_reference_id: [u8; 32],
        their_anchor_document_id: [u8; 32],
    },
    /// Both sides complete: my own anchor (published, `anchorData` filled
    /// in with their ReferenceID) and theirs are both known. Neither
    /// party's anchor document needs to be fetched again after this point.
    Established {
        my_reference_id: [u8; 32],
        my_anchor_document_id: [u8; 32],
        their_reference_id: [u8; 32],
    },
}
