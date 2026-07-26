//! Stateless data types for OrchardPay's private contact/messaging
//! protocol. See `docs/orchardpay/PROTOCOL_DESIGN.md` for the full design
//! and `src/wallet_backend/orchardpay.rs` for the k/v sidecar that persists
//! [`OrchardPayContactState`].

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

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

/// What a [`ShieldedActivityRow`] represents: a received note (still
/// spendable or already consumed) or an outgoing send recovered via OVK.
/// A typed discriminant instead of matching on the display label, since the
/// label wording is free to change (e.g. under future i18n) without
/// breaking the grouping logic in [`group_shielded_activity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedNoteKind {
    /// A note received into this wallet. `spent` is `true` once it's been
    /// consumed as an input to a later transaction this wallet created.
    Received { spent: bool },
    /// An outgoing transfer this wallet sent, recovered via OVK.
    Sent,
}

impl ShieldedNoteKind {
    /// Human-readable kind + direction, e.g. "Sent", "Received", "Received
    /// (spent)".
    pub fn label(self) -> &'static str {
        match self {
            ShieldedNoteKind::Received { spent: false } => "Received",
            ShieldedNoteKind::Received { spent: true } => "Received (spent)",
            ShieldedNoteKind::Sent => "Sent",
        }
    }
}

/// One row in the OrchardPay Shielded TXs tab's shielded transaction
/// history — a DET-native projection built directly from
/// `platform_wallet::wallet::shielded`'s raw per-note lists
/// (`ShieldedStore::get_all_notes` / `get_outgoing_notes`), one row per
/// note with no batch-based clustering — see
/// `wallet_backend::shielded::shielded_activity`'s doc comment for why
/// clustering (`derive_activity_from_scan_data`) was deliberately not used.
/// That's also where the raw memo bytes get matched against
/// `MEMO_TAG_ANCHOR` / `MEMO_TAG_PAYMENT` — this struct only ever holds the
/// already-decoded result, so it has no dependency on `backend_task`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShieldedActivityRow {
    /// What this row represents and, for a received note, whether it's
    /// still spendable.
    pub kind: ShieldedNoteKind,
    /// Amount in credits — format with
    /// `model::fee_estimation::format_credits_as_dash`.
    pub amount_credits: u64,
    /// Already-decoded memo for a Sent row ("Contact request signal",
    /// "OrchardPay payment", a truncated hex fallback for an unrecognized
    /// non-empty memo, or "No memo"). Received rows have no memo available
    /// from this data source at all — see the struct-level doc comment —
    /// so this reads "Memo not available for received notes" instead of
    /// implying there wasn't one.
    pub memo_label: String,
    /// Block height the operation confirmed at. Always `Some` for a row
    /// built from these lists — both only ever contain confirmed,
    /// on-chain-verified entries. The sole chronological signal available
    /// (no per-note wall-clock timestamp exists at this layer).
    pub block_height: Option<u64>,
    /// Whether this row is still unconfirmed. Always `false` for a row
    /// built from these lists.
    pub pending: bool,
}

/// One entry in the Shielded TXs tab's Spent Notes section: a spent
/// received note paired with the outgoing send of the same amount that
/// most likely consumed it, or an unpaired leftover on one side when no
/// same-amount partner exists.
///
/// The pairing is a best-effort amount match, not true note-level linkage
/// — this data source has no way to tell which specific outgoing
/// transaction actually consumed which specific note. When several notes
/// share an amount (e.g. repeated contact-request signals, which all move
/// the same fixed amount), entries are paired oldest-to-oldest within that
/// amount, which reads naturally as a timeline even though any single
/// pairing may not be the literal note that was spent.
#[derive(Debug, Clone, PartialEq)]
pub enum SpentEntry {
    /// A spent received note paired with a same-amount outgoing send.
    Pair {
        spent: ShieldedActivityRow,
        sent: ShieldedActivityRow,
    },
    /// A spent received note with no same-amount outgoing send left to
    /// pair it with.
    SpentOnly(ShieldedActivityRow),
    /// An outgoing send with no same-amount spent received note left to
    /// pair it with.
    SentOnly(ShieldedActivityRow),
}

/// [`ShieldedActivityRow`]s grouped for the Shielded TXs tab's two-section
/// layout — see [`group_shielded_activity`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ShieldedActivityView {
    /// Received notes not yet spent — still part of the wallet's spendable
    /// balance. Most recent first.
    pub unspent: Vec<ShieldedActivityRow>,
    /// `unspent.len()`, kept alongside the list so the UI doesn't
    /// recompute it.
    pub unspent_count: usize,
    /// Sum of `amount_credits` across `unspent`.
    pub unspent_total_credits: u64,
    /// Spent received notes and outgoing sends, paired off by matching
    /// amount where possible. Most recent first.
    pub spent: Vec<SpentEntry>,
}

/// Groups a flat shielded-activity row list into the Shielded TXs tab's
/// Unspent Notes / Spent Notes sections, pairing spent received notes with
/// same-amount outgoing sends. See [`SpentEntry`] for the pairing rules and
/// [`ShieldedActivityView`] for the result shape. Pure and deterministic —
/// no IO, no dependency on wall-clock time.
pub fn group_shielded_activity(rows: Vec<ShieldedActivityRow>) -> ShieldedActivityView {
    let mut unspent = Vec::new();
    let mut spent_received = Vec::new();
    let mut sent = Vec::new();

    for row in rows {
        match row.kind {
            ShieldedNoteKind::Received { spent: false } => unspent.push(row),
            ShieldedNoteKind::Received { spent: true } => spent_received.push(row),
            ShieldedNoteKind::Sent => sent.push(row),
        }
    }

    // Oldest-first within each amount bucket so pairing below is FIFO.
    spent_received.sort_by_key(|r| r.block_height);
    sent.sort_by_key(|r| r.block_height);

    let mut sent_by_amount: BTreeMap<u64, VecDeque<ShieldedActivityRow>> = BTreeMap::new();
    for row in sent {
        sent_by_amount
            .entry(row.amount_credits)
            .or_default()
            .push_back(row);
    }

    let mut spent_entries: Vec<SpentEntry> = Vec::new();
    for spent_row in spent_received {
        let matched = sent_by_amount
            .get_mut(&spent_row.amount_credits)
            .and_then(|queue| queue.pop_front());
        match matched {
            Some(sent_row) => spent_entries.push(SpentEntry::Pair {
                spent: spent_row,
                sent: sent_row,
            }),
            None => spent_entries.push(SpentEntry::SpentOnly(spent_row)),
        }
    }
    for (_, queue) in sent_by_amount {
        for row in queue {
            spent_entries.push(SpentEntry::SentOnly(row));
        }
    }

    // Most-recent-first, matching the flat list's prior ordering.
    spent_entries.sort_by_key(|entry| {
        std::cmp::Reverse(match entry {
            SpentEntry::Pair { spent, sent } => spent.block_height.max(sent.block_height),
            SpentEntry::SpentOnly(row) | SpentEntry::SentOnly(row) => row.block_height,
        })
    });
    unspent.sort_by_key(|r| std::cmp::Reverse(r.block_height));

    let unspent_count = unspent.len();
    let unspent_total_credits = unspent.iter().map(|r| r.amount_credits).sum();

    ShieldedActivityView {
        unspent,
        unspent_count,
        unspent_total_credits,
        spent: spent_entries,
    }
}

/// Below this identity credit balance, OrchardPay screens show an
/// informational "Low Credits" warning next to the balance readout.
/// Actions are still allowed at this level. 0.005 DASH.
pub const LOW_CREDIT_WARNING_THRESHOLD_CREDITS: u64 = 500_000_000;

/// Below this identity credit balance, OrchardPay blocks any further
/// credit-spending action (contact requests, messages, payment requests,
/// payments, publishing a shielded address) rather than let the user hit an
/// opaque insufficient-balance error from the network. 0.002 DASH.
pub const CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS: u64 = 200_000_000;

/// Whether an identity's credit balance is low enough to warrant a
/// "Low Credits" warning (informational only — see
/// [`is_credit_balance_blocked`] for the hard action-block).
pub fn is_credit_balance_low(credits: u64) -> bool {
    credits < LOW_CREDIT_WARNING_THRESHOLD_CREDITS
}

/// Whether an identity's credit balance is low enough that OrchardPay
/// should block further credit-spending actions.
pub fn is_credit_balance_blocked(credits: u64) -> bool {
    credits < CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS
}

/// Shared tooltip text for a credit-spending action disabled by
/// [`is_credit_balance_blocked`]. A single source of truth so the wording
/// stays identical across every OrchardPay screen that gates on it.
pub const CREDIT_BLOCKED_TOOLTIP: &str =
    "Identity credit balance is too low for this action. Add credits to your identity to continue.";

/// Character ceiling for a `Message`'s text. Verified against the
/// `encryptedMessage` contract's `msgData` 5120-byte ceiling
/// (`contract_schema.json`): after bincode framing and the AES-256-GCM
/// nonce/tag (~50-60 bytes total), 1000 characters is at most 4000 bytes
/// even in UTF-8's worst case (4 bytes/char, e.g. emoji or CJK) — safely
/// under budget for every script.
pub const MAX_MESSAGE_CHARS: usize = 1000;

/// Character ceiling for a `Payment`/`PaymentRequest`'s optional memo. Same
/// byte-budget reasoning as [`MAX_MESSAGE_CHARS`].
pub const MAX_PAYMENT_MEMO_CHARS: usize = 1000;

/// Validates a `Message`'s text before it's sent. A message can't be empty
/// (`min: 1`) — this subsumes the composer's old `.trim().is_empty()` check.
pub fn validate_message_text(text: &str) -> Result<(), crate::model::validation::TextLengthError> {
    crate::model::validation::validate_char_count(text, 1, MAX_MESSAGE_CHARS)
}

/// Validates a `Payment`/`PaymentRequest`'s optional memo before it's sent.
/// A memo may be empty (`min: 0`) — mirrors `model/dashpay.rs`'s
/// `validate_payment_memo`, kept as OrchardPay's own copy since DashPay is
/// legacy (`docs/ORCHARDPAY_MIGRATION.md`) and OrchardPay shouldn't depend
/// on it.
pub fn validate_payment_memo(memo: &str) -> Result<(), crate::model::validation::TextLengthError> {
    crate::model::validation::validate_char_count(memo, 0, MAX_PAYMENT_MEMO_CHARS)
}

/// Minimum amount for any OrchardPay-initiated value transfer — a real
/// `Payment`, a `PaymentRequest`'s asked-for amount, Direct Send, or the
/// contact-request anchor-signal transfer — 0.001 DASH. The single source
/// of truth for that floor: `contact_anchor::ANCHOR_SIGNAL_AMOUNT_CREDITS`
/// (Send Friend Request's default signal amount) is defined in terms of
/// this constant rather than as its own independent value, so the two
/// concepts can't silently drift apart.
pub const MIN_SEND_AMOUNT_CREDITS: u64 = 100_000_000;

/// Validates a user-entered send amount (`Payment`, `PaymentRequest`,
/// Direct Send, or an anchor-signal transfer) against
/// [`MIN_SEND_AMOUNT_CREDITS`] — the floor enforced consistently across
/// every OrchardPay value-transfer path.
pub fn validate_send_amount(
    amount_credits: u64,
) -> Result<(), crate::model::validation::AmountTooLowError> {
    crate::model::validation::validate_min_amount(amount_credits, MIN_SEND_AMOUNT_CREDITS)
}

#[cfg(test)]
mod message_validation_tests {
    use super::*;

    #[test]
    fn message_text_rejects_empty() {
        assert!(validate_message_text("").is_err());
    }

    #[test]
    fn message_text_accepts_up_to_the_limit_regardless_of_byte_width() {
        // "é" is 2 bytes in UTF-8 — confirms the check counts characters,
        // not bytes.
        assert!(validate_message_text(&"é".repeat(MAX_MESSAGE_CHARS)).is_ok());
    }

    #[test]
    fn message_text_rejects_one_over_the_limit() {
        assert!(validate_message_text(&"m".repeat(MAX_MESSAGE_CHARS + 1)).is_err());
    }

    #[test]
    fn payment_memo_accepts_empty() {
        assert!(validate_payment_memo("").is_ok());
    }

    #[test]
    fn payment_memo_accepts_up_to_the_limit_regardless_of_byte_width() {
        assert!(validate_payment_memo(&"é".repeat(MAX_PAYMENT_MEMO_CHARS)).is_ok());
    }

    #[test]
    fn payment_memo_rejects_one_over_the_limit() {
        assert!(validate_payment_memo(&"m".repeat(MAX_PAYMENT_MEMO_CHARS + 1)).is_err());
    }
}

#[cfg(test)]
mod send_amount_validation_tests {
    use super::*;

    #[test]
    fn rejects_one_credit_below_the_floor() {
        assert!(validate_send_amount(MIN_SEND_AMOUNT_CREDITS - 1).is_err());
    }

    #[test]
    fn accepts_exactly_the_floor() {
        assert!(validate_send_amount(MIN_SEND_AMOUNT_CREDITS).is_ok());
    }

    #[test]
    fn accepts_above_the_floor() {
        assert!(validate_send_amount(MIN_SEND_AMOUNT_CREDITS + 1).is_ok());
    }
}

#[cfg(test)]
mod credit_balance_threshold_tests {
    use super::*;

    #[test]
    fn low_warning_triggers_strictly_below_threshold() {
        assert!(is_credit_balance_low(
            LOW_CREDIT_WARNING_THRESHOLD_CREDITS - 1
        ));
        assert!(!is_credit_balance_low(LOW_CREDIT_WARNING_THRESHOLD_CREDITS));
        assert!(!is_credit_balance_low(
            LOW_CREDIT_WARNING_THRESHOLD_CREDITS + 1
        ));
    }

    #[test]
    fn action_block_triggers_strictly_below_threshold() {
        assert!(is_credit_balance_blocked(
            CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS - 1
        ));
        assert!(!is_credit_balance_blocked(
            CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS
        ));
        assert!(!is_credit_balance_blocked(
            CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS + 1
        ));
    }

    #[test]
    fn zero_balance_is_low_and_blocked() {
        assert!(is_credit_balance_low(0));
        assert!(is_credit_balance_blocked(0));
    }

    #[test]
    fn a_blocked_balance_is_also_low() {
        // The block threshold sitting below the warning threshold is a
        // compile-time constant, not something worth asserting on its own —
        // this instead checks the behavior that actually matters: nothing
        // can be blocked without also showing the low-credits warning.
        let just_below_block = CREDIT_ACTION_BLOCK_THRESHOLD_CREDITS - 1;
        assert!(is_credit_balance_blocked(just_below_block));
        assert!(is_credit_balance_low(just_below_block));
    }
}

#[cfg(test)]
mod shielded_activity_tests {
    use super::*;

    fn row(kind: ShieldedNoteKind, amount_credits: u64, block_height: u64) -> ShieldedActivityRow {
        ShieldedActivityRow {
            kind,
            amount_credits,
            memo_label: "No memo".to_string(),
            block_height: Some(block_height),
            pending: false,
        }
    }

    #[test]
    fn empty_input_yields_empty_view() {
        let view = group_shielded_activity(Vec::new());
        assert_eq!(view, ShieldedActivityView::default());
    }

    #[test]
    fn unspent_received_notes_go_to_unspent_section() {
        let a = row(ShieldedNoteKind::Received { spent: false }, 100, 10);
        let b = row(ShieldedNoteKind::Received { spent: false }, 200, 20);
        let view = group_shielded_activity(vec![a.clone(), b.clone()]);
        assert_eq!(view.unspent, vec![b, a]); // most recent (higher block) first
        assert_eq!(view.unspent_count, 2);
        assert_eq!(view.unspent_total_credits, 300);
        assert!(view.spent.is_empty());
    }

    #[test]
    fn spent_note_pairs_with_same_amount_send() {
        let spent = row(ShieldedNoteKind::Received { spent: true }, 100, 10);
        let sent = row(ShieldedNoteKind::Sent, 100, 12);
        let view = group_shielded_activity(vec![spent.clone(), sent.clone()]);
        assert_eq!(view.unspent_count, 0);
        assert_eq!(view.spent, vec![SpentEntry::Pair { spent, sent }]);
    }

    #[test]
    fn unpaired_spent_note_stays_in_spent_section_alone() {
        let spent = row(ShieldedNoteKind::Received { spent: true }, 100, 10);
        let view = group_shielded_activity(vec![spent.clone()]);
        assert!(view.unspent.is_empty());
        assert_eq!(view.spent, vec![SpentEntry::SpentOnly(spent)]);
    }

    #[test]
    fn unpaired_sent_note_stays_in_spent_section_alone() {
        let sent = row(ShieldedNoteKind::Sent, 100, 10);
        let view = group_shielded_activity(vec![sent.clone()]);
        assert!(view.unspent.is_empty());
        assert_eq!(view.spent, vec![SpentEntry::SentOnly(sent)]);
    }

    #[test]
    fn same_amount_notes_pair_oldest_to_oldest() {
        let spent_early = row(ShieldedNoteKind::Received { spent: true }, 100, 10);
        let spent_late = row(ShieldedNoteKind::Received { spent: true }, 100, 30);
        let sent_early = row(ShieldedNoteKind::Sent, 100, 20);
        let sent_late = row(ShieldedNoteKind::Sent, 100, 40);
        let view = group_shielded_activity(vec![
            spent_late.clone(),
            spent_early.clone(),
            sent_late.clone(),
            sent_early.clone(),
        ]);
        assert_eq!(
            view.spent,
            vec![
                // Most recent pair first: (spent_late, sent_late) was formed
                // from the later two, sorting above (spent_early, sent_early).
                SpentEntry::Pair {
                    spent: spent_late,
                    sent: sent_late,
                },
                SpentEntry::Pair {
                    spent: spent_early,
                    sent: sent_early,
                },
            ]
        );
    }

    #[test]
    fn extra_spent_notes_of_an_amount_are_left_unpaired() {
        let spent_a = row(ShieldedNoteKind::Received { spent: true }, 100, 10);
        let spent_b = row(ShieldedNoteKind::Received { spent: true }, 100, 20);
        let sent = row(ShieldedNoteKind::Sent, 100, 15);
        let view = group_shielded_activity(vec![spent_a.clone(), spent_b.clone(), sent.clone()]);
        assert_eq!(
            view.spent,
            vec![
                SpentEntry::SpentOnly(spent_b),
                SpentEntry::Pair {
                    spent: spent_a,
                    sent
                },
            ]
        );
    }

    #[test]
    fn different_amounts_never_pair() {
        let spent = row(ShieldedNoteKind::Received { spent: true }, 100, 10);
        let sent = row(ShieldedNoteKind::Sent, 200, 12);
        let view = group_shielded_activity(vec![spent.clone(), sent.clone()]);
        assert_eq!(
            view.spent,
            vec![SpentEntry::SentOnly(sent), SpentEntry::SpentOnly(spent)]
        );
    }
}
