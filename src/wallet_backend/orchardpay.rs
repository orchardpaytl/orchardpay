//! OrchardPay adapter for `WalletBackend` — the k/v sidecar backing local
//! contact-establishment state.
//!
//! Unlike DashPay (`wallet_backend/dashpay.rs`), OrchardPay has no upstream
//! `ManagedIdentity` model to overlay: `contactAnchor` is a brand-new
//! Platform document type upstream knows nothing about. So *all* of
//! OrchardPay's local contact state lives here, in the per-network k/v
//! sidecar (`src/wallet_backend/kv.rs`), scoped per acting identity
//! (`DetScope::Identity`) so it cascades correctly when an identity is
//! removed and never bleeds across identities sharing a wallet.
//!
//! See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Two anchors per
//! relationship" for the protocol this state machine tracks, and
//! `docs/ai-design/2026-07-18-orchardpay-memo-detection/` for why a
//! memo-scan resume cursor lives here too.

use dash_sdk::Sdk;
use dash_sdk::dpp::dashcore::Network;
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::Identifier;
use dash_sdk::platform::shielded::{sync_shielded_notes_stream, try_decrypt_note_with_memo};
use futures::StreamExt;
use platform_wallet::wallet::shielded::OrchardKeySet;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::MEMO_TAG_ANCHOR;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::messages::MEMO_TAG_PAYMENT;
use crate::model::orchardpay::{
    OrchardPayContactState, PendingOrchardPayOperation, ScheduledAnchorReplace,
};
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::{DetScope, WalletBackend};

/// Fixed MMR chunk size shielded note stream positions align to —
/// `rs-drive`'s `SHIELDED_NOTES_CHUNK_POWER = 11`, i.e. `1 << 11`. A stable,
/// versioned Platform protocol constant (not something DET can reach via a
/// public SDK path — `dash_sdk` doesn't re-export it), used by
/// `WalletBackend::orchardpay_recover_received_memos` to compute which
/// aligned chunk a given note position falls in.
const SHIELDED_NOTES_CHUNK_ALIGNMENT: u64 = 2048;

/// One recognized signal found by the incoming-memo scan — either half of
/// the `contactAnchor` handshake, or a [`MEMO_TAG_PAYMENT`]-tagged real
/// value transfer (an unprompted `Payment` document, or a bare fulfillment
/// of a `PaymentRequest`). See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
/// "Message content schema for the three in-scope kinds" for the payment
/// half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingMemoSignal {
    Anchor(Identifier),
    Payment {
        /// The `Payment` or `PaymentRequest` document this transfer's memo
        /// referenced.
        referenced_document_id: Identifier,
        /// The real value observed on this wallet's own decrypted note —
        /// the authoritative amount, cached for `messages::load_thread` to
        /// compare against whatever the document itself claims.
        received_amount_credits: u64,
    },
}

/// Derive OrchardPay's single, wallet-wide `anchorData` encryption key at
/// `m/420'/coin_type'/1'` — see `docs/orchardpay/PROTOCOL_DESIGN.md`'s
/// "`anchorData`: a wallet-local recovery record" for the full design.
/// One key for the whole wallet, shared across every identity it manages —
/// not identity-scoped, not per-relationship, not ECDH. Pure and
/// deterministic: the same seed always re-derives the identical key, which
/// is exactly what makes `anchorData` recoverable independent of any
/// on-chain identity key state.
///
/// `420'` is a deliberately claimed, currently-unregistered top-level BIP43
/// purpose — every other feature in this wallet's tree instead nests under
/// the existing DIP-9 `9'` umbrella (see `key-wallet/src/dip9.rs`). Chosen
/// anyway as a forward-looking bet on a future DIP reservation; see the
/// design doc for the accepted-risk reasoning.
fn derive_anchor_data_key(
    seed_bytes: &[u8; 64],
    network: Network,
) -> Result<Zeroizing<[u8; 32]>, TaskError> {
    use dash_sdk::dpp::key_wallet::bip32::{DerivationPath, ExtendedPrivKey};
    use std::str::FromStr;

    let derive_err =
        |e: dash_sdk::dpp::key_wallet::bip32::Error| TaskError::AnchorDataKeyDerivationFailed {
            source: Box::new(e),
        };

    let master_xprv = ExtendedPrivKey::new_master(network, seed_bytes).map_err(derive_err)?;

    let coin_type = crate::model::wallet::coin_type_for_network(network);
    let path = DerivationPath::from_str(&format!("m/420'/{coin_type}'/1'")).map_err(derive_err)?;

    let secp = dash_sdk::dpp::dashcore::secp256k1::Secp256k1::new();
    let derived = master_xprv.derive_priv(&secp, &path).map_err(derive_err)?;

    Ok(Zeroizing::new(derived.private_key.secret_bytes()))
}

/// How many `key_index` candidates to try when finding a free slot or
/// recovering an already-registered OrchardPay key purely from the seed.
/// Matches `AUTH_KEY_LOOKUP_WINDOW` in
/// `src/backend_task/identity/{load_identity_from_wallet,discover_identities}.rs`
/// — the existing, proven gap-limit size for this same per-identity key
/// slot mechanism, reused here rather than invented fresh. See
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "HD-deriving the
/// ENCRYPTION/DECRYPTION identity keys".
const ORCHARDPAY_KEY_INDEX_WINDOW: u32 = 12;

/// Derive one `(identity_index, key_index)` candidate under DIP-13's generic
/// per-identity key slot (`identity_authentication_path` — the
/// "authentication" in the name is a holdover from its first use case, not a
/// restriction; every one of DashPay's own identity keys, including its
/// ENCRYPTION/DECRYPTION pair, already derives through this same path with
/// only `key_index` varying — see the design doc section above). Returns
/// the compressed public key bytes (Platform's own encoding for an
/// ECDSA_SECP256K1 identity key) alongside the raw private key.
fn derive_identity_key_candidate(
    seed: &[u8],
    network: Network,
    identity_index: u32,
    key_index: u32,
) -> Result<([u8; 33], [u8; 32]), TaskError> {
    use dash_sdk::dpp::dashcore::PublicKey as CorePublicKey;
    use dash_sdk::dpp::dashcore::secp256k1::Secp256k1;
    use dash_sdk::dpp::key_wallet::bip32::{DerivationPath, KeyDerivationType};

    let path = DerivationPath::identity_authentication_path(
        network,
        KeyDerivationType::ECDSA,
        identity_index,
        key_index,
    );
    let extended = path
        .derive_priv_ecdsa_for_master_seed(seed, network)
        .map_err(|e| TaskError::WalletKeyDerivationFailed { source: e.into() })?;

    let secp = Secp256k1::new();
    let public_key = CorePublicKey::new(extended.private_key.public_key(&secp));
    let public_key_bytes: [u8; 33] = public_key
        .to_bytes()
        .try_into()
        .expect("compressed secp256k1 public key is always 33 bytes");

    Ok((public_key_bytes, extended.private_key.secret_bytes()))
}

/// Value: bincode-encoded [`OrchardPayContactState`]. Scope:
/// [`DetScope::Identity`] of the owner — per-relationship state is private
/// to the acting identity and cascades on identity removal. Key shape:
/// `det:orchardpay:contact:<contract_id_b58>:<counterparty_b58>` — scoped by
/// the current OrchardPay contract ID, not just the counterparty. Without
/// this, a contract re-registration (a fresh contract ID — Platform
/// disallows removing/altering indices via a contract *update*, so a
/// breaking schema change ships as a brand-new contract, see
/// `docs/orchardpay/PROTOCOL_DESIGN.md`) would leave stale `Established`/
/// `Pending*` records pointing at anchor/message documents that live under
/// the *retired* contract ID, but still read back as valid under the new
/// one — silently mis-scoping every query built from them (empty threads,
/// or a permanently-stuck pending handshake) instead of erroring. Scoping
/// the key itself by contract ID makes a stale entry simply invisible once
/// the contract ID changes, with no explicit migration step required.
const KV_PREFIX_CONTACT: &str = "det:orchardpay:contact:";

/// Presence marker: resume cursor for the DET-side incoming-memo scan (see
/// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`). Value: `u64`,
/// the last chunk-aligned `start_index` fully scanned. Scope:
/// [`DetScope::Wallet`] — the scan is genuinely wallet-level (the Orchard
/// IVK it re-derives comes from the wallet seed, account 0, not from any one
/// identity), so the cursor lives per-wallet rather than per-identity even
/// though the anchors it finds get handed off to individual identities.
const KV_PREFIX_MEMO_SCAN_CURSOR: &str = "det:orchardpay:memo_scan_cursor";

/// Value: `u64`, the real credits value this wallet observed on a
/// [`MEMO_TAG_PAYMENT`](crate::backend_task::orchardpay::messages::MEMO_TAG_PAYMENT)-tagged
/// incoming shielded note, keyed by the DocumentID the memo referenced
/// (either a `Payment` document, or a `PaymentRequest` being fulfilled by a
/// bare transfer). Written once by the incoming-memo scan, at the point
/// where the real decrypted `Note` value is actually in hand — re-deriving
/// it later would mean re-walking the note stream. Read by
/// `messages::load_thread` to source the UI's authoritative displayed
/// amount and flag a mismatch against the document's claimed `amount`. Only
/// ever written for notes addressed *to* this wallet — a payment I sent
/// needs no verification, since I chose the real amount myself. Scope:
/// [`DetScope::Wallet`], matching [`KV_PREFIX_MEMO_SCAN_CURSOR`]'s own
/// wallet-level (not identity-level) reasoning.
const KV_PREFIX_VERIFIED_PAYMENT: &str = "det:orchardpay:verified_payment:";

/// Presence marker: this identity's `shieldedAddress` document has been
/// confirmed to exist on Platform. Value: `bool`, always `true` when
/// present — there is deliberately no cached `false`. Caching "confirmed
/// absent" would go stale the moment the identity actually publishes (from
/// this device or another), and unlike the positive case there is no
/// write-through moment to refresh it; the live check that would otherwise
/// discover a *new* publish is exactly what a cached negative would
/// suppress. A cached positive can't go stale the same way in the absence
/// of a "delete my shielded address" flow (none exists today). Written by
/// the `CheckOwnShieldedAddress` task on a positive result and by
/// `publish_own_shielded_address` on success, so the next launch/visit
/// knows instantly instead of re-querying Platform. Scope:
/// [`DetScope::Identity`] of the owner. Key shape:
/// `det:orchardpay:has_shielded_address:<contract_id_b58>` — scoped by
/// contract ID for the same reason as [`KV_PREFIX_CONTACT`]: the
/// `shieldedAddress` document this flag caches "confirmed" lives under one
/// specific contract, so a cached `true` from a retired contract must not
/// suppress the live check (and therefore the republish) needed under a
/// freshly re-registered one.
const KV_PREFIX_HAS_SHIELDED_ADDRESS: &str = "det:orchardpay:has_shielded_address";

/// Value: `bool` (always `true` when present). An incoming `Anchor` signal
/// (a `contactAnchor` document ID) that decrypted successfully from this
/// wallet's shielded note stream but didn't match any identity loaded at
/// the time — see `backend_task::orchardpay::memo_scan::scan_for_incoming_anchors`.
/// Persisted so a later-loaded identity (or one that has since set up
/// OrchardPay) can be tried against it without re-walking or re-decrypting
/// the note stream: the decrypt pass is genuinely wallet-level, keyed off
/// the single wallet-wide Orchard viewing key (see
/// [`WalletBackend::orchardpay_scan_incoming_memos`]), so the note itself
/// never needs re-visiting once its signal is known — only the
/// identity-match step (`handle_incoming_anchor_signal`) needs retrying.
/// Cleared once some identity successfully claims it. Scope:
/// [`DetScope::Wallet`], matching [`KV_PREFIX_MEMO_SCAN_CURSOR`]'s own
/// wallet-level reasoning. Key shape:
/// `det:orchardpay:unresolved_anchor:<document_id_b58>`.
const KV_PREFIX_UNRESOLVED_ANCHOR: &str = "det:orchardpay:unresolved_anchor:";

/// Value: `u32`, the number of consecutive scan passes a specific note
/// position has failed to process (a genuine processing error, not a clean
/// "not for this identity" — see `scan_for_incoming_anchors`'s `had_error`
/// path). Once this reaches [`MEMO_SCAN_ERROR_RETRY_CAP`], the scan stops
/// holding the resume cursor back for that note, so one persistently-failing
/// signal can no longer wedge every later signal behind it forever. Scope:
/// [`DetScope::Wallet`]. Key shape:
/// `det:orchardpay:memo_scan_retry_count:<note_index>`.
const KV_PREFIX_MEMO_SCAN_RETRY_COUNT: &str = "det:orchardpay:memo_scan_retry_count:";

/// How many consecutive processing failures a single note position
/// tolerates before the scan gives up holding the cursor back for it. See
/// [`KV_PREFIX_MEMO_SCAN_RETRY_COUNT`].
pub const MEMO_SCAN_ERROR_RETRY_CAP: u32 = 5;

/// Value: bincode-encoded [`PendingOrchardPayOperation`]. A local, resumable
/// marker for an in-flight `initiate_contact`/`accept_contact`/`send_payment`
/// call, written *before* the first network side effect so a crash or a
/// failed transfer never leaves an orphaned duplicate Platform document
/// behind on retry — see M-02 of
/// `docs/ai-design/2026-07-26-m02-atomic-contact-payment-flows/README.md`.
/// Cleared once the operation reaches a consistent end state. Scope:
/// [`DetScope::Identity`] of the owner, matching [`KV_PREFIX_CONTACT`]'s own
/// reasoning (per-relationship state, private to the acting identity,
/// cascades on identity removal, and contract-ID-scoped for the same
/// stale-across-migration reason). Key shape:
/// `det:orchardpay:pending_op:<contract_id_b58>:<counterparty_b58>`.
const KV_PREFIX_PENDING_OPERATION: &str = "det:orchardpay:pending_op:";

/// Value: bincode-encoded `ScheduledAnchorReplace`. A local marker for a
/// `contactAnchor`'s deferred `anchorData` replace — see the 2026-07-27
/// adversarial audit's finding 5 (the pending-vs-established pairing-signal
/// mitigation). Deliberately **not** stored under [`KV_PREFIX_PENDING_OPERATION`]:
/// that key is a single overwrite-only slot shared with contact-anchor
/// creation and M-02's atomic payment-flow marker, and this scheduling
/// marker can legitimately need to sit for up to ~10 hours — long enough
/// that an unrelated in-flight `Payment`/`PaymentRequest` to the same
/// counterparty would otherwise clobber it (or be clobbered by it). Scope:
/// [`DetScope::Identity`] of the owner, matching [`KV_PREFIX_PENDING_OPERATION`]'s
/// own reasoning (per-relationship, private to the acting identity, cascades
/// on identity removal, contract-ID-scoped). Key shape:
/// `det:orchardpay:anchor_replace:<contract_id_b58>:<counterparty_b58>`.
///
/// The prefix is deliberately short: a 32-byte `Identifier` base58-encodes to
/// up to 44 chars (the common case, not an edge case), so this key already
/// carries `<44 chars>:<44 chars>` = 89 chars before the prefix. A prefix
/// longer than ~39 chars pushes the worst case past the upstream
/// [`platform_wallet_storage::kv::MAX_KEY_LEN`] of 128 — this happened for
/// real with the original `det:orchardpay:scheduled_anchor_replace:` prefix
/// (40 chars, worst case 129, `KvError::KeyTooLong`). See the
/// `*_key_stays_within_kv_max_len` test below.
const KV_PREFIX_SCHEDULED_ANCHOR_REPLACE: &str = "det:orchardpay:anchor_replace:";

fn contact_key(contract_id: &Identifier, counterparty: &Identifier) -> String {
    format!(
        "{KV_PREFIX_CONTACT}{}:{}",
        contract_id.to_string(Encoding::Base58),
        counterparty.to_string(Encoding::Base58)
    )
}

fn contact_key_prefix(contract_id: &Identifier) -> String {
    format!(
        "{KV_PREFIX_CONTACT}{}:",
        contract_id.to_string(Encoding::Base58)
    )
}

fn has_shielded_address_key(contract_id: &Identifier) -> String {
    format!(
        "{KV_PREFIX_HAS_SHIELDED_ADDRESS}:{}",
        contract_id.to_string(Encoding::Base58)
    )
}

fn verified_payment_key(document_id: &Identifier) -> String {
    format!(
        "{KV_PREFIX_VERIFIED_PAYMENT}{}",
        document_id.to_string(Encoding::Base58)
    )
}

fn unresolved_anchor_key(anchor_document_id: &Identifier) -> String {
    format!(
        "{KV_PREFIX_UNRESOLVED_ANCHOR}{}",
        anchor_document_id.to_string(Encoding::Base58)
    )
}

fn memo_scan_retry_count_key(note_index: u64) -> String {
    format!("{KV_PREFIX_MEMO_SCAN_RETRY_COUNT}{note_index}")
}

fn pending_operation_key(contract_id: &Identifier, counterparty: &Identifier) -> String {
    format!(
        "{KV_PREFIX_PENDING_OPERATION}{}:{}",
        contract_id.to_string(Encoding::Base58),
        counterparty.to_string(Encoding::Base58)
    )
}

fn scheduled_anchor_replace_key(contract_id: &Identifier, counterparty: &Identifier) -> String {
    format!(
        "{KV_PREFIX_SCHEDULED_ANCHOR_REPLACE}{}:{}",
        contract_id.to_string(Encoding::Base58),
        counterparty.to_string(Encoding::Base58)
    )
}

impl WalletBackend {
    /// Read the local contact-establishment state for `(contract_id, owner,
    /// counterparty)`. `Ok(None)` means no relationship has been started
    /// under this contract — callers should treat this as "not a contact
    /// yet." See [`KV_PREFIX_CONTACT`] for why this is contract-scoped.
    pub fn orchardpay_get_contact_state(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<Option<OrchardPayContactState>, TaskError> {
        let owner_buf = owner.to_buffer();
        let key = contact_key(contract_id, counterparty);
        self.kv()
            .get::<OrchardPayContactState>(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Upsert the local contact-establishment state for `(contract_id, owner,
    /// counterparty)`.
    pub fn orchardpay_set_contact_state(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
        state: &OrchardPayContactState,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = contact_key(contract_id, counterparty);
        self.kv()
            .put::<OrchardPayContactState>(DetScope::Identity(&owner_buf), &key, state)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Read the local resumable marker for an in-flight publish-then-transfer
    /// operation with `counterparty` under `contract_id`, if one exists.
    /// `Ok(None)` means no operation is in flight — callers should treat
    /// this as "safe to start fresh." See [`KV_PREFIX_PENDING_OPERATION`].
    pub fn orchardpay_get_pending_operation(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<Option<PendingOrchardPayOperation>, TaskError> {
        let owner_buf = owner.to_buffer();
        let key = pending_operation_key(contract_id, counterparty);
        self.kv()
            .get::<PendingOrchardPayOperation>(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Upsert the local resumable marker for an in-flight operation with
    /// `counterparty` under `contract_id`.
    pub fn orchardpay_set_pending_operation(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
        operation: &PendingOrchardPayOperation,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = pending_operation_key(contract_id, counterparty);
        self.kv()
            .put::<PendingOrchardPayOperation>(DetScope::Identity(&owner_buf), &key, operation)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Clear the local pending-operation marker for `counterparty` under
    /// `contract_id` — called once the operation reaches a consistent end
    /// state (local contact state written, or a payment transfer
    /// confirmed).
    pub fn orchardpay_clear_pending_operation(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = pending_operation_key(contract_id, counterparty);
        self.kv()
            .delete(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Read the local scheduling marker for `counterparty` under
    /// `contract_id`'s deferred `contactAnchor` replace, if one exists.
    /// `Ok(None)` means either no replace is scheduled, or it already fired
    /// and was cleared. See [`KV_PREFIX_SCHEDULED_ANCHOR_REPLACE`].
    pub fn orchardpay_get_scheduled_anchor_replace(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<Option<ScheduledAnchorReplace>, TaskError> {
        let owner_buf = owner.to_buffer();
        let key = scheduled_anchor_replace_key(contract_id, counterparty);
        self.kv()
            .get::<ScheduledAnchorReplace>(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Upsert the local scheduling marker for `counterparty` under
    /// `contract_id`'s deferred `contactAnchor` replace.
    pub fn orchardpay_set_scheduled_anchor_replace(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
        marker: &ScheduledAnchorReplace,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = scheduled_anchor_replace_key(contract_id, counterparty);
        self.kv()
            .put::<ScheduledAnchorReplace>(DetScope::Identity(&owner_buf), &key, marker)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Clear the local scheduling marker for `counterparty` under
    /// `contract_id` — called once the deferred replace has actually fired.
    pub fn orchardpay_clear_scheduled_anchor_replace(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = scheduled_anchor_replace_key(contract_id, counterparty);
        self.kv()
            .delete(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Read the locally cached "has this identity published a
    /// `shieldedAddress`" flag under `contract_id`. `Ok(None)` means never
    /// confirmed locally yet — callers should do a live Platform check.
    /// There is no cached `false`; see [`KV_PREFIX_HAS_SHIELDED_ADDRESS`]'s
    /// doc comment for why.
    pub fn orchardpay_get_has_shielded_address(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
    ) -> Result<Option<bool>, TaskError> {
        let owner_buf = owner.to_buffer();
        let key = has_shielded_address_key(contract_id);
        self.kv()
            .get::<bool>(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Persist that `owner` has a confirmed published `shieldedAddress`
    /// document under `contract_id`, so later launches/visits know instantly
    /// instead of re-querying Platform.
    pub fn orchardpay_set_has_shielded_address(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = has_shielded_address_key(contract_id);
        self.kv()
            .put::<bool>(DetScope::Identity(&owner_buf), &key, &true)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// List every counterparty identity `owner` has a local contact-state
    /// record for under `contract_id`, regardless of phase (pending
    /// outbound, pending inbound, or established).
    pub fn orchardpay_list_contacts(
        &self,
        contract_id: &Identifier,
        owner: &Identifier,
    ) -> Result<Vec<Identifier>, TaskError> {
        let owner_buf = owner.to_buffer();
        let prefix = contact_key_prefix(contract_id);
        let keys = self
            .kv()
            .list(DetScope::Identity(&owner_buf), Some(&prefix))
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        Ok(keys
            .into_iter()
            .filter_map(|key| {
                let b58 = key.strip_prefix(&prefix)?;
                Identifier::from_string(b58, Encoding::Base58).ok()
            })
            .collect())
    }

    /// Read the DET-side incoming-memo scan's resume cursor for the wallet
    /// identified by `seed_hash`. `Ok(None)` means no pass has completed
    /// yet — scan from `start_index = 0`.
    pub fn orchardpay_get_memo_scan_cursor(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<Option<u64>, TaskError> {
        self.kv()
            .get::<u64>(DetScope::Wallet(seed_hash), KV_PREFIX_MEMO_SCAN_CURSOR)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Persist the DET-side incoming-memo scan's resume cursor for the
    /// wallet identified by `seed_hash`.
    pub fn orchardpay_set_memo_scan_cursor(
        &self,
        seed_hash: &WalletSeedHash,
        next_start_index: u64,
    ) -> Result<(), TaskError> {
        self.kv()
            .put::<u64>(
                DetScope::Wallet(seed_hash),
                KV_PREFIX_MEMO_SCAN_CURSOR,
                &next_start_index,
            )
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// List every incoming `Anchor` signal that decrypted successfully but
    /// hasn't matched any identity yet — candidates to retry the next time a
    /// scan pass runs (e.g. after a new identity is loaded). See
    /// [`KV_PREFIX_UNRESOLVED_ANCHOR`].
    pub fn orchardpay_list_unresolved_anchor_signals(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<Vec<Identifier>, TaskError> {
        let keys = self
            .kv()
            .list(
                DetScope::Wallet(seed_hash),
                Some(KV_PREFIX_UNRESOLVED_ANCHOR),
            )
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        Ok(keys
            .into_iter()
            .filter_map(|key| {
                let b58 = key.strip_prefix(KV_PREFIX_UNRESOLVED_ANCHOR)?;
                Identifier::from_string(b58, Encoding::Base58).ok()
            })
            .collect())
    }

    /// Persist that `anchor_document_id` didn't match any currently-loaded
    /// identity, so a future scan pass can retry it without re-decrypting
    /// the note that carried it.
    pub fn orchardpay_record_unresolved_anchor_signal(
        &self,
        seed_hash: &WalletSeedHash,
        anchor_document_id: &Identifier,
    ) -> Result<(), TaskError> {
        let key = unresolved_anchor_key(anchor_document_id);
        self.kv()
            .put::<bool>(DetScope::Wallet(seed_hash), &key, &true)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Clear a previously-unresolved anchor signal once some identity has
    /// successfully claimed it.
    pub fn orchardpay_clear_unresolved_anchor_signal(
        &self,
        seed_hash: &WalletSeedHash,
        anchor_document_id: &Identifier,
    ) -> Result<(), TaskError> {
        let key = unresolved_anchor_key(anchor_document_id);
        self.kv()
            .delete(DetScope::Wallet(seed_hash), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Read the current processing-failure count for a specific note
    /// position (`0` if never recorded). See
    /// [`KV_PREFIX_MEMO_SCAN_RETRY_COUNT`].
    pub fn orchardpay_get_memo_scan_retry_count(
        &self,
        seed_hash: &WalletSeedHash,
        note_index: u64,
    ) -> Result<u32, TaskError> {
        let key = memo_scan_retry_count_key(note_index);
        Ok(self
            .kv()
            .get::<u32>(DetScope::Wallet(seed_hash), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?
            .unwrap_or(0))
    }

    /// Increment and persist the processing-failure count for a specific
    /// note position, returning the new count.
    pub fn orchardpay_increment_memo_scan_retry_count(
        &self,
        seed_hash: &WalletSeedHash,
        note_index: u64,
    ) -> Result<u32, TaskError> {
        let count = self.orchardpay_get_memo_scan_retry_count(seed_hash, note_index)? + 1;
        let key = memo_scan_retry_count_key(note_index);
        self.kv()
            .put::<u32>(DetScope::Wallet(seed_hash), &key, &count)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
        Ok(count)
    }

    /// Clear a note position's processing-failure count once it's finally
    /// resolved (successfully applied, or quarantined past the retry cap).
    pub fn orchardpay_clear_memo_scan_retry_count(
        &self,
        seed_hash: &WalletSeedHash,
        note_index: u64,
    ) -> Result<(), TaskError> {
        let key = memo_scan_retry_count_key(note_index);
        self.kv()
            .delete(DetScope::Wallet(seed_hash), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Read the real credits value this wallet has confirmed for a
    /// `MEMO_TAG_PAYMENT` signal referencing `document_id` — written by
    /// either of two callers, depending on which side of the transfer this
    /// wallet is on: the incoming-memo scan (a fulfillment transfer this
    /// wallet *received*, i.e. it made the original `PaymentRequest`), or
    /// `messages::send_payment`'s own optimistic post-broadcast record (a
    /// fulfillment this wallet *sent*, i.e. it's paying someone else's
    /// request). `Ok(None)` means neither has happened yet for this wallet
    /// — see `WalletBackend::orchardpay_outgoing_payments_by_document` for
    /// the chain-derived fallback that survives this local cache being
    /// wiped.
    pub fn orchardpay_get_verified_payment_amount(
        &self,
        seed_hash: &WalletSeedHash,
        document_id: &Identifier,
    ) -> Result<Option<u64>, TaskError> {
        let key = verified_payment_key(document_id);
        self.kv()
            .get::<u64>(DetScope::Wallet(seed_hash), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Persist the real credits value confirmed for a `MEMO_TAG_PAYMENT`
    /// signal referencing `document_id`. Two call sites, per
    /// [`Self::orchardpay_get_verified_payment_amount`]'s doc comment: the
    /// incoming-memo scan (received a fulfillment) and
    /// `messages::send_payment` (sent one).
    pub fn orchardpay_set_verified_payment_amount(
        &self,
        seed_hash: &WalletSeedHash,
        document_id: &Identifier,
        amount: u64,
    ) -> Result<(), TaskError> {
        let key = verified_payment_key(document_id);
        self.kv()
            .put::<u64>(DetScope::Wallet(seed_hash), &key, &amount)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Drop every OrchardPay sidecar entry for `owner` — the per-counterparty
    /// contact-state records, the pending-operation recovery markers, and
    /// the cached "has published a shieldedAddress" flag. Mirrors
    /// `dashpay_clear_owner_overlays` for the network-clear path. The
    /// memo-scan cursor and verified-payment cache are wallet-scoped, not
    /// owner-scoped, so neither is covered here — see
    /// [`Self::orchardpay_clear_wallet_overlays`], called from wallet
    /// removal instead of identity removal.
    pub fn orchardpay_clear_owner_overlays(&self, owner: &Identifier) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let scope = DetScope::Identity(&owner_buf);
        let kv = self.kv();

        // Bare (contract-agnostic) prefixes deliberately used here, unlike
        // the per-contract accessors above: identity removal must wipe
        // every contract-scoped entry for this owner, not just the one
        // matching the currently-configured contract ID.
        for prefix in [
            KV_PREFIX_CONTACT,
            KV_PREFIX_PENDING_OPERATION,
            KV_PREFIX_HAS_SHIELDED_ADDRESS,
            KV_PREFIX_SCHEDULED_ANCHOR_REPLACE,
        ] {
            let keys = kv
                .list(scope, Some(prefix))
                .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
            for key in keys {
                kv.delete(scope, &key)
                    .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
            }
        }

        Ok(())
    }

    /// Drop every OrchardPay wallet-scoped sidecar entry for `seed_hash` —
    /// the memo-scan resume cursor, the verified-incoming-payment cache, the
    /// unresolved-anchor-signal list, and the per-note retry-failure
    /// counters. Called from `WalletBackend::forget_wallet_local_state`, not
    /// the per-identity network-clear sweep above: all four are
    /// [`DetScope::Wallet`], and — contrary to an earlier, unverified
    /// assumption in this module — nothing about that scope actually
    /// cascades on wallet removal; `det-app.sqlite` (where this k/v store
    /// lives) has no foreign-key relationship to the upstream persistor's
    /// wallet table, so an explicit sweep is required or these rows orphan
    /// permanently. Not a secret-bearing-state gap: every value here is
    /// non-secret (a resume index; a public credits amount keyed by a
    /// public document ID; a public anchor document ID; a retry count) —
    /// the seed/session/wallet-meta deletes that already run during wallet
    /// removal satisfy the actual "no secrets survive" guarantee. This is
    /// storage hygiene, not hardening.
    pub fn orchardpay_clear_wallet_overlays(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<(), TaskError> {
        let scope = DetScope::Wallet(seed_hash);
        let kv = self.kv();

        kv.delete(scope, KV_PREFIX_MEMO_SCAN_CURSOR)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        for prefix in [
            KV_PREFIX_VERIFIED_PAYMENT,
            KV_PREFIX_UNRESOLVED_ANCHOR,
            KV_PREFIX_MEMO_SCAN_RETRY_COUNT,
        ] {
            let keys = kv
                .list(scope, Some(prefix))
                .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
            for key in keys {
                kv.delete(scope, &key)
                    .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
            }
        }

        Ok(())
    }

    /// Run one pass of the DET-side duplicate incoming-memo scan (see
    /// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`) for the
    /// wallet identified by `seed_hash`: re-derive its Orchard incoming
    /// viewing key through the secret chokepoint, walk the raw note stream
    /// from `start_index`, and return every recognized [`IncomingMemoSignal`]
    /// — a `contactAnchor` handshake step ([`MEMO_TAG_ANCHOR`]) or a real
    /// payment ([`MEMO_TAG_PAYMENT`]) — tagged with the note's absolute
    /// stream position, plus the resume index for the next pass. The
    /// position lets the caller hold the persisted cursor back to a specific
    /// signal that failed to process instead of always advancing past it —
    /// see `memo_scan::scan_for_incoming_anchors`. Both tags are checked in
    /// the same pass over the same note stream rather than two separate
    /// scans, since re-walking it twice would double the redundant-scan cost
    /// this design already accepts.
    ///
    /// Intentionally re-derives the IVK and re-fetches notes independently
    /// of the wallet's own sync coordinator, which cannot recover memos —
    /// see the linked design doc for why this redundant work is the
    /// deliberate near-term tradeoff.
    pub async fn orchardpay_scan_incoming_memos(
        &self,
        sdk: &Sdk,
        seed_hash: &WalletSeedHash,
        network: Network,
        start_index: u64,
    ) -> Result<(Vec<(u64, IncomingMemoSignal)>, u64), TaskError> {
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret_session(&scope, async |session| {
                let plaintext = session.plaintext();
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                let keys = OrchardKeySet::from_seed(seed, network, 0).map_err(|e| {
                    TaskError::WalletBackend {
                        source: Arc::new(e),
                    }
                })?;
                let ivk = keys.prepared_ivk();

                let mut found = Vec::new();
                let mut next_start_index = start_index;
                let mut notes_examined = 0u64;
                let mut notes_decrypted = 0u64;
                let mut stream =
                    std::pin::pin!(sync_shielded_notes_stream(sdk, &ivk, start_index, None));
                while let Some(batch) = stream.next().await {
                    let batch = batch.map_err(|e| {
                        TaskError::OrchardPay(OrchardPayError::MemoScanFailed {
                            source: Box::new(e),
                        })
                    })?;
                    notes_examined += batch.notes.len() as u64;

                    for (offset, note) in batch.notes.iter().enumerate() {
                        let Some((decrypted_note, _, memo)) =
                            try_decrypt_note_with_memo(&ivk, note)
                        else {
                            continue;
                        };
                        notes_decrypted += 1;
                        let note_index = batch.start_index + offset as u64;
                        let tag: [u8; 4] = memo[..4].try_into().expect("memo is 36 bytes");
                        let doc_id_bytes: [u8; 32] =
                            memo[4..].try_into().expect("memo is 36 bytes, tag is 4");
                        if tag == MEMO_TAG_ANCHOR {
                            // Below the shared send floor (Finding 2 of the
                            // 2026-07-26 security audit): a real anchor
                            // signal always carries at least
                            // `MIN_SEND_AMOUNT_CREDITS`
                            // (`ANCHOR_SIGNAL_AMOUNT_CREDITS` is defined in
                            // terms of it), so anything under that is
                            // necessarily garbage — skip it here, before
                            // `handle_incoming_anchor_signal`'s expensive
                            // fetch-by-ID + per-identity decrypt attempt.
                            // The note's value is already known locally
                            // (same field the `Payment` branch below reads),
                            // so this costs nothing extra to check.
                            if decrypted_note.value().inner()
                                < crate::model::orchardpay::MIN_SEND_AMOUNT_CREDITS
                            {
                                continue;
                            }
                            found.push((
                                note_index,
                                IncomingMemoSignal::Anchor(Identifier::from(doc_id_bytes)),
                            ));
                        } else if tag == MEMO_TAG_PAYMENT {
                            found.push((
                                note_index,
                                IncomingMemoSignal::Payment {
                                    referenced_document_id: Identifier::from(doc_id_bytes),
                                    received_amount_credits: decrypted_note.value().inner(),
                                },
                            ));
                        }
                    }

                    next_start_index = if batch.is_partial {
                        batch.start_index
                    } else {
                        batch.start_index + batch.notes.len() as u64
                    };
                }

                tracing::info!(
                    wallet = %hex::encode(seed_hash),
                    start_index,
                    next_start_index,
                    notes_examined,
                    notes_decrypted,
                    anchor_or_payment_signals_found = found.len(),
                    "OrchardPay: incoming memo scan (note-level) pass complete"
                );

                Ok((found, next_start_index))
            })
            .await
    }

    /// Best-effort recovery of the memo for each of `positions` — note
    /// positions already known from `WalletBackend::shielded_activity`'s
    /// `get_all_notes()` read — via a full decrypt of just the aligned
    /// chunk(s) that contain them. The routine wallet sync only ever
    /// extracts the memo-blind *compact* note (for efficiency — see
    /// `try_decrypt_note` vs `try_decrypt_note_with_memo`), so a received
    /// note's memo is never persisted anywhere; this re-derives it on
    /// demand, purely for the Payments tab's display, the same
    /// `try_decrypt_note_with_memo` full decrypt
    /// `orchardpay_scan_incoming_memos` already uses.
    ///
    /// Targeted, not a rescan: only the MMR chunk(s) actually containing a
    /// requested position are fetched (one request per distinct chunk,
    /// deduplicated), not the whole history. Chunk alignment
    /// ([`SHIELDED_NOTES_CHUNK_ALIGNMENT`]) is a fixed, versioned Platform
    /// protocol constant, not something derivable at runtime through a
    /// public SDK path.
    ///
    /// Never fails — a locked wallet, a network hiccup, or a stale position
    /// just yields fewer (or zero) recovered memos, logged at `debug`. This
    /// only enriches an already-complete note list; losing the enrichment
    /// must never break the Payments tab.
    pub(crate) async fn orchardpay_recover_received_memos(
        &self,
        sdk: &Sdk,
        seed_hash: &WalletSeedHash,
        positions: &std::collections::BTreeSet<u64>,
    ) -> std::collections::BTreeMap<u64, [u8; 36]> {
        if positions.is_empty() {
            return std::collections::BTreeMap::new();
        }
        let scope = Self::hd_scope(seed_hash);
        let network = self.inner.network;
        let result = self
            .inner
            .secret_access
            .with_secret_session(&scope, async |session| {
                let plaintext = session.plaintext();
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                let keys = OrchardKeySet::from_seed(seed, network, 0).map_err(|e| {
                    TaskError::WalletBackend {
                        source: Arc::new(e),
                    }
                })?;
                let ivk = keys.prepared_ivk();

                let aligned_starts: std::collections::BTreeSet<u64> = positions
                    .iter()
                    .map(|p| (p / SHIELDED_NOTES_CHUNK_ALIGNMENT) * SHIELDED_NOTES_CHUNK_ALIGNMENT)
                    .collect();

                let mut memos = std::collections::BTreeMap::new();
                for start in aligned_starts {
                    let mut stream =
                        std::pin::pin!(sync_shielded_notes_stream(sdk, &ivk, start, None));
                    let Some(Ok(batch)) = stream.next().await else {
                        continue;
                    };
                    for (offset, note) in batch.notes.iter().enumerate() {
                        let note_index = batch.start_index + offset as u64;
                        if !positions.contains(&note_index) {
                            continue;
                        }
                        if let Some((_, _, memo)) = try_decrypt_note_with_memo(&ivk, note) {
                            memos.insert(note_index, memo);
                        }
                    }
                }
                Ok::<_, TaskError>(memos)
            })
            .await;

        result.unwrap_or_else(|e| {
            tracing::debug!(
                error = ?e,
                "OrchardPay: could not recover received-note memos for Payments display"
            );
            std::collections::BTreeMap::new()
        })
    }

    /// Resolve the wallet's seed through the secret chokepoint and derive
    /// its fixed `anchorData` encryption key ([`derive_anchor_data_key`]).
    /// Safe to call repeatedly — cheap, pure derivation with no persistent
    /// state; the design doc's nonce-reuse analysis is what makes reusing
    /// the result across many documents safe, not caching it here.
    pub async fn orchardpay_anchor_data_key(
        &self,
        seed_hash: &WalletSeedHash,
        network: Network,
    ) -> Result<Zeroizing<[u8; 32]>, TaskError> {
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret(&scope, |plaintext| {
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                derive_anchor_data_key(seed, network)
            })
            .await
    }

    /// Find the first `key_index` in `0..ORCHARDPAY_KEY_INDEX_WINDOW` whose
    /// derived public key doesn't match any of `already_registered_keys` —
    /// the "next free slot" for a newly generated OrchardPay identity key.
    /// Computed from the identity's actual current on-chain key set rather
    /// than a fixed reservation, so it's robust to other features claiming
    /// slots in any order. Returns the free `key_index` plus that
    /// candidate's derived public/private key bytes, so the caller doesn't
    /// need a second derivation pass. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
    /// "HD-deriving the ENCRYPTION/DECRYPTION identity keys".
    pub async fn orchardpay_next_free_identity_key_index(
        &self,
        seed_hash: &WalletSeedHash,
        network: Network,
        identity_index: u32,
        already_registered_keys: &[Vec<u8>],
    ) -> Result<(u32, [u8; 33], Zeroizing<[u8; 32]>), TaskError> {
        use dash_sdk::dpp::dashcore::hashes::{Hash, ripemd160, sha256};

        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret(&scope, |plaintext| {
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                for key_index in 0..ORCHARDPAY_KEY_INDEX_WINDOW {
                    let (public_key_bytes, private_key_bytes) =
                        derive_identity_key_candidate(seed, network, identity_index, key_index)?;
                    // An identity's default keys (master/AUTHENTICATION/
                    // TRANSFER) register as ECDSA_HASH160 — a 20-byte hash,
                    // not the 33-byte compressed pubkey this scan derives.
                    // Comparing only the raw pubkey bytes would silently
                    // never match those slots, misreporting an already-used
                    // index as free (and deriving OrchardPay's key at the
                    // *same* index as e.g. the master key — a real key-reuse
                    // bug, not just a wrong index). Check both encodings of
                    // this candidate against every registered key's raw
                    // data, mirroring the HASH160 comparison
                    // `QualifiedIdentity::sign_via_hash160_path_scan` already
                    // uses for the same underlying reason.
                    let public_key_hash160 = ripemd160::Hash::hash(
                        sha256::Hash::hash(&public_key_bytes).as_byte_array(),
                    );
                    let already_claimed = already_registered_keys.iter().any(|registered| {
                        registered.as_slice() == public_key_bytes.as_slice()
                            || registered.as_slice()
                                == public_key_hash160.as_byte_array().as_slice()
                    });
                    if !already_claimed {
                        return Ok((
                            key_index,
                            public_key_bytes,
                            Zeroizing::new(private_key_bytes),
                        ));
                    }
                }
                Err(TaskError::OrchardPay(OrchardPayError::OwnKeyNotDerivable))
            })
            .await
    }

    /// Recover the private key material for an already-registered OrchardPay
    /// identity key, purely from the seed — no local vault record needed.
    /// Scans the same window `orchardpay_next_free_identity_key_index` draws
    /// from, matching by `target_public_key_data` (the registered key's own
    /// bytes, from `own_bounds_verified_key`). This is what makes a
    /// reinstalled wallet — recovery phrase only, no local data — able to
    /// keep decrypting `data`/`msgData`, closing the gap `anchorData` alone
    /// didn't. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "HD-deriving the
    /// ENCRYPTION/DECRYPTION identity keys".
    pub async fn orchardpay_find_identity_key_by_pubkey(
        &self,
        seed_hash: &WalletSeedHash,
        network: Network,
        identity_index: u32,
        target_public_key_data: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, TaskError> {
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret(&scope, |plaintext| {
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                for key_index in 0..ORCHARDPAY_KEY_INDEX_WINDOW {
                    let (public_key_bytes, private_key_bytes) =
                        derive_identity_key_candidate(seed, network, identity_index, key_index)?;
                    if public_key_bytes.as_slice() == target_public_key_data {
                        return Ok(Zeroizing::new(private_key_bytes));
                    }
                }
                Err(TaskError::OrchardPay(OrchardPayError::OwnKeyNotDerivable))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::orchardpay::{AnchorRole, PendingOperationStep};
    use crate::wallet_backend::kv::DetKv;

    const TEST_SEED: [u8; 64] = [0x42u8; 64];

    #[test]
    fn anchor_data_key_is_deterministic() {
        let a = derive_anchor_data_key(&TEST_SEED, Network::Testnet).expect("derive");
        let b = derive_anchor_data_key(&TEST_SEED, Network::Testnet).expect("derive");
        assert_eq!(
            *a, *b,
            "same seed + network must re-derive the identical key"
        );
    }

    #[test]
    fn anchor_data_key_differs_across_networks() {
        let testnet = derive_anchor_data_key(&TEST_SEED, Network::Testnet).expect("derive");
        let mainnet = derive_anchor_data_key(&TEST_SEED, Network::Mainnet).expect("derive");
        assert_ne!(
            *testnet, *mainnet,
            "mainnet/testnet coin type must produce different keys"
        );
    }

    #[test]
    fn anchor_data_key_differs_across_seeds() {
        let a = derive_anchor_data_key(&TEST_SEED, Network::Testnet).expect("derive");
        let b = derive_anchor_data_key(&[0x24u8; 64], Network::Testnet).expect("derive");
        assert_ne!(*a, *b, "different seeds must produce different keys");
    }

    #[test]
    fn identity_key_candidate_is_deterministic() {
        let a = derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 4).expect("derive");
        let b = derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 4).expect("derive");
        assert_eq!(
            a, b,
            "same seed/network/identity_index/key_index must re-derive identically"
        );
    }

    #[test]
    fn identity_key_candidate_differs_across_key_index() {
        let (pk_a, sk_a) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 4).expect("derive");
        let (pk_b, sk_b) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 5).expect("derive");
        assert_ne!(
            pk_a, pk_b,
            "different key_index must yield different public keys"
        );
        assert_ne!(
            sk_a, sk_b,
            "different key_index must yield different private keys"
        );
    }

    #[test]
    fn identity_key_candidate_differs_across_identity_index() {
        let (pk_a, _) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 4).expect("derive");
        let (pk_b, _) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 1, 4).expect("derive");
        assert_ne!(
            pk_a, pk_b,
            "different identity_index must yield different public keys"
        );
    }

    /// Exercises the same "scan and find" logic
    /// `orchardpay_next_free_identity_key_index` runs inside its
    /// `with_secret` closure, without needing the full secret-vault
    /// machinery — proves the window scan correctly skips claimed slots.
    #[test]
    fn next_free_index_skips_already_registered_candidates() {
        let (index_0_pubkey, _) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 0).expect("derive");
        let (index_1_pubkey, _) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 1).expect("derive");
        let already_registered = [index_0_pubkey.to_vec(), index_1_pubkey.to_vec()];

        let mut found = None;
        for key_index in 0..ORCHARDPAY_KEY_INDEX_WINDOW {
            let (public_key_bytes, _) =
                derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, key_index)
                    .expect("derive");
            if !already_registered
                .iter()
                .any(|registered| registered.as_slice() == public_key_bytes.as_slice())
            {
                found = Some(key_index);
                break;
            }
        }

        assert_eq!(
            found,
            Some(2),
            "first two slots claimed, so index 2 must be the next free one"
        );
    }

    /// Regression test for the exact bug found in live testing: a fresh
    /// identity's default keys at low indices (master, AUTHENTICATION,
    /// TRANSFER) register as ECDSA_HASH160 — a 20-byte hash of the
    /// compressed pubkey, not the 33-byte compressed pubkey itself. A scan
    /// that only compares raw 33-byte candidates against `already_registered`
    /// never matches those HASH160 entries, so it wrongly reports an
    /// already-claimed index (e.g. 0, the master key's own slot) as free —
    /// which would derive OrchardPay's ENCRYPTION key at the *same*
    /// derivation index as the identity's master signing key. This proves
    /// the HASH160-aware comparison (mirroring
    /// `QualifiedIdentity::sign_via_hash160_path_scan`'s own hashing) closes
    /// that gap.
    #[test]
    fn next_free_index_recognizes_hash160_registered_slots_as_claimed() {
        use dash_sdk::dpp::dashcore::hashes::{Hash, ripemd160, sha256};

        let (index_0_pubkey, _) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 0).expect("derive");
        let index_0_hash160 =
            ripemd160::Hash::hash(sha256::Hash::hash(&index_0_pubkey).as_byte_array());

        // Simulate a fresh identity: index 0 (master) registered as its
        // HASH160 form only, exactly like `default_identity_key_specs`.
        let already_registered = [index_0_hash160.as_byte_array().to_vec()];

        let mut found = None;
        for key_index in 0..ORCHARDPAY_KEY_INDEX_WINDOW {
            let (public_key_bytes, _) =
                derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, key_index)
                    .expect("derive");
            let public_key_hash160 =
                ripemd160::Hash::hash(sha256::Hash::hash(&public_key_bytes).as_byte_array());
            let already_claimed = already_registered.iter().any(|registered| {
                registered.as_slice() == public_key_bytes.as_slice()
                    || registered.as_slice() == public_key_hash160.as_byte_array().as_slice()
            });
            if !already_claimed {
                found = Some(key_index);
                break;
            }
        }

        assert_eq!(
            found,
            Some(1),
            "index 0 is claimed (as a HASH160), so index 1 must be the next free one"
        );
    }

    /// Same underlying scan, the other direction: recovering an
    /// already-registered key's private material purely from the seed by
    /// matching public key bytes — what
    /// `orchardpay_find_identity_key_by_pubkey` does after a reinstall with
    /// no local vault record.
    #[test]
    fn scan_recovers_private_key_matching_a_known_public_key() {
        let (target_pubkey, target_privkey) =
            derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, 5).expect("derive");

        let mut recovered = None;
        for key_index in 0..ORCHARDPAY_KEY_INDEX_WINDOW {
            let (public_key_bytes, private_key_bytes) =
                derive_identity_key_candidate(&TEST_SEED, Network::Testnet, 0, key_index)
                    .expect("derive");
            if public_key_bytes == target_pubkey {
                recovered = Some(private_key_bytes);
                break;
            }
        }

        assert_eq!(
            recovered,
            Some(target_privkey),
            "scanning the window must recover the exact private key for the target public key"
        );
    }

    fn empty_kv() -> DetKv {
        use crate::wallet_backend::kv_test_support::InMemoryKv;

        DetKv::from_store(Arc::new(InMemoryKv::default()))
    }

    /// Mirrors `orchardpay_clear_owner_overlays`'s sweep logic directly
    /// against a `DetKv` test double — same style as
    /// `wallet_backend::dashpay`'s own overlay-sweep test — proving the
    /// per-owner `KV_PREFIX_CONTACT` sweep clears only that owner's entries.
    #[test]
    fn owner_overlays_sweep_clears_only_that_owners_contact_entries() {
        let kv = empty_kv();
        let owner_a = [0x11u8; 32];
        let owner_b = [0x22u8; 32];

        kv.put::<u32>(
            DetScope::Identity(&owner_a),
            &format!("{KV_PREFIX_CONTACT}counterparty1"),
            &1,
        )
        .unwrap();
        kv.put::<u32>(
            DetScope::Identity(&owner_b),
            &format!("{KV_PREFIX_CONTACT}counterparty2"),
            &2,
        )
        .unwrap();

        for key in kv
            .list(DetScope::Identity(&owner_a), Some(KV_PREFIX_CONTACT))
            .unwrap()
        {
            kv.delete(DetScope::Identity(&owner_a), &key).unwrap();
        }

        assert!(
            kv.list(DetScope::Identity(&owner_a), Some(KV_PREFIX_CONTACT))
                .unwrap()
                .is_empty(),
            "owner_a's contact overlays must be gone"
        );
        assert_eq!(
            kv.list(DetScope::Identity(&owner_b), Some(KV_PREFIX_CONTACT))
                .unwrap()
                .len(),
            1,
            "owner_b's contact overlays must be untouched"
        );
    }

    /// A pending `ContactAnchor` operation round-trips through get/set/clear
    /// — the exact sequence `initiate_contact`/`accept_contact` rely on to
    /// detect and resume an interrupted attempt. Mirrors
    /// `orchardpay_get/set/clear_pending_operation`'s logic directly against
    /// a `DetKv` test double, same style as the contact-state tests above.
    #[test]
    fn pending_contact_anchor_operation_round_trips() {
        let kv = empty_kv();
        let owner = [0x66u8; 32];
        let contract_id = Identifier::new([0x11u8; 32]);
        let counterparty = Identifier::new([0x77u8; 32]);
        let scope = DetScope::Identity(&owner);
        let key = pending_operation_key(&contract_id, &counterparty);

        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(scope, &key).unwrap(),
            None,
            "nothing pending yet"
        );

        let op = PendingOrchardPayOperation::ContactAnchor {
            my_reference_id: [1u8; 32],
            my_anchor_document_id: [2u8; 32],
            step: PendingOperationStep::DocumentPublished,
        };
        kv.put::<PendingOrchardPayOperation>(scope, &key, &op)
            .unwrap();
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(scope, &key).unwrap(),
            Some(op),
            "recorded operation must read back unchanged"
        );

        kv.delete(scope, &key).unwrap();
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(scope, &key).unwrap(),
            None,
            "cleared operation must no longer be present"
        );
    }

    /// A pending `Payment` operation round-trips the same way — the shape
    /// `send_payment` relies on to detect a prior unconfirmed send.
    #[test]
    fn pending_payment_operation_round_trips() {
        let kv = empty_kv();
        let owner = [0x88u8; 32];
        let contract_id = Identifier::new([0x11u8; 32]);
        let counterparty = Identifier::new([0x99u8; 32]);
        let scope = DetScope::Identity(&owner);
        let key = pending_operation_key(&contract_id, &counterparty);

        let op = PendingOrchardPayOperation::Payment {
            document_id: [3u8; 32],
            step: PendingOperationStep::DocumentPublished,
        };
        kv.put::<PendingOrchardPayOperation>(scope, &key, &op)
            .unwrap();
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(scope, &key).unwrap(),
            Some(op)
        );
    }

    /// Two counterparties under the same owner never collide — each has its
    /// own independent pending-operation slot.
    #[test]
    fn pending_operations_are_scoped_per_counterparty() {
        let kv = empty_kv();
        let owner = [0xaau8; 32];
        let contract_id = Identifier::new([0x11u8; 32]);
        let counterparty_a = Identifier::new([0xbbu8; 32]);
        let counterparty_b = Identifier::new([0xccu8; 32]);
        let scope = DetScope::Identity(&owner);

        let op = PendingOrchardPayOperation::ContactAnchor {
            my_reference_id: [4u8; 32],
            my_anchor_document_id: [5u8; 32],
            step: PendingOperationStep::TransferSent,
        };
        kv.put::<PendingOrchardPayOperation>(
            scope,
            &pending_operation_key(&contract_id, &counterparty_a),
            &op,
        )
        .unwrap();

        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(
                scope,
                &pending_operation_key(&contract_id, &counterparty_a)
            )
            .unwrap(),
            Some(op),
            "counterparty_a's marker must be present"
        );
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(
                scope,
                &pending_operation_key(&contract_id, &counterparty_b)
            )
            .unwrap(),
            None,
            "counterparty_b must not see counterparty_a's marker"
        );
    }

    /// Regression test for the real `KeyTooLong { len: 129 }` failure hit in
    /// production: `scheduled_anchor_replace_key`'s prefix used to be long
    /// enough that two worst-case (44-char base58) `Identifier`s pushed the
    /// key one char past the upstream store's `MAX_KEY_LEN`. `[0xff; 32]` is
    /// the numerically largest 32-byte value, so it deterministically
    /// produces base58's longest encoding (44 chars) — not just a likely
    /// case. Covers every builder in this file that concatenates two full
    /// `Identifier`s into one key, since `scheduled_anchor_replace_key` was
    /// not the only one structurally capable of this, only the one whose
    /// prefix happened to be long enough to overflow.
    #[test]
    fn two_identifier_keys_stay_within_kv_max_len() {
        let contract_id = Identifier::new([0xffu8; 32]);
        let counterparty = Identifier::new([0xffu8; 32]);

        for key in [
            scheduled_anchor_replace_key(&contract_id, &counterparty),
            contact_key(&contract_id, &counterparty),
            pending_operation_key(&contract_id, &counterparty),
        ] {
            assert!(
                key.chars().count() <= platform_wallet_storage::kv::MAX_KEY_LEN,
                "key {key:?} ({} chars) exceeds MAX_KEY_LEN ({})",
                key.chars().count(),
                platform_wallet_storage::kv::MAX_KEY_LEN
            );
        }

        assert_eq!(
            scheduled_anchor_replace_key(&contract_id, &counterparty)
                .chars()
                .count(),
            119,
            "worst-case length should match the prefix's documented budget; update the doc \
             comment on KV_PREFIX_SCHEDULED_ANCHOR_REPLACE if this changes"
        );
    }

    /// A scheduled anchor-replace marker round-trips through get/set/clear
    /// — the sequence the delayed-replace pass (see the 2026-07-27
    /// adversarial audit's finding 5) relies on.
    #[test]
    fn scheduled_anchor_replace_round_trips() {
        let kv = empty_kv();
        let owner = [0xd1u8; 32];
        let contract_id = Identifier::new([0x21u8; 32]);
        let counterparty = Identifier::new([0x22u8; 32]);
        let scope = DetScope::Identity(&owner);
        let key = scheduled_anchor_replace_key(&contract_id, &counterparty);

        assert_eq!(
            kv.get::<ScheduledAnchorReplace>(scope, &key).unwrap(),
            None,
            "nothing scheduled yet"
        );

        let marker = ScheduledAnchorReplace {
            anchor_document_id: [1u8; 32],
            anchor_created_at: 1_700_000_000_000,
            role: AnchorRole::Initiator,
        };
        kv.put::<ScheduledAnchorReplace>(scope, &key, &marker)
            .unwrap();
        assert_eq!(
            kv.get::<ScheduledAnchorReplace>(scope, &key).unwrap(),
            Some(marker),
            "recorded marker must read back unchanged"
        );

        kv.delete(scope, &key).unwrap();
        assert_eq!(
            kv.get::<ScheduledAnchorReplace>(scope, &key).unwrap(),
            None,
            "cleared marker must no longer be present"
        );
    }

    /// The exact conflict the holistic cross-check found: a
    /// `ScheduledAnchorReplace` marker and a `PendingOrchardPayOperation`
    /// for the *same* `(contract_id, counterparty)` must not collide —
    /// they need independent keys, since a payment to the same counterparty
    /// can legitimately be in flight while a replace is still pending.
    #[test]
    fn scheduled_anchor_replace_does_not_collide_with_pending_operation() {
        let kv = empty_kv();
        let owner = [0xd2u8; 32];
        let contract_id = Identifier::new([0x23u8; 32]);
        let counterparty = Identifier::new([0x24u8; 32]);
        let scope = DetScope::Identity(&owner);

        let marker = ScheduledAnchorReplace {
            anchor_document_id: [2u8; 32],
            anchor_created_at: 1_700_000_000_000,
            role: AnchorRole::Acceptor,
        };
        kv.put::<ScheduledAnchorReplace>(
            scope,
            &scheduled_anchor_replace_key(&contract_id, &counterparty),
            &marker,
        )
        .unwrap();

        let payment_op = PendingOrchardPayOperation::Payment {
            document_id: [3u8; 32],
            step: PendingOperationStep::DocumentPublished,
        };
        kv.put::<PendingOrchardPayOperation>(
            scope,
            &pending_operation_key(&contract_id, &counterparty),
            &payment_op,
        )
        .unwrap();

        assert_eq!(
            kv.get::<ScheduledAnchorReplace>(
                scope,
                &scheduled_anchor_replace_key(&contract_id, &counterparty)
            )
            .unwrap(),
            Some(marker),
            "the scheduled-replace marker must survive an in-flight payment op to the same \
             counterparty"
        );
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(
                scope,
                &pending_operation_key(&contract_id, &counterparty)
            )
            .unwrap(),
            Some(payment_op),
            "the payment op must survive a scheduled-replace marker to the same counterparty"
        );
    }

    /// The same `(owner, counterparty)` pair under two different contract
    /// IDs never collides — the exact scenario a contract re-registration
    /// creates: a stale entry under a retired contract ID must not be read
    /// back as valid under the new one.
    #[test]
    fn pending_operations_are_scoped_per_contract_id() {
        let kv = empty_kv();
        let owner = [0xa1u8; 32];
        let counterparty = Identifier::new([0xa2u8; 32]);
        let old_contract = Identifier::new([0x01u8; 32]);
        let new_contract = Identifier::new([0x02u8; 32]);
        let scope = DetScope::Identity(&owner);

        let op = PendingOrchardPayOperation::ContactAnchor {
            my_reference_id: [7u8; 32],
            my_anchor_document_id: [8u8; 32],
            step: PendingOperationStep::TransferSent,
        };
        kv.put::<PendingOrchardPayOperation>(
            scope,
            &pending_operation_key(&old_contract, &counterparty),
            &op,
        )
        .unwrap();

        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(
                scope,
                &pending_operation_key(&new_contract, &counterparty)
            )
            .unwrap(),
            None,
            "a marker recorded under the old contract must not appear under the new one"
        );
    }

    /// The exact regression scenario for the "stale contact survives a
    /// contract re-registration" bug: the same `(owner, counterparty)` pair
    /// recorded as `Established` under a retired contract ID must not be
    /// readable as a contact under a freshly re-registered contract ID.
    #[test]
    fn contact_state_is_scoped_per_contract_id() {
        let kv = empty_kv();
        let owner = [0xb1u8; 32];
        let counterparty = Identifier::new([0xb2u8; 32]);
        let old_contract = Identifier::new([0x03u8; 32]);
        let new_contract = Identifier::new([0x04u8; 32]);
        let scope = DetScope::Identity(&owner);

        let state = OrchardPayContactState::Established {
            my_reference_id: [9u8; 32],
            my_anchor_document_id: [10u8; 32],
            their_reference_id: [11u8; 32],
            counterparty_encryption_pubkey: vec![1, 2, 3],
            counterparty_decryption_pubkey: vec![4, 5, 6],
            name: None,
            created_at: None,
        };
        kv.put::<OrchardPayContactState>(scope, &contact_key(&old_contract, &counterparty), &state)
            .unwrap();

        assert_eq!(
            kv.get::<OrchardPayContactState>(scope, &contact_key(&new_contract, &counterparty))
                .unwrap(),
            None,
            "an Established record under the retired contract must not read back as a contact \
             under the newly re-registered one"
        );
        assert_eq!(
            kv.get::<OrchardPayContactState>(scope, &contact_key(&old_contract, &counterparty))
                .unwrap(),
            Some(state),
            "the record must still be readable under the contract ID it was actually written under"
        );
    }

    /// `orchardpay_list_contacts`'s prefix scan (via [`contact_key_prefix`])
    /// only surfaces contacts recorded under the given contract ID, even
    /// when the same owner has entries under another (e.g. retired)
    /// contract ID too.
    #[test]
    fn list_contacts_prefix_is_scoped_per_contract_id() {
        let kv = empty_kv();
        let owner = [0xb3u8; 32];
        let old_contract = Identifier::new([0x05u8; 32]);
        let new_contract = Identifier::new([0x06u8; 32]);
        let old_counterparty = Identifier::new([0xc1u8; 32]);
        let new_counterparty = Identifier::new([0xc2u8; 32]);
        let scope = DetScope::Identity(&owner);

        let state = OrchardPayContactState::PendingOutbound {
            my_reference_id: [1u8; 32],
            my_anchor_document_id: [2u8; 32],
            name: None,
            created_at: None,
        };
        kv.put::<OrchardPayContactState>(
            scope,
            &contact_key(&old_contract, &old_counterparty),
            &state,
        )
        .unwrap();
        kv.put::<OrchardPayContactState>(
            scope,
            &contact_key(&new_contract, &new_counterparty),
            &state,
        )
        .unwrap();

        let prefix = contact_key_prefix(&new_contract);
        let listed: Vec<Identifier> = kv
            .list(scope, Some(&prefix))
            .unwrap()
            .into_iter()
            .filter_map(|k| {
                let b58 = k.strip_prefix(&prefix)?;
                Identifier::from_string(b58, Encoding::Base58).ok()
            })
            .collect();

        assert_eq!(
            listed,
            vec![new_counterparty],
            "listing under the new contract ID must not include the old contract's counterparty"
        );
    }

    /// The cached "published a shieldedAddress" flag is contract-scoped:
    /// confirmed `true` under a retired contract ID must not suppress the
    /// live check (and republish) needed under a freshly re-registered one.
    #[test]
    fn has_shielded_address_flag_is_scoped_per_contract_id() {
        let kv = empty_kv();
        let owner = [0xb4u8; 32];
        let old_contract = Identifier::new([0x07u8; 32]);
        let new_contract = Identifier::new([0x08u8; 32]);
        let scope = DetScope::Identity(&owner);

        kv.put::<bool>(scope, &has_shielded_address_key(&old_contract), &true)
            .unwrap();

        assert_eq!(
            kv.get::<bool>(scope, &has_shielded_address_key(&new_contract))
                .unwrap(),
            None,
            "a confirmed publish under the old contract must not read back as confirmed under \
             the new one"
        );
    }

    /// `orchardpay_clear_owner_overlays`'s sweep loop must also clear
    /// pending-operation markers, leaving other owners untouched — extends
    /// `owner_overlays_sweep_clears_only_that_owners_contact_entries`.
    #[test]
    fn owner_overlays_sweep_clears_pending_operations_too() {
        let kv = empty_kv();
        let owner_a = [0xddu8; 32];
        let owner_b = [0xeeu8; 32];
        let contract_id = Identifier::new([0x11u8; 32]);
        let counterparty = Identifier::new([0xffu8; 32]);
        let key = pending_operation_key(&contract_id, &counterparty);
        let op = PendingOrchardPayOperation::Payment {
            document_id: [6u8; 32],
            step: PendingOperationStep::DocumentPublished,
        };

        kv.put::<PendingOrchardPayOperation>(DetScope::Identity(&owner_a), &key, &op)
            .unwrap();
        kv.put::<PendingOrchardPayOperation>(DetScope::Identity(&owner_b), &key, &op)
            .unwrap();

        for prefix in [KV_PREFIX_CONTACT, KV_PREFIX_PENDING_OPERATION] {
            for k in kv.list(DetScope::Identity(&owner_a), Some(prefix)).unwrap() {
                kv.delete(DetScope::Identity(&owner_a), &k).unwrap();
            }
        }

        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(DetScope::Identity(&owner_a), &key)
                .unwrap(),
            None,
            "owner_a's pending operation must be gone"
        );
        assert_eq!(
            kv.get::<PendingOrchardPayOperation>(DetScope::Identity(&owner_b), &key)
                .unwrap(),
            Some(op),
            "owner_b's pending operation must be untouched"
        );
    }

    /// `orchardpay_clear_owner_overlays` now sweeps
    /// `KV_PREFIX_HAS_SHIELDED_ADDRESS` by prefix (a family of per-contract
    /// keys) rather than deleting one exact key — proves that sweep clears
    /// every contract-scoped flag for the target owner, including one
    /// recorded under a since-retired contract ID, while leaving another
    /// owner's flag untouched.
    #[test]
    fn owner_overlays_sweep_clears_has_shielded_address_flags_across_contracts() {
        let kv = empty_kv();
        let owner_a = [0x12u8; 32];
        let owner_b = [0x13u8; 32];
        let old_contract = Identifier::new([0x09u8; 32]);
        let new_contract = Identifier::new([0x0au8; 32]);

        kv.put::<bool>(
            DetScope::Identity(&owner_a),
            &has_shielded_address_key(&old_contract),
            &true,
        )
        .unwrap();
        kv.put::<bool>(
            DetScope::Identity(&owner_a),
            &has_shielded_address_key(&new_contract),
            &true,
        )
        .unwrap();
        kv.put::<bool>(
            DetScope::Identity(&owner_b),
            &has_shielded_address_key(&new_contract),
            &true,
        )
        .unwrap();

        for prefix in [
            KV_PREFIX_CONTACT,
            KV_PREFIX_PENDING_OPERATION,
            KV_PREFIX_HAS_SHIELDED_ADDRESS,
            KV_PREFIX_SCHEDULED_ANCHOR_REPLACE,
        ] {
            for k in kv.list(DetScope::Identity(&owner_a), Some(prefix)).unwrap() {
                kv.delete(DetScope::Identity(&owner_a), &k).unwrap();
            }
        }

        assert_eq!(
            kv.get::<bool>(
                DetScope::Identity(&owner_a),
                &has_shielded_address_key(&old_contract)
            )
            .unwrap(),
            None,
            "owner_a's flag under the old contract must be gone"
        );
        assert_eq!(
            kv.get::<bool>(
                DetScope::Identity(&owner_a),
                &has_shielded_address_key(&new_contract)
            )
            .unwrap(),
            None,
            "owner_a's flag under the new contract must be gone too"
        );
        assert_eq!(
            kv.get::<bool>(
                DetScope::Identity(&owner_b),
                &has_shielded_address_key(&new_contract)
            )
            .unwrap(),
            Some(true),
            "owner_b's flag must be untouched"
        );
    }

    /// Mirrors `orchardpay_clear_wallet_overlays`'s sweep logic — proves the
    /// memo-scan cursor (an exact key) and the verified-payment cache (a
    /// true prefix, many entries) are both cleared for the target wallet,
    /// and that an unrelated wallet's entries survive.
    #[test]
    fn wallet_overlays_sweep_clears_only_that_wallets_entries() {
        let kv = empty_kv();
        let wallet_a: WalletSeedHash = [0x33u8; 32];
        let wallet_b: WalletSeedHash = [0x44u8; 32];

        kv.put::<u64>(DetScope::Wallet(&wallet_a), KV_PREFIX_MEMO_SCAN_CURSOR, &42)
            .unwrap();
        kv.put::<u64>(
            DetScope::Wallet(&wallet_a),
            &format!("{KV_PREFIX_VERIFIED_PAYMENT}doc1"),
            &1000,
        )
        .unwrap();
        kv.put::<u64>(DetScope::Wallet(&wallet_b), KV_PREFIX_MEMO_SCAN_CURSOR, &7)
            .unwrap();

        kv.delete(DetScope::Wallet(&wallet_a), KV_PREFIX_MEMO_SCAN_CURSOR)
            .unwrap();
        for key in kv
            .list(
                DetScope::Wallet(&wallet_a),
                Some(KV_PREFIX_VERIFIED_PAYMENT),
            )
            .unwrap()
        {
            kv.delete(DetScope::Wallet(&wallet_a), &key).unwrap();
        }

        assert_eq!(
            kv.get::<u64>(DetScope::Wallet(&wallet_a), KV_PREFIX_MEMO_SCAN_CURSOR)
                .unwrap(),
            None,
            "wallet_a's memo-scan cursor must be gone"
        );
        assert!(
            kv.list(
                DetScope::Wallet(&wallet_a),
                Some(KV_PREFIX_VERIFIED_PAYMENT)
            )
            .unwrap()
            .is_empty(),
            "wallet_a's verified-payment cache must be gone"
        );
        assert_eq!(
            kv.get::<u64>(DetScope::Wallet(&wallet_b), KV_PREFIX_MEMO_SCAN_CURSOR)
                .unwrap(),
            Some(7),
            "wallet_b's memo-scan cursor must be untouched"
        );
    }

    /// An anchor recorded as unresolved is listed, then disappears once
    /// cleared — the exact round-trip `scan_for_incoming_anchors` relies on
    /// to retry a signal without re-decrypting its note. Mirrors
    /// `orchardpay_list_unresolved_anchor_signals` /
    /// `orchardpay_record_unresolved_anchor_signal` /
    /// `orchardpay_clear_unresolved_anchor_signal`'s logic directly against
    /// a `DetKv` test double, same style as the overlay-sweep tests above.
    #[test]
    fn unresolved_anchor_signal_round_trips() {
        let kv = empty_kv();
        let wallet: WalletSeedHash = [0x55u8; 32];
        let anchor = Identifier::new([0x66u8; 32]);
        let scope = DetScope::Wallet(&wallet);
        let key = unresolved_anchor_key(&anchor);

        assert!(
            kv.list(scope, Some(KV_PREFIX_UNRESOLVED_ANCHOR))
                .unwrap()
                .is_empty(),
            "nothing recorded yet"
        );

        kv.put::<bool>(scope, &key, &true).unwrap();
        let listed: Vec<Identifier> = kv
            .list(scope, Some(KV_PREFIX_UNRESOLVED_ANCHOR))
            .unwrap()
            .into_iter()
            .filter_map(|k| {
                let b58 = k.strip_prefix(KV_PREFIX_UNRESOLVED_ANCHOR)?;
                Identifier::from_string(b58, Encoding::Base58).ok()
            })
            .collect();
        assert_eq!(listed, vec![anchor], "recorded anchor must be listed");

        kv.delete(scope, &key).unwrap();
        assert!(
            kv.list(scope, Some(KV_PREFIX_UNRESOLVED_ANCHOR))
                .unwrap()
                .is_empty(),
            "cleared anchor must no longer be listed"
        );
    }

    /// Two wallets' unresolved-anchor lists never cross-contaminate.
    #[test]
    fn unresolved_anchor_signals_are_wallet_scoped() {
        let kv = empty_kv();
        let wallet_a: WalletSeedHash = [0x77u8; 32];
        let wallet_b: WalletSeedHash = [0x88u8; 32];
        let anchor = Identifier::new([0x99u8; 32]);

        kv.put::<bool>(
            DetScope::Wallet(&wallet_a),
            &unresolved_anchor_key(&anchor),
            &true,
        )
        .unwrap();

        assert_eq!(
            kv.list(
                DetScope::Wallet(&wallet_a),
                Some(KV_PREFIX_UNRESOLVED_ANCHOR)
            )
            .unwrap()
            .len(),
            1
        );
        assert!(
            kv.list(
                DetScope::Wallet(&wallet_b),
                Some(KV_PREFIX_UNRESOLVED_ANCHOR)
            )
            .unwrap()
            .is_empty(),
            "wallet_b must not see wallet_a's unresolved anchor"
        );
    }

    /// The retry counter starts at zero, increments on each call, and can be
    /// cleared — the exact sequence `scan_for_incoming_anchors` runs against
    /// a note position that keeps failing to process.
    #[test]
    fn memo_scan_retry_count_increments_and_clears() {
        let kv = empty_kv();
        let wallet: WalletSeedHash = [0xaau8; 32];
        let scope = DetScope::Wallet(&wallet);
        let note_index = 12345u64;
        let key = memo_scan_retry_count_key(note_index);

        assert_eq!(
            kv.get::<u32>(scope, &key).unwrap(),
            None,
            "no failures recorded yet"
        );

        for expected in 1..=MEMO_SCAN_ERROR_RETRY_CAP {
            let count = kv.get::<u32>(scope, &key).unwrap().unwrap_or(0) + 1;
            kv.put::<u32>(scope, &key, &count).unwrap();
            assert_eq!(count, expected);
        }

        kv.delete(scope, &key).unwrap();
        assert_eq!(
            kv.get::<u32>(scope, &key).unwrap(),
            None,
            "cleared counter must be gone"
        );
    }

    /// `orchardpay_clear_wallet_overlays`'s sweep loop must also clear the
    /// two new wallet-scoped prefixes this change adds, leaving other
    /// wallets untouched — extends
    /// `wallet_overlays_sweep_clears_only_that_wallets_entries`.
    #[test]
    fn wallet_overlays_sweep_clears_unresolved_anchors_and_retry_counts() {
        let kv = empty_kv();
        let wallet_a: WalletSeedHash = [0xbbu8; 32];
        let wallet_b: WalletSeedHash = [0xccu8; 32];
        let anchor = Identifier::new([0xddu8; 32]);

        kv.put::<bool>(
            DetScope::Wallet(&wallet_a),
            &unresolved_anchor_key(&anchor),
            &true,
        )
        .unwrap();
        kv.put::<u32>(
            DetScope::Wallet(&wallet_a),
            &memo_scan_retry_count_key(7),
            &1,
        )
        .unwrap();
        kv.put::<bool>(
            DetScope::Wallet(&wallet_b),
            &unresolved_anchor_key(&anchor),
            &true,
        )
        .unwrap();

        for prefix in [KV_PREFIX_UNRESOLVED_ANCHOR, KV_PREFIX_MEMO_SCAN_RETRY_COUNT] {
            for key in kv.list(DetScope::Wallet(&wallet_a), Some(prefix)).unwrap() {
                kv.delete(DetScope::Wallet(&wallet_a), &key).unwrap();
            }
        }

        assert!(
            kv.list(
                DetScope::Wallet(&wallet_a),
                Some(KV_PREFIX_UNRESOLVED_ANCHOR)
            )
            .unwrap()
            .is_empty(),
            "wallet_a's unresolved anchors must be gone"
        );
        assert!(
            kv.list(
                DetScope::Wallet(&wallet_a),
                Some(KV_PREFIX_MEMO_SCAN_RETRY_COUNT)
            )
            .unwrap()
            .is_empty(),
            "wallet_a's retry counts must be gone"
        );
        assert_eq!(
            kv.list(
                DetScope::Wallet(&wallet_b),
                Some(KV_PREFIX_UNRESOLVED_ANCHOR)
            )
            .unwrap()
            .len(),
            1,
            "wallet_b's unresolved anchor must be untouched"
        );
    }
}
