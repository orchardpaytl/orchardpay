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

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::MEMO_TAG_ANCHOR;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::model::orchardpay::OrchardPayContactState;
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::{DetScope, WalletBackend};

/// Value: bincode-encoded [`OrchardPayContactState`]. Scope:
/// [`DetScope::Identity`] of the owner — per-relationship state is private
/// to the acting identity and cascades on identity removal. Key shape:
/// `det:orchardpay:contact:<counterparty_b58>`.
const KV_PREFIX_CONTACT: &str = "det:orchardpay:contact:";

/// Presence marker: resume cursor for the DET-side incoming-memo scan (see
/// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`). Value: `u64`,
/// the last chunk-aligned `start_index` fully scanned. Scope:
/// [`DetScope::Wallet`] — the scan is genuinely wallet-level (the Orchard
/// IVK it re-derives comes from the wallet seed, account 0, not from any one
/// identity), so the cursor lives per-wallet rather than per-identity even
/// though the anchors it finds get handed off to individual identities.
const KV_PREFIX_MEMO_SCAN_CURSOR: &str = "det:orchardpay:memo_scan_cursor";

fn contact_key(counterparty: &Identifier) -> String {
    format!(
        "{KV_PREFIX_CONTACT}{}",
        counterparty.to_string(Encoding::Base58)
    )
}

impl WalletBackend {
    /// Read the local contact-establishment state for `(owner,
    /// counterparty)`. `Ok(None)` means no relationship has been started —
    /// callers should treat this as "not a contact yet."
    pub fn orchardpay_get_contact_state(
        &self,
        owner: &Identifier,
        counterparty: &Identifier,
    ) -> Result<Option<OrchardPayContactState>, TaskError> {
        let owner_buf = owner.to_buffer();
        let key = contact_key(counterparty);
        self.kv()
            .get::<OrchardPayContactState>(DetScope::Identity(&owner_buf), &key)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Upsert the local contact-establishment state for `(owner,
    /// counterparty)`.
    pub fn orchardpay_set_contact_state(
        &self,
        owner: &Identifier,
        counterparty: &Identifier,
        state: &OrchardPayContactState,
    ) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let key = contact_key(counterparty);
        self.kv()
            .put::<OrchardPayContactState>(DetScope::Identity(&owner_buf), &key, state)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// List every counterparty identity `owner` has a local contact-state
    /// record for, regardless of phase (pending outbound, pending inbound,
    /// or established).
    pub fn orchardpay_list_contacts(
        &self,
        owner: &Identifier,
    ) -> Result<Vec<Identifier>, TaskError> {
        let owner_buf = owner.to_buffer();
        let keys = self
            .kv()
            .list(DetScope::Identity(&owner_buf), Some(KV_PREFIX_CONTACT))
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        Ok(keys
            .into_iter()
            .filter_map(|key| {
                let b58 = key.strip_prefix(KV_PREFIX_CONTACT)?;
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

    /// Drop every OrchardPay sidecar entry for `owner` — the per-counterparty
    /// contact-state records. Mirrors `dashpay_clear_owner_overlays` for the
    /// network-clear path. The memo-scan cursor is wallet-scoped, not
    /// owner-scoped, so it is not covered here — it is naturally reaped
    /// when the wallet itself is removed ([`DetScope::Wallet`] cascades on
    /// wallet deletion).
    pub fn orchardpay_clear_owner_overlays(&self, owner: &Identifier) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        let scope = DetScope::Identity(&owner_buf);
        let kv = self.kv();

        let contact_keys = kv
            .list(scope, Some(KV_PREFIX_CONTACT))
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
        for key in contact_keys {
            kv.delete(scope, &key)
                .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
        }

        Ok(())
    }

    /// Run one pass of the DET-side duplicate incoming-memo scan (see
    /// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`) for the
    /// wallet identified by `seed_hash`: re-derive its Orchard incoming
    /// viewing key through the secret chokepoint, walk the raw note stream
    /// from `start_index`, and return every `contactAnchor` DocumentID
    /// signaled by a [`MEMO_TAG_ANCHOR`]-tagged memo, plus the resume index
    /// for the next pass.
    ///
    /// Intentionally re-derives the IVK and re-fetches notes independently
    /// of the wallet's own sync coordinator, which cannot recover memos —
    /// see the linked design doc for why this redundant work is the
    /// deliberate near-term tradeoff.
    pub async fn orchardpay_scan_incoming_anchor_memos(
        &self,
        sdk: &Sdk,
        seed_hash: &WalletSeedHash,
        network: Network,
        start_index: u64,
    ) -> Result<(Vec<Identifier>, u64), TaskError> {
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
                let mut stream =
                    std::pin::pin!(sync_shielded_notes_stream(sdk, &ivk, start_index, None));
                while let Some(batch) = stream.next().await {
                    let batch = batch.map_err(|e| {
                        TaskError::OrchardPay(OrchardPayError::MemoScanFailed {
                            source: Box::new(e),
                        })
                    })?;

                    for note in &batch.notes {
                        if let Some((_, _, memo)) = try_decrypt_note_with_memo(&ivk, note)
                            && memo[..4] == MEMO_TAG_ANCHOR
                        {
                            let doc_id_bytes: [u8; 32] =
                                memo[4..].try_into().expect("memo is 36 bytes, tag is 4");
                            found.push(Identifier::from(doc_id_bytes));
                        }
                    }

                    next_start_index = if batch.is_partial {
                        batch.start_index
                    } else {
                        batch.start_index + batch.notes.len() as u64
                    };
                }

                Ok((found, next_start_index))
            })
            .await
    }
}
