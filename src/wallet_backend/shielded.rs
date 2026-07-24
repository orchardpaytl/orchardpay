//! Shielded-pool (Orchard) operations on [`WalletBackend`].
//!
//! `platform-wallet` is always built with the `shielded` Cargo feature in
//! DET (added in Phase A).  No DET-level opt-out exists, so these methods
//! are unconditionally available.  The fund-moving ops and reads consumed by
//! `run_shielded_task` / `ensure_shielded_bound` are wired (Phase D); the
//! activity-log read (`shielded_activity`) reads the coordinator's
//! already-synced local store directly — no new network calls, no new
//! persisted state.

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::MEMO_TAG_ANCHOR;
use crate::backend_task::orchardpay::messages::MEMO_TAG_PAYMENT;
use crate::model::orchardpay::{ShieldedActivityRow, ShieldedNoteKind};
use crate::model::wallet::WalletSeedHash;
use dash_sdk::platform::Identifier;
use platform_wallet::wallet::shielded::{
    ShieldedNote, ShieldedOutgoingNote, ShieldedStore, SubwalletId,
};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::{
    DetPlatformSigner, DetSigner, PlatformPathIndex, WalletBackend, map_shielded_op_error,
};

impl WalletBackend {
    /// Resolve the network-scoped shielded coordinator.
    ///
    /// Returns `ShieldedNotConfigured` when `configure_shielded` was not called
    /// during backend construction (should never happen in practice — it is
    /// called unconditionally in `WalletBackend::new`).
    async fn shielded_coordinator_arc(
        &self,
    ) -> Result<
        std::sync::Arc<platform_wallet::wallet::shielded::NetworkShieldedCoordinator>,
        TaskError,
    > {
        self.inner
            .pwm
            .shielded_coordinator()
            .await
            .ok_or(TaskError::ShieldedNotConfigured)
    }

    /// Idempotently bind Orchard ZIP-32 keys for `seed_hash` to the shielded
    /// coordinator.  A no-op when the wallet is already bound; one call needed
    /// per wallet per process lifetime.
    ///
    /// Called from `bootstrap_wallet_addresses_jit` (Phase C-bind) inside the
    /// existing `with_secret_session` scope; also callable directly for the
    /// MCP headless path.
    pub(crate) async fn ensure_shielded_bound(
        &self,
        seed_hash: &WalletSeedHash,
        seed: &[u8],
    ) -> Result<(), TaskError> {
        let wallet = self.resolve_wallet(seed_hash).await?;
        if wallet.is_shielded_bound().await {
            return Ok(());
        }
        let coordinator = self.shielded_coordinator_arc().await?;
        wallet
            .bind_shielded(seed, &[0], &coordinator)
            .await
            .map_err(|e| TaskError::WalletBackend {
                source: Arc::new(e),
            })
    }

    /// Bind Orchard keys for `seed_hash` by resolving its HD seed just-in-time
    /// through the [`SecretAccess`](super::SecretAccess) chokepoint, then delegating to
    /// [`Self::ensure_shielded_bound`].
    ///
    /// The headless sibling of the Phase-C-bind call in
    /// `bootstrap_wallet_addresses_jit`: an unprotected wallet resolves
    /// prompt-free via the no-passphrase fast-path; a protected one needs its
    /// seed already promoted to the session cache. Idempotent — exits
    /// immediately when the wallet is already bound. The Phase-G `shielded_init`
    /// MCP tool uses this so an agent can bind a wallet without a GUI prompt.
    #[cfg(any(feature = "mcp", feature = "cli"))]
    pub(crate) async fn ensure_shielded_bound_jit(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<(), TaskError> {
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret_session(&scope, async |session| {
                let plaintext = session.plaintext();
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                self.ensure_shielded_bound(seed_hash, seed).await
            })
            .await
    }

    /// Warm the Orchard proving key so the first shielded spend does not block.
    ///
    /// The Halo2 proving key takes ~30 s to build on first use; this primes the
    /// process-global cache ahead of time. Runs on a blocking thread so the
    /// async runtime keeps serving other work during the build, and is
    /// idempotent — a second call returns immediately. Returns whether the key
    /// is ready afterwards (a `spawn_blocking` panic leaves it unbuilt → `false`).
    /// The Phase-G `shielded_init` MCP tool calls this during headless setup.
    #[cfg(any(feature = "mcp", feature = "cli"))]
    pub(crate) async fn warm_shielded_prover(&self) -> bool {
        tokio::task::spawn_blocking(|| {
            let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
            prover.warm_up();
            prover.is_ready()
        })
        .await
        .unwrap_or(false)
    }

    /// Fund the shielded pool from a Core asset lock through the upstream
    /// orchestrator pipeline.
    ///
    /// Mirrors `fund_platform_address` exactly: the `asset_lock_signer` is a
    /// `DetSigner` borrowed from the held JIT session, and the upstream method
    /// owns the full IS→CL fallback + `consume_asset_lock` path.  A single
    /// `(recipient, None)` entry passes the whole lock value (minus the flat
    /// shielded fee) to `recipient`.
    ///
    /// The Orchard prover is created internally via
    /// `CachedOrchardProver::new()` — callers do not supply a prover.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn shield_from_asset_lock(
        &self,
        seed_hash: &WalletSeedHash,
        funding: platform_wallet::wallet::asset_lock::AssetLockFunding,
        recipient: dash_sdk::dpp::address_funds::OrchardAddress,
        dummy_outputs: usize,
        settings: Option<dash_sdk::platform::transition::put_settings::PutSettings>,
    ) -> Result<(), TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret_session(&scope, async |session| {
                let asset_lock_signer =
                    DetSigner::from_held(session.plaintext(), self.inner.network);
                let wallet = self.resolve_wallet(seed_hash).await?;
                let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
                wallet
                    .shielded_fund_from_asset_lock(
                        &coordinator,
                        funding,
                        vec![(recipient, None)],
                        &asset_lock_signer,
                        &prover,
                        None,
                        dummy_outputs,
                        settings,
                        // User-facing funding: wait indefinitely for the
                        // ChainLock (the broadcast lock is pending, never failed).
                        None,
                    )
                    .await
                    .map_err(map_shielded_op_error)
            })
            .await
    }

    /// Shield platform-address credits (Type 15) into the Orchard pool.
    ///
    /// The `signer` authorises the per-address `AddressWitness`; it is a
    /// `DetPlatformSigner` built from the held JIT seed and `path_index`.
    /// Build `path_index` via `PlatformPathIndex::from_wallet` before calling —
    /// the same pattern as `fund_platform_address`.
    ///
    /// The Orchard prover is created internally via
    /// `CachedOrchardProver::new()` — callers do not supply a prover.
    pub(crate) async fn shield_from_balance(
        &self,
        seed_hash: &WalletSeedHash,
        path_index: &PlatformPathIndex,
        shielded_account: u32,
        payment_account: u32,
        amount: u64,
    ) -> Result<(), TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let scope = Self::hd_scope(seed_hash);
        self.inner
            .secret_access
            .with_secret_session(&scope, async |session| {
                let plaintext = session.plaintext();
                let seed = plaintext.expose_hd_seed().ok_or(TaskError::WalletLocked)?;
                let signer = DetPlatformSigner::from_held(seed, self.inner.network, path_index);
                let wallet = self.resolve_wallet(seed_hash).await?;
                let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
                wallet
                    .shielded_shield_from_account(
                        &coordinator,
                        shielded_account,
                        payment_account,
                        amount,
                        &signer,
                        &prover,
                    )
                    .await
                    .map_err(map_shielded_op_error)
            })
            .await
    }

    /// Shielded → shielded transfer from `account`'s notes to `recipient`.
    ///
    /// No seed scope needed — the Orchard ASK is already resident in the
    /// wallet's bound `shielded_keys` slot from `ensure_shielded_bound`.
    ///
    /// The Orchard prover is created internally via
    /// `CachedOrchardProver::new()` — callers do not supply a prover.
    pub(crate) async fn shielded_transfer(
        &self,
        seed_hash: &WalletSeedHash,
        account: u32,
        recipient_raw_43: &[u8; 43],
        amount: u64,
        memo: [u8; 36],
    ) -> Result<(), TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let wallet = self.resolve_wallet(seed_hash).await?;
        let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
        let result = wallet
            .shielded_transfer_to(
                &coordinator,
                account,
                recipient_raw_43,
                amount,
                memo,
                &prover,
            )
            .await
            .map_err(map_shielded_op_error);
        if result.is_ok() {
            self.inner.connection_status.note_shielded_send_broadcast();
        }
        result
    }

    /// Unshield from `account`'s notes to a transparent platform address
    /// (bech32m `"dash1…"` / `"tdash1…"` string).
    ///
    /// No seed scope needed — keys are already bound.
    ///
    /// The Orchard prover is created internally via
    /// `CachedOrchardProver::new()` — callers do not supply a prover.
    pub(crate) async fn shielded_unshield(
        &self,
        seed_hash: &WalletSeedHash,
        account: u32,
        to_platform_addr_bech32m: &str,
        amount: u64,
    ) -> Result<(), TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let wallet = self.resolve_wallet(seed_hash).await?;
        let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
        let result = wallet
            .shielded_unshield_to(
                &coordinator,
                account,
                to_platform_addr_bech32m,
                amount,
                &prover,
            )
            .await
            .map_err(map_shielded_op_error);
        if result.is_ok() {
            self.inner.connection_status.note_shielded_send_broadcast();
        }
        result
    }

    /// Withdraw from `account`'s notes to a Core L1 address (Base58Check).
    ///
    /// No seed scope needed — keys are already bound.
    ///
    /// The Orchard prover is created internally via
    /// `CachedOrchardProver::new()` — callers do not supply a prover.
    pub(crate) async fn shielded_withdraw(
        &self,
        seed_hash: &WalletSeedHash,
        account: u32,
        to_core_address: &str,
        amount: u64,
        core_fee_per_byte: u32,
    ) -> Result<(), TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let wallet = self.resolve_wallet(seed_hash).await?;
        let prover = platform_wallet::wallet::shielded::CachedOrchardProver::new();
        let result = wallet
            .shielded_withdraw_to(
                &coordinator,
                account,
                to_core_address,
                amount,
                core_fee_per_byte,
                &prover,
            )
            .await
            .map_err(map_shielded_op_error);
        if result.is_ok() {
            self.inner.connection_status.note_shielded_send_broadcast();
        }
        result
    }

    /// Per-account unspent shielded balance for `seed_hash`'s wallet.
    ///
    /// Returns an empty map when the wallet is not bound or has no shielded
    /// balance.  This is the push-snapshot producer (Phase E): the result is
    /// written into `AppContext::shielded_balances` by `on_shielded_sync_completed`.
    pub(crate) async fn shielded_balances(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<std::collections::BTreeMap<u32, u64>, TaskError> {
        let coordinator = self.shielded_coordinator_arc().await?;
        let wallet = self.resolve_wallet(seed_hash).await?;
        wallet
            .shielded_balances(&coordinator)
            .await
            .map_err(|e| TaskError::WalletBackend {
                source: Arc::new(e),
            })
    }

    /// The default Orchard payment address for `account` on `seed_hash`'s wallet
    /// (raw 43-byte representation).  Returns `None` if the wallet is not bound
    /// or `account` is not registered.
    pub async fn shielded_default_address(
        &self,
        seed_hash: &WalletSeedHash,
        account: u32,
    ) -> Result<Option<[u8; 43]>, TaskError> {
        let wallet = self.resolve_wallet(seed_hash).await?;
        Ok(wallet.shielded_default_address(account).await)
    }

    /// Force an immediate shielded sync pass (network-wide across every bound
    /// wallet on the coordinator).
    ///
    /// `sync_now` fires `on_shielded_sync_completed` synchronously before it
    /// returns, so the [`EventBridge`](super::EventBridge) has already written the post-sync
    /// per-wallet balances into `AppContext::shielded_balances` (Phase E) by the
    /// time this resolves — a subsequent `shielded_balance_credits` read sees
    /// the fresh figure. The 60-second background loop is the normal driver;
    /// this is the explicit-refresh primitive for the backend-e2e lifecycle test
    /// and the Phase-G `shielded_sync` MCP tool. A no-op when shielded support
    /// was never configured (empty coordinator → empty pass).
    pub async fn sync_shielded_now(&self, force: bool) {
        self.inner.pwm.shielded_sync_arc().sync_now(force).await;
    }

    /// Read-only shielded transaction history (sent + received) for
    /// `seed_hash`'s account-0 subwallet — the OrchardPay Shielded TXs tab's
    /// diagnostic view. One row per raw note, straight from
    /// `ShieldedStore::get_all_notes` (received) and `get_outgoing_notes`
    /// (sent) — no network calls, no writes, safe to call on every tab
    /// open/refresh.
    ///
    /// Deliberately does **not** use `platform_wallet::wallet::shielded`'s
    /// `derive_activity_from_scan_data` classifier. That helper clusters
    /// events by which fetch-chunk *batch* they were scanned in (its own
    /// doc comment: "on a cold restore one chunk can span many historical
    /// blocks of unrelated operations, which then merge into a single
    /// synthetic entry") — when a batch contains both an outgoing send and
    /// an incoming receipt, the whole cluster becomes one `Sent` entry and
    /// the receipt's value is treated as change and dropped. OrchardPay's
    /// handshake produces exactly that shape (each side both sends its own
    /// anchor-signal transfer and receives the counterparty's, often in the
    /// same batch during a bulk rescan), which silently hid every genuinely
    /// received note behind the "Sent" row. Building rows directly from the
    /// two raw lists sidesteps that limitation entirely.
    ///
    /// `account_index` is fixed at `0`: OrchardPay only ever binds and uses
    /// account 0's default address (see `ensure_shielded_bound`,
    /// `shielded_default_address`).
    ///
    /// Returns an empty list rather than an error when the wallet isn't
    /// bound/registered yet this session — matches this file's existing
    /// "not bound" convention (e.g. [`Self::shielded_default_address`])
    /// rather than surfacing a spurious error for a wallet that simply
    /// hasn't finished startup.
    ///
    /// Received rows get a best-effort memo backfill via
    /// [`WalletBackend::orchardpay_recover_received_memos`] — see that
    /// method's doc comment for why the memo isn't already on the stored
    /// `ShieldedNote` and has to be recovered separately.
    pub async fn shielded_activity(
        &self,
        sdk: &dash_sdk::Sdk,
        seed_hash: &WalletSeedHash,
    ) -> Result<Vec<ShieldedActivityRow>, TaskError> {
        let Some(wallet_id) = self.registered_wallet_id(seed_hash) else {
            return Ok(Vec::new());
        };
        let subwallet_id = SubwalletId::new(wallet_id, 0);

        let coordinator = self.shielded_coordinator_arc().await?;
        let (notes, outgoing) = {
            let store = coordinator.store().read().await;
            let notes = store.get_all_notes(subwallet_id).map_err(|e| {
                TaskError::ShieldedActivityUnavailable {
                    source: Box::new(e),
                }
            })?;
            let outgoing = store.get_outgoing_notes(subwallet_id).map_err(|e| {
                TaskError::ShieldedActivityUnavailable {
                    source: Box::new(e),
                }
            })?;
            (notes, outgoing)
        };

        let positions: std::collections::BTreeSet<u64> = notes.iter().map(|n| n.position).collect();
        let recovered_memos = self
            .orchardpay_recover_received_memos(sdk, seed_hash, &positions)
            .await;

        let mut rows: Vec<ShieldedActivityRow> = Vec::with_capacity(notes.len() + outgoing.len());
        for note in &notes {
            let memo_label = match recovered_memos.get(&note.position) {
                Some(memo) => decode_memo_label(memo),
                None => "Memo not available for received notes".to_string(),
            };
            rows.push(ShieldedActivityRow {
                kind: ShieldedNoteKind::Received {
                    spent: note.is_spent,
                },
                amount_credits: note.value,
                memo_label,
                block_height: Some(note.block_height),
                pending: false,
            });
        }
        for out in &outgoing {
            rows.push(ShieldedActivityRow {
                kind: ShieldedNoteKind::Sent,
                amount_credits: out.value,
                memo_label: decode_memo_label(&out.memo),
                block_height: Some(out.block_height),
                pending: false,
            });
        }
        rows.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        Ok(rows)
    }

    /// Every locally-known outgoing [`MEMO_TAG_PAYMENT`]-tagged transfer for
    /// `seed_hash`'s account-0 subwallet, keyed by the `Payment`/
    /// `PaymentRequest` document ID its memo referenced, valued at the
    /// credits actually sent.
    ///
    /// This is the recovery path for "did I already fulfill this
    /// `PaymentRequest`" on the *payer's* side: `send_payment` also writes
    /// an immediate optimistic record via
    /// `WalletBackend::orchardpay_set_verified_payment_amount` right after
    /// a successful fulfillment broadcast (so the UI flips to "Paid"
    /// without waiting on a sync pass), but that's local k/v state — lost
    /// on reinstall or a new device, same as any other local cache. This
    /// method reconstructs the same answer straight from chain data: an
    /// outgoing note's memo is already available at sync time (contrast
    /// [`WalletBackend::orchardpay_recover_received_memos`], needed only
    /// for *received* notes), so no separate scan-and-cache mechanism is
    /// needed here — just read the already-synced local store fresh on
    /// every call.
    ///
    /// Returns an empty map rather than an error when the wallet isn't
    /// bound/registered yet this session, matching this file's existing
    /// "not bound" convention.
    pub async fn orchardpay_outgoing_payments_by_document(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<BTreeMap<Identifier, u64>, TaskError> {
        let Some(wallet_id) = self.registered_wallet_id(seed_hash) else {
            return Ok(BTreeMap::new());
        };
        let subwallet_id = SubwalletId::new(wallet_id, 0);

        let coordinator = self.shielded_coordinator_arc().await?;
        let outgoing = {
            let store = coordinator.store().read().await;
            store.get_outgoing_notes(subwallet_id).map_err(|e| {
                TaskError::ShieldedActivityUnavailable {
                    source: Box::new(e),
                }
            })?
        };

        Ok(outgoing_payments_by_document(&outgoing))
    }

    /// Every locally-known incoming [`MEMO_TAG_PAYMENT`]-tagged transfer
    /// for `seed_hash`'s account-0 subwallet, keyed by the `PaymentRequest`
    /// document ID its memo referenced, valued at the credits actually
    /// received.
    ///
    /// This is the *requester's*-side counterpart to
    /// [`Self::orchardpay_outgoing_payments_by_document`], and exists to
    /// close the same kind of consistency gap: the separate incoming-memo
    /// scan (`orchardpay_scan_incoming_memos`, which caches its findings
    /// via `orchardpay_set_verified_payment_amount`) walks the raw note
    /// stream independently of this wallet's own normal sync coordinator,
    /// on its own resumable cursor — so it can genuinely lag behind a note
    /// that's already visible in [`Self::shielded_activity`] (the Shielded
    /// TXs tab), which reads the coordinator's already-synced local store
    /// directly. A `PaymentRequest`'s "paid" status should never be less
    /// current than what the Shielded TXs tab already shows for the same
    /// note, so this reads the same already-synced notes and recovers
    /// their memos the same way `shielded_activity` does (via
    /// [`Self::orchardpay_recover_received_memos`]), independent of the
    /// memo-scan's own cursor.
    ///
    /// Returns an empty map rather than an error when the wallet isn't
    /// bound/registered yet this session, matching this file's existing
    /// "not bound" convention.
    pub async fn orchardpay_incoming_payments_by_document(
        &self,
        sdk: &dash_sdk::Sdk,
        seed_hash: &WalletSeedHash,
    ) -> Result<BTreeMap<Identifier, u64>, TaskError> {
        let Some(wallet_id) = self.registered_wallet_id(seed_hash) else {
            return Ok(BTreeMap::new());
        };
        let subwallet_id = SubwalletId::new(wallet_id, 0);

        let coordinator = self.shielded_coordinator_arc().await?;
        let notes = {
            let store = coordinator.store().read().await;
            store.get_all_notes(subwallet_id).map_err(|e| {
                TaskError::ShieldedActivityUnavailable {
                    source: Box::new(e),
                }
            })?
        };

        let positions: std::collections::BTreeSet<u64> = notes.iter().map(|n| n.position).collect();
        let recovered_memos = self
            .orchardpay_recover_received_memos(sdk, seed_hash, &positions)
            .await;

        Ok(incoming_payments_by_document(&notes, &recovered_memos))
    }
}

/// Pure parsing step behind
/// [`WalletBackend::orchardpay_outgoing_payments_by_document`]: filters
/// `outgoing` down to [`MEMO_TAG_PAYMENT`]-tagged notes and maps each to
/// the document ID its memo's 32-byte suffix names. A short or malformed
/// memo — never produced by this wallet's own send path, but not assumed —
/// is skipped rather than treated as a match.
fn outgoing_payments_by_document(outgoing: &[ShieldedOutgoingNote]) -> BTreeMap<Identifier, u64> {
    outgoing
        .iter()
        .filter_map(|note| {
            if note.memo.len() < 36 || note.memo[..4] != MEMO_TAG_PAYMENT {
                return None;
            }
            let document_id = Identifier::from_bytes(&note.memo[4..36]).ok()?;
            Some((document_id, note.value))
        })
        .collect()
}

/// Pure parsing step behind
/// [`WalletBackend::orchardpay_incoming_payments_by_document`]: pairs
/// `notes` with their recovered memo (by position) and maps each
/// [`MEMO_TAG_PAYMENT`]-tagged one to the document ID its memo names. A
/// note with no recovered memo (not yet reached by
/// `orchardpay_recover_received_memos`, e.g. a network hiccup on that
/// chunk) is skipped rather than treated as a non-match — the caller
/// re-derives this fresh on every call, so it's picked up on the next one.
fn incoming_payments_by_document(
    notes: &[ShieldedNote],
    recovered_memos: &BTreeMap<u64, [u8; 36]>,
) -> BTreeMap<Identifier, u64> {
    notes
        .iter()
        .filter_map(|note| {
            let memo = recovered_memos.get(&note.position)?;
            if memo[..4] != MEMO_TAG_PAYMENT {
                return None;
            }
            let document_id = Identifier::from_bytes(&memo[4..36]).ok()?;
            Some((document_id, note.value))
        })
        .collect()
}

/// Decode an outgoing note's raw memo against OrchardPay's known tags.
/// Empty or all-zero (the `DashMemo` "no memo" sentinel) → "No memo"; a
/// recognized 4-byte tag → its plain-language meaning; anything else →
/// truncated hex so an unrecognized payload is still visible for
/// debugging.
fn decode_memo_label(memo: &[u8]) -> String {
    if memo.is_empty() || memo.iter().all(|&b| b == 0) {
        return "No memo".to_string();
    }
    if memo.starts_with(&MEMO_TAG_ANCHOR) {
        "Contact request signal".to_string()
    } else if memo.starts_with(&MEMO_TAG_PAYMENT) {
        "OrchardPay payment".to_string()
    } else {
        format!("Unrecognized memo: {}", hex::encode(memo))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShieldedNote, ShieldedOutgoingNote, decode_memo_label, incoming_payments_by_document,
        outgoing_payments_by_document,
    };
    use crate::backend_task::orchardpay::contact_anchor::MEMO_TAG_ANCHOR;
    use crate::backend_task::orchardpay::messages::MEMO_TAG_PAYMENT;
    use dash_sdk::platform::Identifier;
    use std::collections::BTreeMap;

    fn outgoing_note(memo: Vec<u8>, value: u64) -> ShieldedOutgoingNote {
        ShieldedOutgoingNote {
            cmx: [0u8; 32],
            recipient: vec![0u8; 43],
            value,
            memo,
            block_height: 100,
        }
    }

    fn received_note(position: u64, value: u64) -> ShieldedNote {
        ShieldedNote {
            position,
            cmx: [0u8; 32],
            nullifier: [0u8; 32],
            block_height: 100,
            is_spent: false,
            value,
            note_data: Vec::new(),
        }
    }

    #[test]
    fn recognizes_contact_anchor_memo_tag() {
        let mut memo = vec![0u8; 36];
        memo[..4].copy_from_slice(&MEMO_TAG_ANCHOR);
        assert_eq!(decode_memo_label(&memo), "Contact request signal");
    }

    #[test]
    fn recognizes_payment_memo_tag() {
        let mut memo = vec![0u8; 36];
        memo[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        assert_eq!(decode_memo_label(&memo), "OrchardPay payment");
    }

    #[test]
    fn unrecognized_memo_falls_back_to_hex() {
        let memo = vec![0xABu8; 36];
        assert_eq!(
            decode_memo_label(&memo),
            format!("Unrecognized memo: {}", hex::encode(&memo))
        );
    }

    #[test]
    fn empty_memo_is_labeled_explicitly() {
        assert_eq!(decode_memo_label(&[]), "No memo");
    }

    #[test]
    fn maps_payment_tagged_outgoing_notes_by_document_id() {
        let document_id = Identifier::from([7u8; 32]);
        let mut memo = vec![0u8; 36];
        memo[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        memo[4..].copy_from_slice(&document_id.to_buffer());

        let map = outgoing_payments_by_document(&[outgoing_note(memo, 12_345)]);

        assert_eq!(map.get(&document_id), Some(&12_345));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn ignores_notes_without_the_payment_tag() {
        let map = outgoing_payments_by_document(&[outgoing_note(vec![0u8; 36], 999)]);
        assert!(map.is_empty());
    }

    #[test]
    fn ignores_a_memo_shorter_than_the_tagged_document_id_layout() {
        let mut memo = vec![0u8; 10];
        memo[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        let map = outgoing_payments_by_document(&[outgoing_note(memo, 1)]);
        assert!(map.is_empty());
    }

    #[test]
    fn keeps_multiple_distinct_payments_separate() {
        let doc_a = Identifier::from([1u8; 32]);
        let doc_b = Identifier::from([2u8; 32]);
        let mut memo_a = vec![0u8; 36];
        memo_a[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        memo_a[4..].copy_from_slice(&doc_a.to_buffer());
        let mut memo_b = vec![0u8; 36];
        memo_b[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        memo_b[4..].copy_from_slice(&doc_b.to_buffer());

        let map = outgoing_payments_by_document(&[
            outgoing_note(memo_a, 100),
            outgoing_note(memo_b, 200),
        ]);

        assert_eq!(map.get(&doc_a), Some(&100));
        assert_eq!(map.get(&doc_b), Some(&200));
    }

    #[test]
    fn maps_payment_tagged_received_notes_by_document_id() {
        let document_id = Identifier::from([9u8; 32]);
        let mut memo = [0u8; 36];
        memo[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
        memo[4..].copy_from_slice(&document_id.to_buffer());
        let mut recovered = BTreeMap::new();
        recovered.insert(5u64, memo);

        let map = incoming_payments_by_document(&[received_note(5, 555)], &recovered);

        assert_eq!(map.get(&document_id), Some(&555));
    }

    #[test]
    fn a_note_with_no_recovered_memo_is_skipped_not_treated_as_unmatched() {
        // Position 5 has no entry in `recovered` at all — e.g. that chunk's
        // memo recovery hasn't completed yet — so it must be absent from
        // the result, not silently mapped as "no payment".
        let map = incoming_payments_by_document(&[received_note(5, 1)], &BTreeMap::new());
        assert!(map.is_empty());
    }

    #[test]
    fn ignores_received_notes_without_the_payment_tag() {
        let mut recovered = BTreeMap::new();
        recovered.insert(1u64, [0u8; 36]);
        let map = incoming_payments_by_document(&[received_note(1, 1)], &recovered);
        assert!(map.is_empty());
    }
}
