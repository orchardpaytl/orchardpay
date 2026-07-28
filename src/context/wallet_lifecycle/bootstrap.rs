//! Address bootstrap and post-unlock warmup: deriving addresses, reconciling
//! managed identities, warming auth-key caches, and queuing identity discovery.

use super::*;

impl AppContext {
    /// Whether `wallet` still needs its bootstrap address set derived.
    ///
    /// `true` for a fresh wallet (no known addresses) or one created with only
    /// a Core address (no Platform-payment addresses yet). Idempotent: a
    /// fully-bootstrapped wallet returns `false`.
    fn wallet_needs_bootstrap(guard: &Wallet) -> bool {
        // INTENTIONAL: Bootstrap checks only PlatformPayment address
        // type. Other platform address types may trigger redundant
        // re-derivation, but `bootstrap_known_addresses` is idempotent so this
        // is safe.
        let has_platform_addresses = guard.watched_addresses.values().any(|info| {
            info.path_reference == crate::model::wallet::DerivationPathReference::PlatformPayment
        });
        guard.known_addresses.is_empty() || !has_platform_addresses
    }

    /// Bootstrap a wallet's address set from a borrowed HD seed.
    ///
    /// The sync bridge used by the **fresh-register** path only
    /// ([`Self::register_wallet`]): a just-created or just-imported wallet's
    /// seed is in the caller's hand from construction, so it is passed in by
    /// borrow rather than read from any parked field — an open `Wallet` parks
    /// no seed (R3). The borrow is fanned down into the seed-as-parameter
    /// [`Wallet::bootstrap_known_addresses`]; no `bootstrap_*` child reaches
    /// back into the wallet for a seed. A locked wallet is skipped and
    /// bootstraps later via [`Self::bootstrap_wallet_addresses_jit`] once its
    /// seed is resolvable through the chokepoint.
    pub fn bootstrap_wallet_addresses(&self, wallet: &Arc<RwLock<Wallet>>, seed: &[u8; 64]) {
        if let Ok(mut guard) = wallet.write() {
            if !guard.is_open() {
                tracing::debug!("Skipping address bootstrap for locked wallet");
                return;
            }
            if Self::wallet_needs_bootstrap(&guard) {
                tracing::info!(wallet = %hex::encode(guard.seed_hash()), "Bootstrapping wallet addresses");
                guard.bootstrap_known_addresses(seed, self);
            }
        }
    }

    /// Bootstrap a wallet's address set by resolving its HD seed just-in-time
    /// through the [`SecretAccess`](crate::wallet_backend::SecretAccess)
    /// chokepoint, holding one `with_secret_session` for the whole bootstrap
    /// run.
    ///
    /// The async sibling of [`Self::bootstrap_wallet_addresses`] for the
    /// cold-boot path. To preserve the prompt-free startup contract it operates
    /// only on wallets whose seed already resolves without asking the user — an
    /// unprotected wallet (resolved via the chokepoint's no-passphrase
    /// fast-path) or a protected one whose seed the user already promoted to the
    /// session cache on unlock. A still-locked protected wallet is left for its
    /// unlock gesture to bootstrap, exactly as before; this method never forces
    /// a passphrase prompt at startup.
    ///
    /// This is also the W2 cold-boot reconciliation point: inside
    /// the same prompt-free seed scope it registers any wallet present in DET
    /// sidecars but absent from the upstream SPV persistor (migrated installs,
    /// wallets created before the fix, post-reset), so received funds become
    /// visible without a launch-time password prompt. Registration is
    /// independent of address bootstrap: an already-bootstrapped wallet that
    /// was never registered upstream still gets registered here.
    pub async fn bootstrap_wallet_addresses_jit(&self, wallet: &Arc<RwLock<Wallet>>) {
        let Ok(backend) = self.wallet_backend() else {
            return;
        };
        let seed_hash = {
            let Ok(guard) = wallet.read() else {
                return;
            };
            // Gate on the open seed being resolvable prompt-free: an open
            // wallet at cold boot is either unprotected (no-prompt fast-path) or
            // already session-cached via the unlock gesture. A locked protected
            // wallet is skipped to avoid a surprise startup prompt.
            if !guard.is_open() {
                return;
            }
            guard.seed_hash()
        };

        // An open wallet always enters the seed scope: shielded key binding runs
        // on every cold boot and `ensure_shielded_bound` is idempotent (upstream
        // does an in-memory check and returns immediately when already bound), so
        // there is no cheap pre-check that would let us skip the scope. Address
        // bootstrap and upstream registration are re-checked inside the scope, so
        // entering with nothing to do is harmless. The upstream 60 s
        // ShieldedSyncManager loop picks up any newly bound wallets automatically.
        let wallet = Arc::clone(wallet);
        let result = backend
            .secret_access()
            .with_secret_session(
                &crate::wallet_backend::SecretScope::HdSeed { seed_hash },
                async |session| {
                    let plaintext = session.plaintext();
                    let seed = plaintext
                        .expose_hd_seed()
                        .ok_or(TaskError::WalletLocked)?;
                    if let Ok(mut guard) = wallet.write() {
                        // Re-check under the write lock: a concurrent bootstrap
                        // may have run between the read above and here.
                        if Self::wallet_needs_bootstrap(&guard) {
                            tracing::info!(wallet = %hex::encode(seed_hash), "Bootstrapping wallet addresses (JIT seed)");
                            guard.bootstrap_known_addresses(seed, self);
                        }
                    }
                    // W2 cold-boot reconciliation: register with the upstream
                    // SPV backend if this wallet is not yet known to it, using
                    // the seed already open in this scope. Idempotent and
                    // genesis-floored so pre-existing deposits are found.
                    // Best-effort — a failure is retried on the
                    // next boot.
                    if let Err(error) = backend.ensure_upstream_registered(&seed_hash, seed).await {
                        tracing::warn!(
                            wallet = %hex::encode(seed_hash),
                            %error,
                            "W2 upstream registration failed; will retry at next cold boot"
                        );
                    }
                    // Identity reconcile: register every DET-known wallet-owned
                    // identity into the upstream manager so identity ops (top-up)
                    // can find them. Seed-free, idempotent; runs after the wallet
                    // is upstream-registered. Best-effort — retried next boot/unlock.
                    self.reconcile_managed_identities(&backend, &seed_hash).await;
                    // Lazily bind Orchard ZIP-32 keys for this wallet.
                    // Best-effort — a failure only defers the first shielded op prompt.
                    // The upstream ShieldedSyncManager 60s loop picks up any newly
                    // bound wallets automatically; no manual sync trigger needed.
                    if let Err(error) =
                        backend.ensure_shielded_bound(&seed_hash, seed).await
                    {
                        tracing::debug!(
                            wallet = %hex::encode(seed_hash),
                            %error,
                            "Shielded bind deferred; will retry on next unlock"
                        );
                    } else {
                        // Keys are bound, so the receive address is now readable
                        // from the upstream key slot. Cache it for the frame loop.
                        self.cache_shielded_receive_address(&backend, &seed_hash).await;
                    }
                    // Register every established contact's DIP-15 receiving
                    // account so SPV watches the addresses each contact pays us
                    // at. Seed-bearing (the receiving path is hardened) and
                    // reachable only here where the seed is already open, so a
                    // locked wallet is skipped, never prompted. Best-effort;
                    // re-runs every boot/unlock because upstream keeps contact
                    // accounts in runtime state only.
                    self.register_established_contact_accounts(&backend, &seed_hash, seed)
                        .await;
                    // OrchardPay: fire any due ScheduledAnchorReplace markers
                    // (finding 5 of the 2026-07-27 adversarial audit) — the
                    // "on next app use" trigger for the deferred anchorData
                    // replace. Not seed-bearing itself, but runs alongside
                    // the other best-effort catch-up passes in this same
                    // cold-boot/unlock scope, which is exactly the "app is
                    // actually being used" moment the delay is designed
                    // around. Best-effort; re-checked every boot/unlock.
                    self.fire_due_scheduled_anchor_replaces(&seed_hash).await;
                    // D4b lazy warm: populate the identity-auth public-key
                    // cache for the identities this wallet already knows, in
                    // the same prompt-free seed scope, so the steady-state
                    // identity-auth reads are seed-free. Best-effort — a warm
                    // failure only forgoes the optimisation.
                    if let Ok(guard) = wallet.read() {
                        self.warm_auth_pubkey_cache(&backend, &guard, seed, seed_hash);
                    }
                    Ok(())
                },
            )
            .await;
        if let Err(e) = result {
            tracing::debug!(
                wallet = %hex::encode(seed_hash),
                error = %e,
                "JIT address bootstrap skipped"
            );
        }
    }

    /// Publish `seed_hash`'s shielded receive address into the frame-safe
    /// snapshot the Shielded tab reads ([`AppContext::shielded_receive_address`]).
    ///
    /// Reads Orchard **account 0** — the only account DET binds and the only one
    /// its spend path (`shielded_transfer(.., 0, ..)`) can spend from — through
    /// the upstream-owned key slot, so the address shown is derived from the very
    /// `OrchardKeySet` the coordinator scans with. Runs on the async backend
    /// side, never in the frame loop.
    ///
    /// Best-effort: an unbound wallet or a malformed payload leaves the snapshot
    /// untouched and the tab keeps its "not ready yet" copy rather than showing a
    /// stale or unusable address.
    pub(super) async fn cache_shielded_receive_address(
        &self,
        backend: &WalletBackend,
        seed_hash: &WalletSeedHash,
    ) {
        let raw = match backend.shielded_default_address(seed_hash, 0).await {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                tracing::debug!(
                    wallet = %hex::encode(seed_hash),
                    "Shielded receive address unavailable; wallet has no bound Orchard account 0"
                );
                return;
            }
            Err(error) => {
                tracing::debug!(
                    wallet = %hex::encode(seed_hash),
                    %error,
                    "Shielded receive address read failed; will retry on next boot/unlock"
                );
                return;
            }
        };
        match crate::model::address::encode_shielded_address(&raw, self.network) {
            Ok(address) => {
                if let Ok(mut cache) = self.shielded_addresses.lock() {
                    cache.insert(*seed_hash, address);
                }
            }
            Err(error) => tracing::warn!(
                wallet = %hex::encode(seed_hash),
                %error,
                "Shielded receive address could not be encoded; leaving it unset"
            ),
        }
    }

    /// Register every DET-known, wallet-owned identity for `seed_hash` into the
    /// upstream `IdentityManager`, so identity ops that look identities up there
    /// (currently: top-up) find them instead of raising `IdentityNotFound`.
    ///
    /// Best-effort, idempotent, and **seed-free** — a per-identity failure is
    /// logged and never aborts the rest. Called inside
    /// [`Self::bootstrap_wallet_addresses_jit`]'s seed scope after upstream
    /// registration (the seam reached from both cold boot and unlock); the seed
    /// is not used, so it is also safe while the wallet is locked.
    pub(super) async fn reconcile_managed_identities(
        &self,
        backend: &WalletBackend,
        seed_hash: &WalletSeedHash,
    ) {
        use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
        let identities = match self.load_local_qualified_identities_for_wallet(seed_hash) {
            Ok(identities) => identities,
            Err(error) => {
                tracing::warn!(
                    wallet = %hex::encode(seed_hash),
                    %error,
                    "Identity reconcile: sidecar read failed; will retry next boot/unlock"
                );
                return;
            }
        };
        let mut added = 0usize;
        for qi in &identities {
            let Some(index) = qi.wallet_index else {
                continue;
            };
            match backend
                .ensure_identity_managed(seed_hash, &qi.identity, index)
                .await
            {
                Ok(true) => added += 1,
                Ok(false) => {}
                Err(error) => tracing::debug!(
                    identity = %qi.identity.id(),
                    %error,
                    "Identity reconcile deferred; will retry next boot/unlock"
                ),
            }
        }
        if added > 0 {
            tracing::info!(
                wallet = %hex::encode(seed_hash),
                added,
                "Reconciled DET identities into the upstream manager"
            );
        }
    }

    /// Register the DIP-15 receiving accounts of every established contact of
    /// every identity on `seed_hash`, so SPV watches the addresses each contact
    /// pays us at. Best-effort — a failure is logged and retried next unlock.
    ///
    /// Called inside [`Self::bootstrap_wallet_addresses_jit`]'s seed scope, so
    /// the seed is already open and a locked wallet is never reached.
    async fn register_established_contact_accounts(
        &self,
        backend: &WalletBackend,
        seed_hash: &WalletSeedHash,
        seed: &[u8; 64],
    ) {
        let pairs = self.established_contact_pairs(backend, seed_hash).await;
        match backend
            .register_contact_receiving_accounts(seed_hash, seed, &pairs)
            .await
        {
            Ok(0) => {}
            Ok(count) => tracing::info!(
                wallet = %hex::encode(seed_hash),
                count,
                "Registered contact receiving accounts for watching"
            ),
            Err(error) => tracing::debug!(
                wallet = %hex::encode(seed_hash),
                %error,
                "Contact receiving-account registration deferred; will retry next unlock"
            ),
        }
    }

    /// For every OrchardPay contact of every identity on `seed_hash`, fire
    /// a due `ScheduledAnchorReplace` marker if one exists — see the
    /// 2026-07-27 adversarial audit's finding 5 and
    /// `contact_anchor::fire_due_scheduled_anchor_replace`'s doc comment
    /// for the full mechanism. Best-effort per contact; a failure is logged
    /// and never blocks the rest of this pass or the caller's own scope.
    /// Not seed-bearing itself (the marker check needs no secret), but runs
    /// here anyway since this is exactly the "app is being used" moment the
    /// delay is designed around, and `orchardpay_list_contacts` is cheapest
    /// to call once per identity already in hand.
    async fn fire_due_scheduled_anchor_replaces(&self, seed_hash: &WalletSeedHash) {
        use crate::backend_task::orchardpay::contact_anchor::fire_due_scheduled_anchor_replace;
        use dash_sdk::dpp::identity::accessors::IdentityGettersV0;

        let Ok(backend) = self.wallet_backend() else {
            return;
        };
        let Some(contract_id) = self.orchardpay_contract_id() else {
            return;
        };
        let identities = match self.load_local_qualified_identities_for_wallet(seed_hash) {
            Ok(identities) => identities,
            Err(error) => {
                tracing::debug!(
                    wallet = %hex::encode(seed_hash),
                    %error,
                    "Scheduled anchor-replace sweep: sidecar read failed; will retry next boot/unlock"
                );
                return;
            }
        };

        let sdk = self.sdk.load().as_ref().clone();
        for qualified_identity in &identities {
            let owner_id = qualified_identity.identity.id();
            let counterparties = match backend.orchardpay_list_contacts(&contract_id, &owner_id) {
                Ok(counterparties) => counterparties,
                Err(error) => {
                    tracing::debug!(
                        identity = %owner_id,
                        %error,
                        "Scheduled anchor-replace sweep: contact list read failed for this identity"
                    );
                    continue;
                }
            };
            for counterparty_identity_id in counterparties {
                if let Err(error) = fire_due_scheduled_anchor_replace(
                    self,
                    &sdk,
                    qualified_identity,
                    counterparty_identity_id,
                    *seed_hash,
                )
                .await
                {
                    tracing::debug!(
                        identity = %owner_id,
                        counterparty = %counterparty_identity_id,
                        %error,
                        "Scheduled anchor-replace deferred; will retry next boot/unlock"
                    );
                }
            }
        }
    }

    /// Collect `(owner, contact)` identity-id pairs for every accepted contact
    /// of each local identity whose DashPay wallet is `seed_hash`.
    async fn established_contact_pairs(
        &self,
        backend: &WalletBackend,
        seed_hash: &WalletSeedHash,
    ) -> Vec<(
        dash_sdk::platform::Identifier,
        dash_sdk::platform::Identifier,
    )> {
        use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
        use dash_sdk::platform::Identifier;

        let Ok(identities) = self.load_local_qualified_identities() else {
            return Vec::new();
        };
        let view = backend.dashpay_view();
        let mut pairs = Vec::new();
        for identity in &identities {
            if identity.dashpay_wallet_seed_hash().as_ref() != Some(seed_hash) {
                continue;
            }
            let owner = identity.identity.id();
            for contact in view.contacts(&owner).await {
                if contact.contact_status != ContactStatus::Accepted {
                    continue;
                }
                if let Ok(contact_id) = Identifier::from_bytes(&contact.contact_identity_id) {
                    pairs.push((owner, contact_id));
                }
            }
        }
        pairs
    }

    /// Warm the identity-authentication public-key cache (D4b) for the
    /// identities this wallet already knows.
    ///
    /// Called from inside the JIT bootstrap's `with_secret_session` scope,
    /// so the borrowed seed is already in hand and no extra prompt is
    /// raised. Derives the first [`AUTH_PUBKEY_WARM_KEY_COUNT`] auth keys
    /// per known identity index and persists them in one whole-blob write.
    /// Identities discovered later warm lazily on the read path's cold-fill.
    /// Best-effort: a derivation or persist failure is logged and skipped,
    /// because the read path self-heals regardless.
    fn warm_auth_pubkey_cache(
        &self,
        backend: &WalletBackend,
        wallet: &Wallet,
        seed: &[u8; 64],
        seed_hash: WalletSeedHash,
    ) {
        let network = self.network;
        let view = backend.auth_pubkey_cache();
        let mut cache = view.get(network, &seed_hash);
        let mut changed = false;

        for &identity_index in wallet.identities.keys() {
            for key_index in 0..AUTH_PUBKEY_WARM_KEY_COUNT {
                if cache.get(network, identity_index, key_index).is_some() {
                    continue;
                }
                match wallet.identity_authentication_ecdsa_public_key_from_seed(
                    seed,
                    network,
                    identity_index,
                    key_index,
                ) {
                    Ok(public_key) => {
                        changed |= cache.insert(network, identity_index, key_index, &public_key);
                    }
                    Err(error) => {
                        tracing::debug!(
                            wallet = %hex::encode(seed_hash),
                            identity_index,
                            key_index,
                            %error,
                            "Skipping auth-pubkey warm for one key"
                        );
                    }
                }
            }
        }

        if changed && let Err(e) = view.put(network, &seed_hash, &cache) {
            tracing::debug!(
                wallet = %hex::encode(seed_hash),
                error = %e,
                "Failed to persist warmed auth-pubkey cache"
            );
        }
    }

    /// Queue automatic, gap-limited identity discovery for every open wallet,
    /// once per SPV session.
    ///
    /// Fired when Platform becomes reachable (masternode list `Synced`). A
    /// single [`AtomicBool`](std::sync::atomic::AtomicBool) latch makes it run at
    /// most once per session — a re-entrant nudge (e.g. a repeated readiness
    /// event) is a no-op until [`stop_spv`](Self::stop_spv) clears the latch on
    /// the next reconnect.
    ///
    /// Locked, password-protected wallets are skipped here: the sweep runs with
    /// `allow_prompt = false`, so it never pops a passphrase modal for a wallet
    /// the user has not unlocked. Such a wallet is picked up later, with the
    /// user's consent, when it is unlocked
    /// (see [`Self::queue_wallet_identity_discovery`]).
    pub fn queue_all_wallets_identity_discovery(self: &Arc<Self>) {
        use std::sync::atomic::Ordering;

        // One-shot per session: skip if already fired.
        if self
            .identity_autodiscovery_fired
            .swap(true, Ordering::SeqCst)
        {
            tracing::debug!("All-wallets identity discovery already ran this session; skipping");
            return;
        }

        // Snapshot only open wallets — a locked protected wallet hydrates closed
        // (`is_open() == false`) and is skipped so the background sweep cannot
        // trigger a passphrase prompt.
        let open_wallets = self.open_wallets();

        if open_wallets.is_empty() {
            tracing::debug!("No open wallets to run automatic identity discovery for");
            return;
        }

        tracing::info!(
            wallet_count = open_wallets.len(),
            "Starting automatic identity discovery for all open wallets"
        );

        for wallet in open_wallets {
            let ctx = Arc::clone(self);
            let _ = self
                .subtasks
                .spawn_sync("all_wallets_identity_discovery", async move {
                    if let Err(error) = ctx
                        .discover_identities_gap_limited(&wallet, 0, false, None)
                        .await
                    {
                        tracing::warn!(
                            %error,
                            "Automatic identity discovery failed for a wallet"
                        );
                    }
                });
        }
    }

    /// Queue gap-limited identity discovery for a single wallet the user just
    /// unlocked, so a wallet that was locked during the all-wallets sweep still
    /// gets discovered this session.
    ///
    /// Independent of the once-per-session `identity_autodiscovery_fired` latch
    /// (that guards the all-wallets sweep, not per-wallet unlock). Gated on
    /// Platform readiness: if the masternode list is not yet `Synced`, this is a
    /// no-op — the wallet is now open, so the upcoming all-wallets sweep covers
    /// it. The user is present for the unlock, so `allow_prompt = true`; no
    /// prompt occurs anyway because the unlock just promoted the seed to the
    /// session cache. Idempotent with the sweep: discovery is
    /// update-preserving-alias, so a double-run is harmless.
    pub fn queue_unlocked_wallet_identity_discovery(
        self: &Arc<Self>,
        wallet: &Arc<RwLock<Wallet>>,
    ) {
        let ctx = Arc::clone(self);
        let wallet = Arc::clone(wallet);
        let _ = self
            .subtasks
            .spawn_sync("unlocked_wallet_identity_discovery", async move {
                ctx.discover_unlocked_wallet_identities(&wallet).await;
            });
    }

    /// Discover identities after unlock while the wallet seed remains available.
    pub(super) async fn discover_unlocked_wallet_identities(
        self: &Arc<Self>,
        wallet: &Arc<RwLock<Wallet>>,
    ) {
        if !self.connection_status.masternodes_ready() {
            tracing::debug!(
                "Platform not ready yet; deferring unlocked-wallet identity discovery to the all-wallets sweep"
            );
            return;
        }

        if let Err(error) = self
            .discover_identities_gap_limited(wallet, 0, true, None)
            .await
        {
            tracing::warn!(
                %error,
                "Identity discovery failed for the just-unlocked wallet"
            );
        }
    }

    /// Queue automatic discovery of identities derived from a wallet.
    /// Checks identity indices 0 through max_identity_index for existing identities on the network.
    pub fn queue_wallet_identity_discovery(
        self: &Arc<Self>,
        wallet: &Arc<RwLock<Wallet>>,
        max_identity_index: u32,
    ) {
        let ctx = Arc::clone(self);
        let wallet_clone = Arc::clone(wallet);
        let _ = self
            .subtasks
            .spawn_sync("wallet_identity_discovery", async move {
                if let Err(error) = ctx
                    .discover_identities_from_wallet(&wallet_clone, max_identity_index)
                    .await
                {
                    tracing::warn!(
                        %error,
                        "Failed to discover identities from wallet"
                    );
                }
            });
    }

    pub async fn bootstrap_loaded_wallets(self: &Arc<Self>) {
        let wallets: Vec<_> = {
            let guard = self.wallets.read_recover();
            guard.values().cloned().collect()
        };

        for wallet in wallets.iter() {
            self.bootstrap_wallet_addresses_jit(wallet).await;
        }
    }

    /// Update wallet platform address info from SDK-returned AddressInfos.
    /// This uses the proof-verified data from SDK operations rather than fetching.
    pub(crate) fn update_wallet_platform_address_info_from_sdk(
        &self,
        seed_hash: WalletSeedHash,
        address_infos: &dash_sdk::query_types::AddressInfos,
    ) -> Result<(), TaskError> {
        let wallet_arc = self.wallet_arc(&seed_hash)?;

        let mut wallet = wallet_arc.write()?;

        for (platform_addr, maybe_info) in address_infos.iter() {
            if let Some(info) = maybe_info {
                // Convert PlatformAddress to core Address using the network
                let core_addr = platform_addr.to_address_with_network(self.network);

                wallet.set_platform_address_info(core_addr.clone(), info.balance, info.nonce);

                tracing::debug!(
                    "Updated platform address {} balance={} nonce={} from SDK response",
                    core_addr,
                    info.balance,
                    info.nonce
                );
            }
        }

        Ok(())
    }
}
