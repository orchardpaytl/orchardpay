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
use crate::model::orchardpay::OrchardPayContactState;
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::{DetScope, WalletBackend};

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
/// `det:orchardpay:has_shielded_address`.
const KV_PREFIX_HAS_SHIELDED_ADDRESS: &str = "det:orchardpay:has_shielded_address";

fn contact_key(counterparty: &Identifier) -> String {
    format!(
        "{KV_PREFIX_CONTACT}{}",
        counterparty.to_string(Encoding::Base58)
    )
}

fn verified_payment_key(document_id: &Identifier) -> String {
    format!(
        "{KV_PREFIX_VERIFIED_PAYMENT}{}",
        document_id.to_string(Encoding::Base58)
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

    /// Read the locally cached "has this identity published a
    /// `shieldedAddress`" flag. `Ok(None)` means never confirmed locally
    /// yet — callers should do a live Platform check. There is no cached
    /// `false`; see [`KV_PREFIX_HAS_SHIELDED_ADDRESS`]'s doc comment for why.
    pub fn orchardpay_get_has_shielded_address(
        &self,
        owner: &Identifier,
    ) -> Result<Option<bool>, TaskError> {
        let owner_buf = owner.to_buffer();
        self.kv()
            .get::<bool>(
                DetScope::Identity(&owner_buf),
                KV_PREFIX_HAS_SHIELDED_ADDRESS,
            )
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })
    }

    /// Persist that `owner` has a confirmed published `shieldedAddress`
    /// document, so later launches/visits know instantly instead of
    /// re-querying Platform.
    pub fn orchardpay_set_has_shielded_address(&self, owner: &Identifier) -> Result<(), TaskError> {
        let owner_buf = owner.to_buffer();
        self.kv()
            .put::<bool>(
                DetScope::Identity(&owner_buf),
                KV_PREFIX_HAS_SHIELDED_ADDRESS,
                &true,
            )
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

    /// Read the real credits value this wallet observed for a
    /// `MEMO_TAG_PAYMENT`-tagged incoming note referencing `document_id`.
    /// `Ok(None)` means either the scan hasn't reached it yet, or it was
    /// never addressed to this wallet (e.g. a payment I sent myself, which
    /// needs no verification).
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

    /// Persist the real credits value observed for a `MEMO_TAG_PAYMENT`
    /// signal referencing `document_id`. Called once by the incoming-memo
    /// scan, at the point the decrypted `Note`'s real value is in hand.
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
    /// contact-state records and the cached "has published a
    /// shieldedAddress" flag. Mirrors `dashpay_clear_owner_overlays` for the
    /// network-clear path. The memo-scan cursor and verified-payment cache
    /// are wallet-scoped, not owner-scoped, so neither is covered here — see
    /// [`Self::orchardpay_clear_wallet_overlays`], called from wallet
    /// removal instead of identity removal.
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

        kv.delete(scope, KV_PREFIX_HAS_SHIELDED_ADDRESS)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        Ok(())
    }

    /// Drop every OrchardPay wallet-scoped sidecar entry for `seed_hash` —
    /// the memo-scan resume cursor and the verified-incoming-payment cache.
    /// Called from `WalletBackend::forget_wallet_local_state`, not the
    /// per-identity network-clear sweep above: both entries are
    /// [`DetScope::Wallet`], and — contrary to an earlier, unverified
    /// assumption in this module — nothing about that scope actually
    /// cascades on wallet removal; `det-app.sqlite` (where this k/v store
    /// lives) has no foreign-key relationship to the upstream persistor's
    /// wallet table, so an explicit sweep is required or these rows orphan
    /// permanently. Not a secret-bearing-state gap: both values are
    /// non-secret (a resume index; a public credits amount keyed by a
    /// public document ID) — the seed/session/wallet-meta deletes that
    /// already run during wallet removal satisfy the actual "no secrets
    /// survive" guarantee. This is storage hygiene, not hardening.
    pub fn orchardpay_clear_wallet_overlays(
        &self,
        seed_hash: &WalletSeedHash,
    ) -> Result<(), TaskError> {
        let scope = DetScope::Wallet(seed_hash);
        let kv = self.kv();

        kv.delete(scope, KV_PREFIX_MEMO_SCAN_CURSOR)
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;

        let verified_payment_keys = kv
            .list(scope, Some(KV_PREFIX_VERIFIED_PAYMENT))
            .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
        for key in verified_payment_keys {
            kv.delete(scope, &key)
                .map_err(|e| TaskError::OrchardPaySidecarStorage { source: e })?;
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
                let mut stream =
                    std::pin::pin!(sync_shielded_notes_stream(sdk, &ivk, start_index, None));
                while let Some(batch) = stream.next().await {
                    let batch = batch.map_err(|e| {
                        TaskError::OrchardPay(OrchardPayError::MemoScanFailed {
                            source: Box::new(e),
                        })
                    })?;

                    for (offset, note) in batch.notes.iter().enumerate() {
                        let Some((decrypted_note, _, memo)) =
                            try_decrypt_note_with_memo(&ivk, note)
                        else {
                            continue;
                        };
                        let note_index = batch.start_index + offset as u64;
                        let tag: [u8; 4] = memo[..4].try_into().expect("memo is 36 bytes");
                        let doc_id_bytes: [u8; 32] =
                            memo[4..].try_into().expect("memo is 36 bytes, tag is 4");
                        if tag == MEMO_TAG_ANCHOR {
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

                Ok((found, next_start_index))
            })
            .await
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
}
