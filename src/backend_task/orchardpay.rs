//! OrchardPay's privacy-first contact/messaging protocol — see
//! `docs/orchardpay/PROTOCOL_DESIGN.md` for the full design and
//! `docs/ORCHARDPAY_MIGRATION.md` for how it relates to (and eventually
//! replaces) the legacy DashPay contact-request model.

pub mod contact_anchor;
pub mod contact_search;
pub mod encryption;
pub mod errors;
pub mod keys;
pub mod memo_scan;
pub mod messages;
pub mod shielded_address;

use crate::backend_task::BackendTaskSuccessResult;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::context::AppContext;
use crate::model::orchardpay::ShieldedActivityRow;
use crate::model::qualified_contract::InsertTokensToo;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use dash_sdk::Sdk;
use dash_sdk::platform::{DataContract, Fetch, IdentityPublicKey};
use platform_wallet::wallet::shielded::{
    ShieldedActivityEntry, ShieldedActivityKind, ShieldedActivityStatus, ShieldedDirection,
};
use std::sync::Arc;

/// Resolves OrchardPay's contract, fetching it from the network and caching
/// it locally the first time it's needed. `AppContext::orchardpay_contract`
/// only reads the local cache — a fresh install ships a contract ID in
/// `.env.example` but nothing ever fetches the contract itself, so every
/// caller here funnels through this instead of calling
/// `app_context.orchardpay_contract()` directly.
async fn ensure_orchardpay_contract(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
) -> Result<Arc<DataContract>, TaskError> {
    if let Some(contract) = app_context.orchardpay_contract() {
        return Ok(Arc::new(contract));
    }
    let contract_id = app_context
        .orchardpay_contract_id()
        .ok_or(OrchardPayError::ContractNotConfigured)?;
    let contract = DataContract::fetch(sdk, contract_id)
        .await
        .map_err(|e| OrchardPayError::ContractFetchFailed(Box::new(e)))?
        .ok_or(OrchardPayError::ContractNotConfigured)?;
    app_context.insert_contract_if_not_exists(
        &contract,
        Some("orchardpay"),
        InsertTokensToo::NoTokensShouldBeAdded,
    )?;
    Ok(Arc::new(contract))
}

/// Maps an upstream `ShieldedActivityEntry` to DET's own display type,
/// decoding the raw 36-byte memo against OrchardPay's known tags. Lives here
/// rather than in `model::orchardpay` so that module stays free of a
/// `backend_task` dependency — see `ShieldedActivityRow`'s doc comment.
fn shielded_activity_row_from_entry(entry: ShieldedActivityEntry) -> ShieldedActivityRow {
    let kind_label = match (&entry.kind, entry.direction) {
        (ShieldedActivityKind::Shield, _) => "Shield",
        (ShieldedActivityKind::ShieldFromAssetLock, _) => "Shield (from Core)",
        (ShieldedActivityKind::Received, _) => "Received",
        (ShieldedActivityKind::Sent, _) => "Sent",
        (ShieldedActivityKind::Unshield, _) => "Unshield",
        (ShieldedActivityKind::Withdrawal, _) => "Withdrawal",
        (ShieldedActivityKind::IdentityCreate { .. }, _) => "Identity Create",
        (ShieldedActivityKind::ShieldedSpend, ShieldedDirection::SelfTransfer) => {
            "Internal Transfer"
        }
        (ShieldedActivityKind::ShieldedSpend, _) => "Shielded Spend",
    };

    let memo_label = match entry.memo.as_deref() {
        None => "No memo".to_string(),
        Some(memo) if memo.starts_with(&contact_anchor::MEMO_TAG_ANCHOR) => {
            "Contact request signal".to_string()
        }
        Some(memo) if memo.starts_with(&messages::MEMO_TAG_PAYMENT) => {
            "OrchardPay payment".to_string()
        }
        Some(memo) => format!("Unrecognized memo: {}", hex::encode(memo)),
    };

    ShieldedActivityRow {
        kind_label,
        amount_credits: entry.amount,
        memo_label,
        block_height: entry.block_height,
        pending: entry.status == ShieldedActivityStatus::Pending,
        created_at_ms: entry.created_at_ms,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OrchardPayTask {
    /// Publish or rotate the caller's own `shieldedAddress` document to
    /// their wallet's current default Orchard address.
    PublishShieldedAddress {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        seed_hash: WalletSeedHash,
    },
    /// Start a new contact relationship: publish my own `contactAnchor` and
    /// signal the counterparty via a memo-tagged shielded transfer. See
    /// `contact_anchor::initiate_contact`.
    InitiateContact {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        /// The counterparty's DPNS name at the time of this request —
        /// snapshotted into `anchorData` so it survives independently of a
        /// later rename or lookup failure. See `contact_anchor::initiate_contact`.
        counterparty_name: String,
        seed_hash: WalletSeedHash,
    },
    /// Complete a relationship already recorded as `PendingInboundUnaccepted`.
    /// See `contact_anchor::accept_contact`.
    AcceptContact {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
    },
    /// Run one pass of the DET-side duplicate incoming-memo scan for
    /// `seed_hash`'s wallet, trying every detected anchor signal against
    /// every identity in `qualified_identities`. See `memo_scan` and
    /// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`.
    ScanForIncomingAnchors {
        qualified_identities: Vec<QualifiedIdentity>,
        seed_hash: WalletSeedHash,
    },
    /// DPNS-prefix search for contactable identities. See `contact_search`.
    SearchContacts {
        search_query: String,
        owner_identity_id: dash_sdk::platform::Identifier,
    },
    /// Check whether `identity_id` has published a `shieldedAddress`
    /// document — the OrchardPay screen's readiness gate uses this to
    /// decide whether to show the "Publish a shielded address" prompt or
    /// the normal Contacts/Search UI.
    CheckOwnShieldedAddress {
        identity_id: dash_sdk::platform::Identifier,
    },
    /// Send a plain-text `Message` to an established contact. See
    /// `messages::send_message`.
    SendMessage {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        text: String,
        seed_hash: WalletSeedHash,
    },
    /// Send a `PaymentRequest` to an established contact — a pure document,
    /// no transfer. See `messages::send_payment_request`.
    SendPaymentRequest {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        amount: u64,
        memo: Option<String>,
        seed_hash: WalletSeedHash,
    },
    /// Send a real payment — unprompted, or fulfilling an existing
    /// `fulfilling_request_document_id`. See `messages::send_payment` for
    /// both paths.
    SendPayment {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
        amount: u64,
        memo: Option<String>,
        fulfilling_request_document_id: Option<dash_sdk::platform::Identifier>,
    },
    /// Load the full two-way `encryptedMessage` thread with an established
    /// contact. See `messages::load_thread`.
    LoadThread {
        qualified_identity: QualifiedIdentity,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
    },
    /// Rebuild local contact state from every `contactAnchor` this identity
    /// has published — the "my published anchors" recovery path for a
    /// reinstalled/new-device wallet. See
    /// `contact_anchor::recover_own_anchors`.
    RecoverContacts {
        qualified_identity: QualifiedIdentity,
        seed_hash: WalletSeedHash,
    },
    /// Order every established contact by their conversation's most recent
    /// activity, for the "Most Recent" navigation view. Pure Platform reads
    /// — no wallet/signing involved, so no `seed_hash`. See
    /// `messages::fetch_recent_activity`.
    LoadRecentActivity {
        qualified_identity: QualifiedIdentity,
    },
    /// Load the shielded transaction history (sent + received) for
    /// `seed_hash`'s wallet, for the Payments tab's diagnostic view.
    /// Wallet-scoped, no identity needed. See
    /// `wallet_backend::shielded::shielded_activity`.
    LoadShieldedActivity { seed_hash: WalletSeedHash },
}

impl AppContext {
    pub async fn run_orchardpay_task(
        self: &Arc<Self>,
        task: OrchardPayTask,
        sdk: &Sdk,
    ) -> Result<BackendTaskSuccessResult, TaskError> {
        match task {
            OrchardPayTask::PublishShieldedAddress {
                qualified_identity,
                identity_key,
                seed_hash,
            } => {
                shielded_address::publish_own_shielded_address(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::InitiateContact {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                counterparty_name,
                seed_hash,
            } => {
                contact_anchor::initiate_contact(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    counterparty_name,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::AcceptContact {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                seed_hash,
            } => {
                contact_anchor::accept_contact(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::ScanForIncomingAnchors {
                qualified_identities,
                seed_hash,
            } => {
                memo_scan::scan_for_incoming_anchors(self, sdk, qualified_identities, seed_hash)
                    .await
            }
            OrchardPayTask::SearchContacts {
                search_query,
                owner_identity_id,
            } => contact_search::search_contacts(self, sdk, search_query, owner_identity_id).await,
            OrchardPayTask::CheckOwnShieldedAddress { identity_id } => {
                let published = shielded_address::lookup_shielded_address(self, sdk, identity_id)
                    .await?
                    .is_some();
                if published {
                    self.wallet_backend()?
                        .orchardpay_set_has_shielded_address(&identity_id)?;
                }
                Ok(
                    BackendTaskSuccessResult::OrchardPayOwnShieldedAddressStatus {
                        identity_id,
                        published,
                    },
                )
            }
            OrchardPayTask::SendMessage {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                text,
                seed_hash,
            } => {
                messages::send_message(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    text,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::SendPaymentRequest {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                amount,
                memo,
                seed_hash,
            } => {
                messages::send_payment_request(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    amount,
                    memo,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::SendPayment {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                seed_hash,
                amount,
                memo,
                fulfilling_request_document_id,
            } => {
                messages::send_payment(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    seed_hash,
                    amount,
                    memo,
                    fulfilling_request_document_id,
                )
                .await
            }
            OrchardPayTask::LoadThread {
                qualified_identity,
                counterparty_identity_id,
                seed_hash,
            } => {
                let messages = messages::load_thread(
                    self,
                    sdk,
                    &qualified_identity,
                    counterparty_identity_id,
                    seed_hash,
                )
                .await?;
                Ok(BackendTaskSuccessResult::OrchardPayThreadLoaded {
                    counterparty_identity_id,
                    messages,
                })
            }
            OrchardPayTask::RecoverContacts {
                qualified_identity,
                seed_hash,
            } => {
                let summary =
                    contact_anchor::recover_own_anchors(self, sdk, &qualified_identity, seed_hash)
                        .await?;
                Ok(BackendTaskSuccessResult::OrchardPayContactsRecovered {
                    anchors_found: summary.anchors_found,
                    contacts_recovered: summary.contacts_recovered,
                    already_tracked: summary.already_tracked,
                    undecryptable: summary.undecryptable,
                })
            }
            OrchardPayTask::LoadRecentActivity { qualified_identity } => {
                messages::fetch_recent_activity(self, sdk, &qualified_identity).await
            }
            OrchardPayTask::LoadShieldedActivity { seed_hash } => {
                let entries = self.wallet_backend()?.shielded_activity(&seed_hash).await?;
                let rows = entries
                    .into_iter()
                    .map(shielded_activity_row_from_entry)
                    .collect();
                Ok(BackendTaskSuccessResult::OrchardPayShieldedActivity(rows))
            }
        }
    }
}

/// The contract JSON checked in at `contract_schema.json`, ready to paste
/// into the "Register Contract" screen. `id`/`ownerId` are placeholders —
/// the screen overwrites `ownerId` with the registering identity, and
/// Platform derives the real contract ID at creation regardless of what's
/// submitted here.
pub const CONTRACT_SCHEMA_JSON: &str = include_str!("orchardpay/contract_schema.json");

#[cfg(test)]
mod tests {
    use super::{CONTRACT_SCHEMA_JSON, shielded_activity_row_from_entry};
    use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
    use dash_sdk::dpp::data_contract::conversion::json::DataContractJsonConversionMethodsV0;
    use dash_sdk::dpp::data_contract::document_type::accessors::DocumentTypeV0Getters;
    use dash_sdk::dpp::data_contract::storage_requirements::keys_for_document_type::StorageKeyRequirements;
    use dash_sdk::dpp::version::PlatformVersion;
    use dash_sdk::platform::DataContract;
    use platform_wallet::wallet::shielded::{
        ShieldedActivityEntry, ShieldedActivityKind, ShieldedActivityStatus, ShieldedDirection,
    };

    fn base_entry() -> ShieldedActivityEntry {
        ShieldedActivityEntry {
            id: [0u8; 32],
            kind: ShieldedActivityKind::Sent,
            direction: ShieldedDirection::Out,
            amount: 100_000_000,
            fee: None,
            counterparty: None,
            memo: None,
            block_height: Some(42),
            status: ShieldedActivityStatus::Confirmed,
            created_at_ms: 1_700_000_000_000,
            note_cmxs: Vec::new(),
            spent_nullifiers: Vec::new(),
        }
    }

    #[test]
    fn recognizes_contact_anchor_memo_tag() {
        let mut memo = vec![0u8; 36];
        memo[..4].copy_from_slice(&super::contact_anchor::MEMO_TAG_ANCHOR);
        let entry = ShieldedActivityEntry {
            memo: Some(memo),
            ..base_entry()
        };
        let row = shielded_activity_row_from_entry(entry);
        assert_eq!(row.memo_label, "Contact request signal");
    }

    #[test]
    fn recognizes_payment_memo_tag() {
        let mut memo = vec![0u8; 36];
        memo[..4].copy_from_slice(&super::messages::MEMO_TAG_PAYMENT);
        let entry = ShieldedActivityEntry {
            memo: Some(memo),
            ..base_entry()
        };
        let row = shielded_activity_row_from_entry(entry);
        assert_eq!(row.memo_label, "OrchardPay payment");
    }

    #[test]
    fn unrecognized_memo_falls_back_to_hex() {
        let memo = vec![0xABu8; 36];
        let entry = ShieldedActivityEntry {
            memo: Some(memo.clone()),
            ..base_entry()
        };
        let row = shielded_activity_row_from_entry(entry);
        assert_eq!(
            row.memo_label,
            format!("Unrecognized memo: {}", hex::encode(&memo))
        );
    }

    #[test]
    fn no_memo_is_labeled_explicitly() {
        let row = shielded_activity_row_from_entry(base_entry());
        assert_eq!(row.memo_label, "No memo");
    }

    #[test]
    fn pending_status_maps_to_pending_flag() {
        let entry = ShieldedActivityEntry {
            status: ShieldedActivityStatus::Pending,
            block_height: None,
            ..base_entry()
        };
        let row = shielded_activity_row_from_entry(entry);
        assert!(row.pending);
    }

    #[test]
    fn self_transfer_shielded_spend_gets_internal_label() {
        let entry = ShieldedActivityEntry {
            kind: ShieldedActivityKind::ShieldedSpend,
            direction: ShieldedDirection::SelfTransfer,
            ..base_entry()
        };
        let row = shielded_activity_row_from_entry(entry);
        assert_eq!(row.kind_label, "Internal Transfer");
    }

    /// Guards against accidental schema corruption: the checked-in contract
    /// JSON must always parse as a valid `DataContract` against the pinned
    /// Platform version, or registration fails with a hard-to-diagnose error
    /// (as happened once already — this file was originally checked in as
    /// just the `documentSchemas` fragment, missing the required
    /// `$formatVersion`/`id`/`ownerId`/`version` wrapper).
    #[test]
    fn contract_schema_parses_as_valid_data_contract() {
        let json_val: serde_json::Value =
            serde_json::from_str(CONTRACT_SCHEMA_JSON).expect("contract_schema.json is valid JSON");
        let platform_version = PlatformVersion::latest();
        let contract = DataContract::from_json(json_val, true, platform_version)
            .expect("contract_schema.json must parse as a valid DataContract");

        // The one property registration actually depends on: without these,
        // Platform rejects the contract-bounded ENCRYPTION/DECRYPTION keys
        // default_orchardpay_key_specs asks new identities to register.
        let contact_anchor = contract
            .document_type_for_name("contactAnchor")
            .expect("contactAnchor document type must exist");
        assert_eq!(
            contact_anchor.requires_identity_encryption_bounded_key(),
            Some(StorageKeyRequirements::MultipleReferenceToLatest)
        );
        assert_eq!(
            contact_anchor.requires_identity_decryption_bounded_key(),
            Some(StorageKeyRequirements::MultipleReferenceToLatest)
        );
    }
}
