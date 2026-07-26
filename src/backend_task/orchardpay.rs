//! OrchardPay's privacy-first contact/messaging protocol — see
//! `docs/orchardpay/PROTOCOL_DESIGN.md` for the full design and
//! `docs/ORCHARDPAY_MIGRATION.md` for how it relates to (and eventually
//! replaces) the legacy DashPay contact-request model.

pub mod contact_anchor;
pub mod contact_search;
pub mod direct_send;
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
use crate::model::qualified_contract::InsertTokensToo;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use dash_sdk::Sdk;
use dash_sdk::platform::{DataContract, Fetch, IdentityPublicKey};
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
        /// Credits transferred with the anchor-signaling shielded transfer.
        /// Send Friend Request passes
        /// `contact_anchor::ANCHOR_SIGNAL_AMOUNT_CREDITS` (today's fixed
        /// 0.001 DASH default); Direct Send's "include a contact request"
        /// branch passes the user's own typed amount instead.
        amount_credits: u64,
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
        /// Whether to save a `PaymentRequestReceipt` for the request being
        /// fulfilled — ignored (treated as `false`) for an unprompted
        /// payment. See `messages::send_payment`.
        save_receipt: bool,
        /// The `PaymentRequest`'s own memo/`$createdAt` at pay-time, only
        /// meaningful when `save_receipt` is true.
        original_request_memo: Option<String>,
        original_request_created_at: Option<u64>,
    },
    /// Send DASH directly to `counterparty_identity_id` with no contact
    /// request and no OrchardPay document — a bare shielded transfer. See
    /// `direct_send::send_direct`. Direct Send's other branch (its
    /// confirmation modal's checkbox checked) instead dispatches
    /// `InitiateContact` with a caller-chosen `amount_credits`; this variant
    /// is only for the no-request path.
    SendDirect {
        owner_identity_id: dash_sdk::platform::Identifier,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
        amount: u64,
    },
    /// Edit a `Message` I sent. See `messages::edit_message`.
    EditMessage {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        document_id: dash_sdk::platform::Identifier,
        new_text: String,
        seed_hash: WalletSeedHash,
    },
    /// Edit a `Payment`'s memo (never its amount). See
    /// `messages::edit_payment_memo`.
    EditPaymentMemo {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        document_id: dash_sdk::platform::Identifier,
        new_memo: Option<String>,
        seed_hash: WalletSeedHash,
    },
    /// Cancel a `PaymentRequest` I created — never deletes it, only while
    /// unpaid. See `messages::cancel_payment_request`.
    CancelPaymentRequest {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        document_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
    },
    /// Delete a `Message` I sent — a true document delete, only ever
    /// offered for this content kind. See `messages::delete_message`.
    DeleteMessage {
        qualified_identity: QualifiedIdentity,
        identity_key: IdentityPublicKey,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        document_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
    },
    /// Load the newest page of the two-way `encryptedMessage` thread with an
    /// established contact. See `messages::load_thread`.
    LoadThread {
        qualified_identity: QualifiedIdentity,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
    },
    /// Fetch the next older page of conversation history, for the "See more
    /// conversation history" button — only reached once a prior
    /// `LoadThread`/`LoadMoreHistory` result reported more available via
    /// `history_cursor`. See `messages::load_more_history`.
    LoadMoreHistory {
        qualified_identity: QualifiedIdentity,
        counterparty_identity_id: dash_sdk::platform::Identifier,
        seed_hash: WalletSeedHash,
        all_decoded: Vec<messages::ThreadMessage>,
        history_cursor: messages::HistoryCursor,
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
                amount_credits,
            } => {
                contact_anchor::initiate_contact(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    counterparty_name,
                    seed_hash,
                    amount_credits,
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
                save_receipt,
                original_request_memo,
                original_request_created_at,
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
                    save_receipt,
                    original_request_memo,
                    original_request_created_at,
                )
                .await
            }
            OrchardPayTask::SendDirect {
                owner_identity_id,
                counterparty_identity_id,
                seed_hash,
                amount,
            } => {
                direct_send::send_direct(
                    self,
                    sdk,
                    owner_identity_id,
                    counterparty_identity_id,
                    seed_hash,
                    amount,
                )
                .await
            }
            OrchardPayTask::EditMessage {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                document_id,
                new_text,
                seed_hash,
            } => {
                messages::edit_message(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    document_id,
                    new_text,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::EditPaymentMemo {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                document_id,
                new_memo,
                seed_hash,
            } => {
                messages::edit_payment_memo(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    document_id,
                    new_memo,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::CancelPaymentRequest {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                document_id,
                seed_hash,
            } => {
                messages::cancel_payment_request(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    document_id,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::DeleteMessage {
                qualified_identity,
                identity_key,
                counterparty_identity_id,
                document_id,
                seed_hash,
            } => {
                messages::delete_message(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    document_id,
                    seed_hash,
                )
                .await
            }
            OrchardPayTask::LoadThread {
                qualified_identity,
                counterparty_identity_id,
                seed_hash,
            } => {
                let messages::LoadedThread {
                    all_decoded,
                    messages,
                    receipt_alerts,
                    history_cursor,
                } = messages::load_thread(
                    self,
                    sdk,
                    &qualified_identity,
                    counterparty_identity_id,
                    seed_hash,
                )
                .await?;
                Ok(BackendTaskSuccessResult::OrchardPayThreadLoaded {
                    counterparty_identity_id,
                    all_decoded,
                    messages,
                    receipt_alerts,
                    history_cursor,
                })
            }
            OrchardPayTask::LoadMoreHistory {
                qualified_identity,
                counterparty_identity_id,
                seed_hash,
                all_decoded,
                history_cursor,
            } => {
                let messages::LoadedThread {
                    all_decoded,
                    messages,
                    receipt_alerts,
                    history_cursor,
                } = messages::load_more_history(
                    self,
                    sdk,
                    &qualified_identity,
                    counterparty_identity_id,
                    seed_hash,
                    all_decoded,
                    history_cursor,
                )
                .await?;
                Ok(BackendTaskSuccessResult::OrchardPayThreadLoaded {
                    counterparty_identity_id,
                    all_decoded,
                    messages,
                    receipt_alerts,
                    history_cursor,
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
                let rows = self
                    .wallet_backend()?
                    .shielded_activity(sdk, &seed_hash)
                    .await?;
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
    use super::CONTRACT_SCHEMA_JSON;
    use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
    use dash_sdk::dpp::data_contract::conversion::json::DataContractJsonConversionMethodsV0;
    use dash_sdk::dpp::data_contract::document_type::accessors::DocumentTypeV0Getters;
    use dash_sdk::dpp::data_contract::storage_requirements::keys_for_document_type::StorageKeyRequirements;
    use dash_sdk::dpp::version::PlatformVersion;
    use dash_sdk::platform::DataContract;

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
