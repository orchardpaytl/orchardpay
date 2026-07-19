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
pub mod shielded_address;

use crate::backend_task::BackendTaskSuccessResult;
use crate::backend_task::error::TaskError;
use crate::context::AppContext;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use dash_sdk::Sdk;
use dash_sdk::platform::IdentityPublicKey;
use std::sync::Arc;

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
    SearchContacts { search_query: String },
    /// Check whether `identity_id` has published a `shieldedAddress`
    /// document — the OrchardPay screen's readiness gate uses this to
    /// decide whether to show the "Publish a shielded address" prompt or
    /// the normal Contacts/Search UI.
    CheckOwnShieldedAddress {
        identity_id: dash_sdk::platform::Identifier,
    },
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
                seed_hash,
            } => {
                contact_anchor::initiate_contact(
                    self,
                    sdk,
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
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
            OrchardPayTask::SearchContacts { search_query } => {
                contact_search::search_contacts(self, sdk, search_query).await
            }
            OrchardPayTask::CheckOwnShieldedAddress { identity_id } => {
                let published = shielded_address::lookup_shielded_address(self, sdk, identity_id)
                    .await?
                    .is_some();
                Ok(
                    BackendTaskSuccessResult::OrchardPayOwnShieldedAddressStatus {
                        identity_id,
                        published,
                    },
                )
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
