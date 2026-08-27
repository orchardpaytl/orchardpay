use crate::backend_task::document::DocumentTask;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::{
    BackendTaskSuccessResult, NETWORK_REQUEST_TIMEOUT, await_network_request_with_timeout,
};
use crate::context::AppContext;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use bip39::rand::SeedableRng;
use bip39::rand::rngs::StdRng;
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::document::{
    Document as DppDocument, DocumentV0, DocumentV0Getters, DocumentV0Setters,
};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::platform_value::{Bytes32, Value};
use dash_sdk::drive::query::{WhereClause, WhereOperator};
use dash_sdk::platform::{
    DataContract, Document, DocumentQuery, FetchMany, Identifier, IdentityPublicKey,
};
use std::sync::Arc;

/// The `shieldedAddress` document type name, matching
/// `src/backend_task/orchardpay/contract_schema.json`.
pub const SHIELDED_ADDRESS_DOCUMENT_TYPE: &str = "shieldedAddress";
const SHIELDED_ADDRESS_PROPERTY: &str = "shieldedAddress";

/// Publishes or rotates the caller's own `shieldedAddress` document to their
/// wallet's current default Orchard address (account 0 — see
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Future: account separation" for
/// why this may change later). Create-or-replace: at most one such document
/// exists per identity, enforced by the schema's unique `byOwner` index.
pub async fn publish_own_shielded_address(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();

    // Publishing a shielded address is the one flow that gets an identity
    // fully set up for OrchardPay: generate and broadcast its ENCRYPTION/
    // DECRYPTION keys first if it doesn't have them yet (a no-op, no
    // network call, if it already does). See `keys::ensure_own_orchardpay_keys`.
    let qualified_identity = super::keys::ensure_own_orchardpay_keys(
        app_context,
        sdk,
        qualified_identity,
        orchardpay_contract.id(),
        seed_hash,
    )
    .await?;

    let backend = app_context.wallet_backend()?;
    let raw_address = backend
        .shielded_default_address(&seed_hash, 0)
        .await?
        .ok_or(TaskError::ShieldedNotBound)?;

    let owner_id = qualified_identity.identity.id();
    let existing = fetch_shielded_address_document(&orchardpay_contract, sdk, owner_id).await?;

    let document_type = orchardpay_contract
        .document_type_cloned_for_name(SHIELDED_ADDRESS_DOCUMENT_TYPE)
        .expect(
            "shieldedAddress document type is part of the checked-in OrchardPay contract schema",
        );

    let task = match existing {
        Some(mut document) => {
            document.set(
                SHIELDED_ADDRESS_PROPERTY,
                Value::Bytes(raw_address.to_vec()),
            );
            document.bump_revision();
            DocumentTask::ReplaceDocument {
                document,
                document_type,
                data_contract: orchardpay_contract,
                qualified_identity,
                identity_key,
                token_payment_info: None,
            }
        }
        None => {
            let mut rng = StdRng::from_entropy();
            let entropy = Bytes32::random_with_rng(&mut rng);
            let document_id = DppDocument::generate_document_id_v0(
                &orchardpay_contract.id(),
                &owner_id,
                SHIELDED_ADDRESS_DOCUMENT_TYPE,
                entropy.as_slice(),
            );

            let mut properties = std::collections::BTreeMap::new();
            properties.insert(
                SHIELDED_ADDRESS_PROPERTY.to_string(),
                Value::Bytes(raw_address.to_vec()),
            );

            let document = DppDocument::V0(DocumentV0 {
                id: document_id,
                owner_id,
                creator_id: None,
                properties,
                revision: Some(1),
                contract_version: None,
                created_at: None,
                updated_at: None,
                transferred_at: None,
                created_at_block_height: None,
                updated_at_block_height: None,
                transferred_at_block_height: None,
                created_at_core_block_height: None,
                updated_at_core_block_height: None,
                transferred_at_core_block_height: None,
            });

            DocumentTask::BroadcastDocument {
                document,
                token_payment_info: None,
                entropy: entropy
                    .as_slice()
                    .try_into()
                    .expect("Bytes32 is always 32 bytes"),
                document_type,
                data_contract: orchardpay_contract,
                qualified_identity,
                identity_key,
            }
        }
    };

    let result = app_context.run_document_task(task, sdk).await?;
    backend.orchardpay_set_has_shielded_address(&contract_id, &owner_id)?;
    Ok(result)
}

/// Looks up an identity's published `shieldedAddress`, if any. Returns the
/// raw 43-byte address on success. `Ok(None)` means the identity hasn't
/// published one — not an error, just "not contactable via OrchardPay yet".
/// `Err(OrchardPayError::CounterpartyShieldedAddressInvalid)` means a
/// document exists but its payload isn't a valid Orchard address — distinct
/// from "not contactable" so a caller doesn't spend a fee trusting it (see
/// `model::address::validate_shielded_address_bytes`).
pub async fn lookup_shielded_address(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    target_identity_id: Identifier,
) -> Result<Option<[u8; 43]>, TaskError> {
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;

    let Some(document) =
        fetch_shielded_address_document(&orchardpay_contract, sdk, target_identity_id).await?
    else {
        return Ok(None);
    };

    match document.properties().get(SHIELDED_ADDRESS_PROPERTY) {
        Some(Value::Bytes(bytes)) => crate::model::address::validate_shielded_address_bytes(bytes)
            .map(Some)
            .map_err(|_| OrchardPayError::CounterpartyShieldedAddressInvalid.into()),
        _ => Ok(None),
    }
}

async fn fetch_shielded_address_document(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    owner_id: Identifier,
) -> Result<Option<Document>, TaskError> {
    let mut query = DocumentQuery::new(orchardpay_contract.clone(), SHIELDED_ADDRESS_DOCUMENT_TYPE)
        .map_err(|e| OrchardPayError::QueryCreation {
            query_target: "shieldedAddress lookup",
            source: Box::new(e.into()),
        })?;
    query = query.with_where(WhereClause {
        field: "$ownerId".to_string(),
        operator: WhereOperator::Equal,
        value: Value::Identifier(owner_id.to_buffer()),
    });

    let results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    Ok(results.into_values().flatten().next())
}
