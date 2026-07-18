//! The two-anchor contact-establishment handshake. See
//! `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Two anchors per relationship" for
//! the full protocol this module implements.
//!
//! Three entry points, matching the three places a human or the incoming-
//! memo scan (`docs/ai-design/2026-07-18-orchardpay-memo-detection/`) drives
//! this state machine forward:
//!
//! - [`initiate_contact`]: I start a new relationship with `counterparty_id`.
//! - [`accept_contact`]: I've already detected and decrypted their anchor
//!   (a [`OrchardPayContactState::PendingInboundUnaccepted`] record exists)
//!   and now choose to complete the handshake.
//! - [`handle_incoming_anchor_signal`]: called by the memo scan when it
//!   detects a memo-tagged transfer referencing a `contactAnchor` document —
//!   dispatches to either "record a fresh inbound request" or "complete my
//!   own pending outbound request," depending on whether local state already
//!   tracks this counterparty.
//!
//! Both `data` and `anchorData` on a given anchor document are encrypted
//! under the *same* ECDH shared secret — the one derived from this
//! document's owner's ENCRYPTION key and the counterparty's DECRYPTION key.
//! There is no separate key derivation for `anchorData`: it is simply a
//! second encrypted field on the same document, decryptable by the same two
//! parties as `data`.

use crate::backend_task::document::DocumentTask;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::encryption::ContactAnchorPayload;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::keys::{
    CONTACT_ANCHOR_DOCUMENT_TYPE, fetch_bounds_verified_counterparty_key,
};
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::backend_task::{
    BackendTaskSuccessResult, NETWORK_REQUEST_TIMEOUT, await_network_request_with_timeout,
};
use crate::context::AppContext;
use crate::model::orchardpay::OrchardPayContactState;
use crate::model::qualified_identity::{PrivateKeyTarget, QualifiedIdentity};
use crate::model::wallet::WalletSeedHash;
use bip39::rand::RngCore;
use bip39::rand::rngs::OsRng;
use bip39::rand::{SeedableRng, rngs::StdRng};
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::document::{
    Document as DppDocument, DocumentV0, DocumentV0Getters, DocumentV0Setters,
};
use dash_sdk::dpp::identity::Purpose;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dash_sdk::dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dash_sdk::dpp::platform_value::{Bytes32, Value};
use dash_sdk::drive::query::{WhereClause, WhereOperator};
use dash_sdk::platform::{
    DataContract, Document, DocumentQuery, FetchMany, Identifier, IdentityPublicKey,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

const DATA_FIELD: &str = "data";
const ANCHOR_DATA_FIELD: &str = "anchorData";
const EXTRA_FIELD: &str = "extra";

/// 4-byte tag identifying an anchor-signaling shielded transfer's memo, per
/// `docs/ai-design/2026-07-18-orchardpay-memo-detection/`. Followed by the
/// signaling anchor's 32-byte DocumentID for a 36-byte memo total.
pub const MEMO_TAG_ANCHOR: [u8; 4] = *b"OPA1";

/// Minimal amount for the anchor-signaling shielded transfer — it exists
/// purely to deliver a memo, not to move meaningful value. Chosen as a
/// small, non-zero credit amount; no independent verification has been done
/// of whether Platform enforces its own higher minimum. If it does, the
/// underlying `shielded_transfer` call simply fails with its normal
/// insufficient-amount error.
const ANCHOR_SIGNAL_AMOUNT_CREDITS: u64 = 1000;

/// Start a new contact relationship with `counterparty_identity_id`:
/// publish my own `contactAnchor` (with `anchorData` still empty) and send a
/// memo-tagged shielded transfer to their published `shieldedAddress`.
pub async fn initiate_contact(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    if owner_id == counterparty_identity_id {
        return Err(OrchardPayError::CounterpartyKeyMissing.into());
    }

    let orchardpay_contract: Arc<DataContract> = Arc::new(
        app_context
            .orchardpay_contract()
            .ok_or(OrchardPayError::ContractNotConfigured)?,
    );

    let backend = app_context.wallet_backend()?;
    if backend
        .orchardpay_get_contact_state(&owner_id, &counterparty_identity_id)?
        .is_some()
    {
        // Already initiated, already inbound-pending, or already established
        // — the caller should be looking at that existing state, not
        // starting a new one.
        return Err(OrchardPayError::AnchorNotFound.into());
    }

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let my_encryption_key = own_bounds_verified_key(
        &qualified_identity,
        orchardpay_contract.id(),
        Purpose::ENCRYPTION,
    )
    .ok_or(OrchardPayError::OwnKeyMissing)?;

    let shared_secret = compute_shared_secret(
        sdk,
        orchardpay_contract.id(),
        &qualified_identity,
        &my_encryption_key,
        counterparty_identity_id,
        Purpose::DECRYPTION,
    )
    .await?;

    let mut my_reference_id = [0u8; 32];
    OsRng.fill_bytes(&mut my_reference_id);

    let my_payload = ContactAnchorPayload {
        reference_id: my_reference_id,
        core_payment_xpub: None,
        dedicated_shielded_address: None,
        initial_message: None,
    };
    let data_bytes = my_payload
        .encrypt(&shared_secret)
        .map_err(OrchardPayError::Crypto)?;

    let document_type = orchardpay_contract
        .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
        .expect("contactAnchor document type is part of the checked-in OrchardPay contract schema");

    let mut rng = StdRng::from_entropy();
    let entropy = Bytes32::random_with_rng(&mut rng);
    let document_id = DppDocument::generate_document_id_v0(
        &orchardpay_contract.id(),
        &owner_id,
        CONTACT_ANCHOR_DOCUMENT_TYPE,
        entropy.as_slice(),
    );

    let mut properties = BTreeMap::new();
    properties.insert(DATA_FIELD.to_string(), Value::Bytes(data_bytes));
    properties.insert(ANCHOR_DATA_FIELD.to_string(), Value::Bytes(Vec::new()));
    properties.insert(EXTRA_FIELD.to_string(), Value::Bytes(Vec::new()));

    let document = DppDocument::V0(DocumentV0 {
        id: document_id,
        owner_id,
        creator_id: None,
        properties,
        revision: Some(1),
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

    let task = DocumentTask::BroadcastDocument {
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
    };
    let result = app_context.run_document_task(task, sdk).await?;

    let mut memo = [0u8; 36];
    memo[..4].copy_from_slice(&MEMO_TAG_ANCHOR);
    memo[4..].copy_from_slice(&document_id.to_buffer());

    backend
        .shielded_transfer(
            &seed_hash,
            0,
            &counterparty_shielded_address,
            ANCHOR_SIGNAL_AMOUNT_CREDITS,
            memo,
        )
        .await?;

    backend.orchardpay_set_contact_state(
        &owner_id,
        &counterparty_identity_id,
        &OrchardPayContactState::PendingOutbound {
            my_reference_id,
            my_anchor_document_id: document_id.to_buffer(),
        },
    )?;

    Ok(result)
}

/// Complete a relationship already recorded as
/// [`OrchardPayContactState::PendingInboundUnaccepted`]: publish my own
/// `contactAnchor` with `anchorData` already filled in (I already know
/// their ReferenceID) and send the return memo-tagged transfer.
pub async fn accept_contact(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract: Arc<DataContract> = Arc::new(
        app_context
            .orchardpay_contract()
            .ok_or(OrchardPayError::ContractNotConfigured)?,
    );

    let backend = app_context.wallet_backend()?;
    let their_reference_id =
        match backend.orchardpay_get_contact_state(&owner_id, &counterparty_identity_id)? {
            Some(OrchardPayContactState::PendingInboundUnaccepted {
                their_reference_id, ..
            }) => their_reference_id,
            _ => return Err(OrchardPayError::AnchorNotFound.into()),
        };

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let my_encryption_key = own_bounds_verified_key(
        &qualified_identity,
        orchardpay_contract.id(),
        Purpose::ENCRYPTION,
    )
    .ok_or(OrchardPayError::OwnKeyMissing)?;

    let shared_secret = compute_shared_secret(
        sdk,
        orchardpay_contract.id(),
        &qualified_identity,
        &my_encryption_key,
        counterparty_identity_id,
        Purpose::DECRYPTION,
    )
    .await?;

    let mut my_reference_id = [0u8; 32];
    OsRng.fill_bytes(&mut my_reference_id);

    let my_payload = ContactAnchorPayload {
        reference_id: my_reference_id,
        core_payment_xpub: None,
        dedicated_shielded_address: None,
        initial_message: None,
    };
    let data_bytes = my_payload
        .encrypt(&shared_secret)
        .map_err(OrchardPayError::Crypto)?;

    let their_payload = ContactAnchorPayload {
        reference_id: their_reference_id,
        core_payment_xpub: None,
        dedicated_shielded_address: None,
        initial_message: None,
    };
    let anchor_data_bytes = their_payload
        .encrypt(&shared_secret)
        .map_err(OrchardPayError::Crypto)?;

    let document_type = orchardpay_contract
        .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
        .expect("contactAnchor document type is part of the checked-in OrchardPay contract schema");

    let mut rng = StdRng::from_entropy();
    let entropy = Bytes32::random_with_rng(&mut rng);
    let document_id = DppDocument::generate_document_id_v0(
        &orchardpay_contract.id(),
        &owner_id,
        CONTACT_ANCHOR_DOCUMENT_TYPE,
        entropy.as_slice(),
    );

    let mut properties = BTreeMap::new();
    properties.insert(DATA_FIELD.to_string(), Value::Bytes(data_bytes));
    properties.insert(
        ANCHOR_DATA_FIELD.to_string(),
        Value::Bytes(anchor_data_bytes),
    );
    properties.insert(EXTRA_FIELD.to_string(), Value::Bytes(Vec::new()));

    let document = DppDocument::V0(DocumentV0 {
        id: document_id,
        owner_id,
        creator_id: None,
        properties,
        revision: Some(1),
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

    let task = DocumentTask::BroadcastDocument {
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
    };
    let result = app_context.run_document_task(task, sdk).await?;

    let mut memo = [0u8; 36];
    memo[..4].copy_from_slice(&MEMO_TAG_ANCHOR);
    memo[4..].copy_from_slice(&document_id.to_buffer());

    backend
        .shielded_transfer(
            &seed_hash,
            0,
            &counterparty_shielded_address,
            ANCHOR_SIGNAL_AMOUNT_CREDITS,
            memo,
        )
        .await?;

    backend.orchardpay_set_contact_state(
        &owner_id,
        &counterparty_identity_id,
        &OrchardPayContactState::Established {
            my_reference_id,
            my_anchor_document_id: document_id.to_buffer(),
            their_reference_id,
        },
    )?;

    Ok(result)
}

/// Called by the incoming-memo scan when it detects a transfer memo tagged
/// [`MEMO_TAG_ANCHOR`], carrying `anchor_document_id`. Fetches that document
/// directly by ID (never by query), learns the sender from its `$ownerId`,
/// and either records a fresh inbound request or completes a pending
/// outbound one, depending on existing local state.
///
/// Returns `Ok(true)` if the signal was recognized and acted on, `Ok(false)`
/// if the referenced document doesn't exist (stale/foreign memo — not an
/// error, just nothing to do).
pub async fn handle_incoming_anchor_signal(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    anchor_document_id: Identifier,
) -> Result<bool, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = app_context
        .orchardpay_contract()
        .ok_or(OrchardPayError::ContractNotConfigured)?;

    let Some(document) =
        fetch_anchor_document_by_id(&orchardpay_contract, sdk, anchor_document_id).await?
    else {
        return Ok(false);
    };

    let sender_id = document.owner_id();
    if sender_id == owner_id {
        // My own anchor's signal, observed via my own outgoing OVK
        // recovery or similar — nothing to react to.
        return Ok(false);
    }

    let data_bytes = match document.properties().get(DATA_FIELD) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Ok(false),
    };

    let my_decryption_key = own_bounds_verified_key(
        qualified_identity,
        orchardpay_contract.id(),
        Purpose::DECRYPTION,
    )
    .ok_or(OrchardPayError::OwnKeyMissing)?;

    let shared_secret = compute_shared_secret(
        sdk,
        orchardpay_contract.id(),
        qualified_identity,
        &my_decryption_key,
        sender_id,
        Purpose::ENCRYPTION,
    )
    .await?;

    let their_payload = ContactAnchorPayload::decrypt(&shared_secret, &data_bytes)
        .map_err(OrchardPayError::Crypto)?;

    let backend = app_context.wallet_backend()?;
    match backend.orchardpay_get_contact_state(&owner_id, &sender_id)? {
        None => {
            // Fresh inbound request.
            backend.orchardpay_set_contact_state(
                &owner_id,
                &sender_id,
                &OrchardPayContactState::PendingInboundUnaccepted {
                    their_reference_id: their_payload.reference_id,
                    their_anchor_document_id: anchor_document_id.to_buffer(),
                },
            )?;
            Ok(true)
        }
        Some(OrchardPayContactState::PendingOutbound {
            my_reference_id,
            my_anchor_document_id,
        }) => {
            // This is the counterparty's return signal — complete my own
            // anchor by writing their ReferenceID into my anchorData, using
            // the same shared secret I used to encrypt my own `data`.
            let my_anchor_document_identifier = Identifier::from(my_anchor_document_id);
            let mut my_document = fetch_anchor_document_by_id(
                &orchardpay_contract,
                sdk,
                my_anchor_document_identifier,
            )
            .await?
            .ok_or(OrchardPayError::AnchorNotFound)?;

            let my_encryption_key = own_bounds_verified_key(
                qualified_identity,
                orchardpay_contract.id(),
                Purpose::ENCRYPTION,
            )
            .ok_or(OrchardPayError::OwnKeyMissing)?;
            let outbound_secret = compute_shared_secret(
                sdk,
                orchardpay_contract.id(),
                qualified_identity,
                &my_encryption_key,
                sender_id,
                Purpose::DECRYPTION,
            )
            .await?;
            let anchor_data_bytes = their_payload
                .encrypt(&outbound_secret)
                .map_err(OrchardPayError::Crypto)?;

            my_document.set(ANCHOR_DATA_FIELD, Value::Bytes(anchor_data_bytes));
            my_document.bump_revision();

            let document_type = orchardpay_contract
                .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
                .expect(
                    "contactAnchor document type is part of the checked-in OrchardPay contract schema",
                );
            let identity_key =
                own_signing_key(qualified_identity).ok_or(OrchardPayError::OwnKeyMissing)?;

            let task = DocumentTask::ReplaceDocument {
                document: my_document,
                document_type,
                data_contract: Arc::new(orchardpay_contract),
                qualified_identity: qualified_identity.clone(),
                identity_key,
                token_payment_info: None,
            };
            app_context.run_document_task(task, sdk).await?;

            backend.orchardpay_set_contact_state(
                &owner_id,
                &sender_id,
                &OrchardPayContactState::Established {
                    my_reference_id,
                    my_anchor_document_id,
                    their_reference_id: their_payload.reference_id,
                },
            )?;
            Ok(true)
        }
        Some(
            OrchardPayContactState::PendingInboundUnaccepted { .. }
            | OrchardPayContactState::Established { .. },
        ) => {
            // Already tracked in a phase this signal doesn't advance
            // (a duplicate/replayed memo, or an established relationship
            // resending). Nothing to do — not an error.
            Ok(false)
        }
    }
}

/// Find `identity`'s own key for `purpose`, bounded via
/// `ContractBounds::SingleContractDocumentType` to OrchardPay's contract +
/// `contactAnchor`. Unlike DashPay's `get_first_public_key_matching` (which
/// has no `contract_bounds` parameter), this only ever returns a key
/// actually scoped to this contract, so it can't accidentally return an
/// unrelated ENCRYPTION/DECRYPTION key the identity happens to also hold.
fn own_bounds_verified_key(
    identity: &QualifiedIdentity,
    orchardpay_contract_id: Identifier,
    purpose: Purpose,
) -> Option<IdentityPublicKey> {
    let expected_bounds = ContractBounds::SingleContractDocumentType {
        id: orchardpay_contract_id,
        document_type_name: CONTACT_ANCHOR_DOCUMENT_TYPE.to_string(),
    };
    identity
        .identity
        .public_keys()
        .values()
        .find(|key| key.purpose() == purpose && key.contract_bounds() == Some(&expected_bounds))
        .cloned()
}

/// Find a key suitable for signing a document state transition (an
/// AUTHENTICATION key at MEDIUM security or higher — MASTER cannot sign
/// document operations). Used only by [`handle_incoming_anchor_signal`],
/// which runs unattended (no UI to let the user pick a key), unlike
/// [`initiate_contact`]/[`accept_contact`] which take the caller's chosen
/// `identity_key` directly.
fn own_signing_key(identity: &QualifiedIdentity) -> Option<IdentityPublicKey> {
    use dash_sdk::dpp::identity::{KeyType, SecurityLevel};
    identity
        .identity
        .get_first_public_key_matching(
            Purpose::AUTHENTICATION,
            [
                SecurityLevel::CRITICAL,
                SecurityLevel::HIGH,
                SecurityLevel::MEDIUM,
            ]
            .into(),
            KeyType::all_key_types().into(),
            false,
        )
        .cloned()
}

/// Compute the ECDH shared secret for a message directed at
/// `counterparty_id`, using my own `my_key`'s private bytes and
/// `counterparty_id`'s bounds-verified key of `counterparty_key_purpose`.
///
/// Symmetric by construction: encrypting *to* someone uses my ENCRYPTION key
/// together with their DECRYPTION key; decrypting *from* someone uses my
/// DECRYPTION key together with their ENCRYPTION key. ECDH's commutativity
/// means both sides land on the same secret for a given direction.
async fn compute_shared_secret(
    sdk: &Sdk,
    orchardpay_contract_id: Identifier,
    my_identity: &QualifiedIdentity,
    my_key: &IdentityPublicKey,
    counterparty_id: Identifier,
    counterparty_key_purpose: Purpose,
) -> Result<Zeroizing<[u8; 32]>, TaskError> {
    let my_private_key = my_identity
        .resolve_private_key_bytes(PrivateKeyTarget::PrivateKeyOnMainIdentity, my_key.id())
        .await?
        .map(|(_, key)| key)
        .ok_or(OrchardPayError::OwnKeyMissing)?;

    let counterparty_key = fetch_bounds_verified_counterparty_key(
        sdk,
        orchardpay_contract_id,
        counterparty_id,
        counterparty_key_purpose,
    )
    .await?;

    crate::backend_task::dashpay::encryption::generate_ecdh_shared_key(
        &my_private_key[..],
        &counterparty_key,
    )
    .map_err(|detail| TaskError::EncryptionError { detail })
}

/// Fetch a `contactAnchor` document directly by its DocumentID — never by
/// query, per `docs/orchardpay/PROTOCOL_DESIGN.md`'s core privacy property
/// (no `contactAnchor` is ever discoverable by anything but knowing its ID
/// in advance, e.g. from a memo).
async fn fetch_anchor_document_by_id(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    document_id: Identifier,
) -> Result<Option<Document>, TaskError> {
    let mut query = DocumentQuery::new(orchardpay_contract.clone(), CONTACT_ANCHOR_DOCUMENT_TYPE)
        .map_err(|e| OrchardPayError::QueryCreation {
        query_target: "contactAnchor fetch by id",
        source: Box::new(e),
    })?;
    query = query.with_where(WhereClause {
        field: "$id".to_string(),
        operator: WhereOperator::Equal,
        value: Value::Identifier(document_id.to_buffer()),
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
