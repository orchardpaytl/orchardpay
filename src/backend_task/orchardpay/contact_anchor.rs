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
//! `data` is encrypted under an ECDH shared secret (readable by both the
//! owner and the counterparty), the same as before. `anchorData` is now
//! encrypted under the wallet's fixed, HD-derived, self-only key instead —
//! see `encryption`'s module doc and `docs/orchardpay/PROTOCOL_DESIGN.md`'s
//! "`anchorData`: a wallet-local recovery record" for why the two fields
//! deliberately use different key schemes.

use crate::backend_task::document::DocumentTask;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::encryption::{AnchorDataRecord, ContactAnchorPayload};
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::keys::{
    CONTACT_ANCHOR_DOCUMENT_TYPE, fetch_bounds_verified_counterparty_key,
};
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::backend_task::{
    BackendTaskSuccessResult, NETWORK_REQUEST_TIMEOUT, await_network_request_with_timeout,
};
use crate::context::AppContext;
use crate::model::orchardpay::{
    AnchorRole, OrchardPayContactState, PendingOperationStep, PendingOrchardPayOperation,
    ScheduledAnchorReplace, validate_send_amount,
};
use crate::model::qualified_identity::{PrivateKeyTarget, QualifiedIdentity};
use crate::model::wallet::WalletSeedHash;
use bip39::rand::RngCore;
use bip39::rand::rngs::OsRng;
use bip39::rand::{SeedableRng, rngs::StdRng};
use dash_sdk::Sdk;
use dash_sdk::dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
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

/// Default amount for the anchor-signaling shielded transfer, used by Send
/// Friend Request. Its primary purpose is still to deliver a memo, not to
/// move meaningful value, but it's deliberately equal to
/// [`crate::model::orchardpay::MIN_SEND_AMOUNT_CREDITS`] — the shared floor
/// every OrchardPay send path enforces — rather than an independent value,
/// so the two concepts can't drift apart. Sending one costs the sender
/// something, however little, as a small barrier to spamming contact
/// requests.
///
/// `initiate_contact` itself takes a caller-supplied `amount_credits`
/// instead of referencing this directly — Direct Send's "include a contact
/// request" branch passes its own user-chosen amount instead of this
/// default (still subject to the same floor, enforced inside
/// `initiate_contact` itself). `pub` so callers building that amount
/// elsewhere (e.g. as a floor for their own input validation) can
/// reference the same constant.
pub const ANCHOR_SIGNAL_AMOUNT_CREDITS: u64 = crate::model::orchardpay::MIN_SEND_AMOUNT_CREDITS;

/// Platform-assigned `$createdAt` (ms since epoch) of the document a
/// `DocumentTask::BroadcastDocument` just broadcast, if `result` is that
/// variant. Used to snapshot "when I sent this request" into local contact
/// state without a second network round-trip — the broadcast response
/// already carries it.
fn broadcast_document_created_at(result: &BackendTaskSuccessResult) -> Option<u64> {
    match result {
        BackendTaskSuccessResult::BroadcastedDocument(document) => document.created_at(),
        _ => None,
    }
}

/// Start a new contact relationship with `counterparty_identity_id`:
/// publish my own `contactAnchor` (with `anchorData` already populated from
/// what I know at this point — see [`AnchorDataRecord`]) and send a
/// memo-tagged shielded transfer to their published `shieldedAddress`, worth
/// `amount_credits` (Send Friend Request passes
/// [`ANCHOR_SIGNAL_AMOUNT_CREDITS`]; Direct Send's "include a contact
/// request" branch passes the user's own typed amount instead).
#[allow(clippy::too_many_arguments)]
pub async fn initiate_contact(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    counterparty_name: String,
    seed_hash: WalletSeedHash,
    amount_credits: u64,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    if owner_id == counterparty_identity_id {
        return Err(OrchardPayError::CounterpartyKeyMissing.into());
    }
    validate_send_amount(amount_credits)
        .map_err(|source| TaskError::OrchardPayAmountTooLow { source })?;

    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();

    let backend = app_context.wallet_backend()?;
    if backend
        .orchardpay_get_contact_state(&contract_id, &owner_id, &counterparty_identity_id)?
        .is_some()
    {
        // Already initiated, already inbound-pending, or already established
        // — the caller should be looking at that existing state, not
        // starting a new one. The UI's search screen already pre-checks
        // this (see contact_search.rs's existing_relationship field), so
        // reaching here means the check raced with stale search results —
        // still worth a clear, distinct error rather than the misleading
        // "not found".
        return Err(OrchardPayError::RelationshipAlreadyExists.into());
    }

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    // Resume a previously-interrupted attempt instead of starting fresh, if
    // one was left behind (document published and/or transfer sent, but the
    // final local state write never landed) — see M-02 of
    // `docs/ai-design/2026-07-26-m02-atomic-contact-payment-flows/README.md`.
    // Reusing the persisted `my_reference_id`/`document_id` instead of
    // generating fresh ones is what prevents a naive retry from publishing a
    // second, orphaned anchor.
    let pending = backend.orchardpay_get_pending_operation(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?;

    let (my_reference_id, document_id, needs_transfer, mut broadcast_result) = match pending {
        Some(PendingOrchardPayOperation::ContactAnchor {
            my_reference_id,
            my_anchor_document_id,
            step,
        }) => (
            my_reference_id,
            Identifier::from(my_anchor_document_id),
            matches!(step, PendingOperationStep::DocumentPublished),
            None,
        ),
        _ => {
            let my_encryption_key = own_bounds_verified_key(
                &qualified_identity,
                orchardpay_contract.id(),
                Purpose::ENCRYPTION,
            )
            .ok_or(OrchardPayError::OwnKeyMissing)?;

            // Fetch both of the counterparty's keys up front: DECRYPTION
            // drives `data`'s ECDH secret right now, ENCRYPTION gets cached
            // in `anchorData` for reading their future messages — no reason
            // to make that a second network trip once messaging actually
            // needs it.
            let (counterparty_decryption_key, counterparty_decryption_pubkey) =
                fetch_counterparty_key_bytes(
                    sdk,
                    orchardpay_contract.id(),
                    counterparty_identity_id,
                    Purpose::DECRYPTION,
                )
                .await?;
            let (_, counterparty_encryption_pubkey) = fetch_counterparty_key_bytes(
                sdk,
                orchardpay_contract.id(),
                counterparty_identity_id,
                Purpose::ENCRYPTION,
            )
            .await?;

            let shared_secret = compute_shared_secret_from_key(
                app_context,
                &qualified_identity,
                &my_encryption_key,
                &counterparty_decryption_key,
                seed_hash,
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

            let anchor_data_key = backend
                .orchardpay_anchor_data_key(&seed_hash, app_context.network)
                .await?;
            // `their_reference_id` is seeded with a self-recognizable filler
            // (this identity's own ID — negligible collision risk against a
            // genuine random 32-byte `reference_id`) rather than left `None`.
            // Both this and the acceptor's anchor now look "complete" from
            // creation; a deferred `ScheduledAnchorReplace` (written below,
            // once the real on-chain `$createdAt` is known) swaps the filler
            // for the real value later, removing the create-vs-replace
            // timing asymmetry an outside observer could otherwise use to
            // tell initiator and acceptor apart. See the 2026-07-27
            // adversarial audit's finding 5.
            let anchor_record = AnchorDataRecord {
                counterparty_identity_id: counterparty_identity_id.to_buffer(),
                counterparty_name_snapshot: Some(counterparty_name.clone()),
                my_reference_id,
                their_reference_id: Some(owner_id.to_buffer()),
                my_initial_message: None,
                my_core_payment_xpub: None,
                my_dedicated_shielded_address: None,
                counterparty_encryption_pubkey: Some(counterparty_encryption_pubkey),
                counterparty_decryption_pubkey: Some(counterparty_decryption_pubkey),
            };
            let anchor_data_bytes = anchor_record
                .encrypt(&anchor_data_key)
                .map_err(OrchardPayError::Crypto)?;

            let document_type = orchardpay_contract
                .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
                .expect(
                    "contactAnchor document type is part of the checked-in OrchardPay contract schema",
                );

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

            // Persist intent *before* the first network side effect — if the
            // broadcast or transfer below fails, a retry finds this marker
            // and resumes instead of generating a second anchor.
            backend.orchardpay_set_pending_operation(
                &contract_id,
                &owner_id,
                &counterparty_identity_id,
                &PendingOrchardPayOperation::ContactAnchor {
                    my_reference_id,
                    my_anchor_document_id: document_id.to_buffer(),
                    step: PendingOperationStep::DocumentPublished,
                },
            )?;

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

            // Best-effort: if this write is somehow missed (a crash in this
            // exact narrow window), the filler simply never gets swapped for
            // the real value — local functionality (messaging, etc.) is
            // entirely unaffected, since it never depends on `anchorData`.
            // Only this one relationship's anchor-based recovery record
            // stays incomplete, the same accepted cost finding 5 already
            // takes on for the normal (non-crash) case.
            if let Some(created_at) = broadcast_document_created_at(&result) {
                backend.orchardpay_set_scheduled_anchor_replace(
                    &contract_id,
                    &owner_id,
                    &counterparty_identity_id,
                    &ScheduledAnchorReplace {
                        anchor_document_id: document_id.to_buffer(),
                        anchor_created_at: created_at,
                        role: AnchorRole::Initiator,
                    },
                )?;
            }

            (my_reference_id, document_id, true, Some(result))
        }
    };

    if needs_transfer {
        let mut memo = [0u8; 36];
        memo[..4].copy_from_slice(&MEMO_TAG_ANCHOR);
        memo[4..].copy_from_slice(&document_id.to_buffer());

        backend
            .shielded_transfer(
                &seed_hash,
                0,
                &counterparty_shielded_address,
                amount_credits,
                memo,
            )
            .await?;

        backend.orchardpay_set_pending_operation(
            &contract_id,
            &owner_id,
            &counterparty_identity_id,
            &PendingOrchardPayOperation::ContactAnchor {
                my_reference_id,
                my_anchor_document_id: document_id.to_buffer(),
                step: PendingOperationStep::TransferSent,
            },
        )?;
    }

    backend.orchardpay_set_contact_state(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
        &OrchardPayContactState::PendingOutbound {
            my_reference_id,
            my_anchor_document_id: document_id.to_buffer(),
            name: Some(counterparty_name),
            created_at: broadcast_result
                .as_ref()
                .and_then(broadcast_document_created_at),
        },
    )?;
    backend.orchardpay_clear_pending_operation(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?;

    Ok(broadcast_result
        .take()
        .unwrap_or(BackendTaskSuccessResult::None))
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
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();

    let backend = app_context.wallet_backend()?;
    let their_reference_id = match backend.orchardpay_get_contact_state(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )? {
        Some(OrchardPayContactState::PendingInboundUnaccepted {
            their_reference_id, ..
        }) => their_reference_id,
        _ => return Err(OrchardPayError::AnchorNotFound.into()),
    };

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    // Needed for the final `Established` state regardless of whether this
    // call ends up publishing fresh or resuming an interrupted attempt —
    // cheap, read-only lookups, safe to repeat on a resume.
    let (counterparty_decryption_key, counterparty_decryption_pubkey) =
        fetch_counterparty_key_bytes(
            sdk,
            orchardpay_contract.id(),
            counterparty_identity_id,
            Purpose::DECRYPTION,
        )
        .await?;
    let (_, counterparty_encryption_pubkey) = fetch_counterparty_key_bytes(
        sdk,
        orchardpay_contract.id(),
        counterparty_identity_id,
        Purpose::ENCRYPTION,
    )
    .await?;
    // Best-effort: a DPNS lookup failure shouldn't block accepting the
    // contact, it just means the local recovery record won't carry a name
    // snapshot yet.
    let counterparty_name =
        resolve_dpns_name_for_identity(app_context, sdk, counterparty_identity_id)
            .await
            .ok()
            .flatten();

    // Resume a previously-interrupted attempt instead of starting fresh, if
    // one was left behind — see M-02 of
    // `docs/ai-design/2026-07-26-m02-atomic-contact-payment-flows/README.md`
    // and `initiate_contact`'s identical treatment above.
    let pending = backend.orchardpay_get_pending_operation(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?;

    let (my_reference_id, document_id, needs_transfer, mut broadcast_result) = match pending {
        Some(PendingOrchardPayOperation::ContactAnchor {
            my_reference_id,
            my_anchor_document_id,
            step,
        }) => (
            my_reference_id,
            Identifier::from(my_anchor_document_id),
            matches!(step, PendingOperationStep::DocumentPublished),
            None,
        ),
        _ => {
            let my_encryption_key = own_bounds_verified_key(
                &qualified_identity,
                orchardpay_contract.id(),
                Purpose::ENCRYPTION,
            )
            .ok_or(OrchardPayError::OwnKeyMissing)?;

            let shared_secret = compute_shared_secret_from_key(
                app_context,
                &qualified_identity,
                &my_encryption_key,
                &counterparty_decryption_key,
                seed_hash,
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

            let anchor_data_key = backend
                .orchardpay_anchor_data_key(&seed_hash, app_context.network)
                .await?;
            let anchor_record = AnchorDataRecord {
                counterparty_identity_id: counterparty_identity_id.to_buffer(),
                counterparty_name_snapshot: counterparty_name.clone(),
                my_reference_id,
                their_reference_id: Some(their_reference_id),
                my_initial_message: None,
                my_core_payment_xpub: None,
                my_dedicated_shielded_address: None,
                counterparty_encryption_pubkey: Some(counterparty_encryption_pubkey.clone()),
                counterparty_decryption_pubkey: Some(counterparty_decryption_pubkey.clone()),
            };
            let anchor_data_bytes = anchor_record
                .encrypt(&anchor_data_key)
                .map_err(OrchardPayError::Crypto)?;

            let document_type = orchardpay_contract
                .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
                .expect(
                    "contactAnchor document type is part of the checked-in OrchardPay contract schema",
                );

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

            // Persist intent *before* the first network side effect, same
            // reasoning as `initiate_contact`.
            backend.orchardpay_set_pending_operation(
                &contract_id,
                &owner_id,
                &counterparty_identity_id,
                &PendingOrchardPayOperation::ContactAnchor {
                    my_reference_id,
                    my_anchor_document_id: document_id.to_buffer(),
                    step: PendingOperationStep::DocumentPublished,
                },
            )?;

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

            // Unlike the initiator, this anchor already carries the real
            // `their_reference_id` from creation (see the `AnchorDataRecord`
            // literal above) — this marker's delayed action is a pure
            // re-seal (fresh nonce, unchanged content), purely so this side
            // also shows exactly one replace after some delay, matching the
            // initiator's side. Best-effort, same crash-window reasoning as
            // `initiate_contact`'s own write.
            if let Some(created_at) = broadcast_document_created_at(&result) {
                backend.orchardpay_set_scheduled_anchor_replace(
                    &contract_id,
                    &owner_id,
                    &counterparty_identity_id,
                    &ScheduledAnchorReplace {
                        anchor_document_id: document_id.to_buffer(),
                        anchor_created_at: created_at,
                        role: AnchorRole::Acceptor,
                    },
                )?;
            }

            (my_reference_id, document_id, true, Some(result))
        }
    };

    if needs_transfer {
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

        backend.orchardpay_set_pending_operation(
            &contract_id,
            &owner_id,
            &counterparty_identity_id,
            &PendingOrchardPayOperation::ContactAnchor {
                my_reference_id,
                my_anchor_document_id: document_id.to_buffer(),
                step: PendingOperationStep::TransferSent,
            },
        )?;
    }

    backend.orchardpay_set_contact_state(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
        &OrchardPayContactState::Established {
            my_reference_id,
            my_anchor_document_id: document_id.to_buffer(),
            their_reference_id,
            counterparty_encryption_pubkey,
            counterparty_decryption_pubkey,
            name: counterparty_name,
            created_at: broadcast_result
                .as_ref()
                .and_then(broadcast_document_created_at),
        },
    )?;
    backend.orchardpay_clear_pending_operation(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?;

    Ok(broadcast_result
        .take()
        .unwrap_or(BackendTaskSuccessResult::None))
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
    seed_hash: WalletSeedHash,
) -> Result<bool, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();

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

    // No OrchardPay DECRYPTION key at all means this identity hasn't set up
    // OrchardPay yet — routine when trying a signal against every
    // locally-known identity, not a processing failure. `Ok(false)` here
    // (rather than propagating an error) keeps the memo scan's cursor from
    // treating "not this identity" as something worth retrying forever.
    let Some(my_decryption_key) = own_bounds_verified_key(
        qualified_identity,
        orchardpay_contract.id(),
        Purpose::DECRYPTION,
    ) else {
        return Ok(false);
    };

    // Fetch the sender's ENCRYPTION key: it drives the inbound `data`
    // secret now, and its raw bytes get cached in `anchorData` for reading
    // their future messages too.
    let (sender_encryption_key, sender_encryption_pubkey) = fetch_counterparty_key_bytes(
        sdk,
        orchardpay_contract.id(),
        sender_id,
        Purpose::ENCRYPTION,
    )
    .await?;

    let shared_secret = compute_shared_secret_from_key(
        app_context,
        qualified_identity,
        &my_decryption_key,
        &sender_encryption_key,
        seed_hash,
    )
    .await?;

    // An AEAD tag mismatch means this signal's `data` field wasn't encrypted
    // to this identity's key (wrong identity — expected on most trials);
    // malformed plaintext means corrupted data. Neither is retryable
    // (retrying re-decrypts the same bytes with the same key), so treat both
    // as "not applicable" rather than a processing error.
    let Ok(their_payload) = ContactAnchorPayload::decrypt(&shared_secret, &data_bytes) else {
        return Ok(false);
    };

    let backend = app_context.wallet_backend()?;
    match backend.orchardpay_get_contact_state(&contract_id, &owner_id, &sender_id)? {
        None => {
            // Fresh inbound request. Best-effort: a DPNS lookup failure
            // shouldn't block recording the request, it just means the
            // Contacts list won't show a name for it yet.
            let sender_name = resolve_dpns_name_for_identity(app_context, sdk, sender_id)
                .await
                .ok()
                .flatten();
            backend.orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &sender_id,
                &OrchardPayContactState::PendingInboundUnaccepted {
                    their_reference_id: their_payload.reference_id,
                    their_anchor_document_id: anchor_document_id.to_buffer(),
                    name: sender_name,
                    created_at: document.created_at(),
                },
            )?;
            Ok(true)
        }
        Some(OrchardPayContactState::PendingOutbound {
            my_reference_id,
            my_anchor_document_id,
            name,
            created_at,
        }) => {
            // This is the counterparty's return signal. Read (not write)
            // my own anchor's `anchorData` to recover the counterparty
            // pubkeys already cached there from initiate time — enough to
            // complete local state below. The Platform document itself is
            // **not** replaced here: `their_reference_id` was already
            // seeded with a self-recognizable filler at creation (see
            // `initiate_contact`), and the real value only gets published
            // once `ScheduledAnchorReplace`'s delayed check (10h, checked
            // opportunistically on app use — see finding 5 of the
            // 2026-07-27 adversarial audit) fires, so an outside observer
            // can't use "was this anchor ever replaced, and how soon" as a
            // pending-vs-established / initiator-vs-acceptor signal.
            let my_anchor_document_identifier = Identifier::from(my_anchor_document_id);
            let my_document = fetch_anchor_document_by_id(
                &orchardpay_contract,
                sdk,
                my_anchor_document_identifier,
            )
            .await?
            .ok_or(OrchardPayError::AnchorNotFound)?;

            let anchor_data_key = app_context
                .wallet_backend()?
                .orchardpay_anchor_data_key(&seed_hash, app_context.network)
                .await?;

            let mut anchor_record = match my_document.properties().get(ANCHOR_DATA_FIELD) {
                Some(Value::Bytes(bytes)) if !bytes.is_empty() => {
                    AnchorDataRecord::decrypt(&anchor_data_key, bytes)
                        .map_err(OrchardPayError::Crypto)?
                }
                _ => AnchorDataRecord {
                    counterparty_identity_id: sender_id.to_buffer(),
                    counterparty_name_snapshot: None,
                    my_reference_id,
                    their_reference_id: None,
                    my_initial_message: None,
                    my_core_payment_xpub: None,
                    my_dedicated_shielded_address: None,
                    counterparty_encryption_pubkey: None,
                    counterparty_decryption_pubkey: None,
                },
            };
            anchor_record.their_reference_id = Some(their_payload.reference_id);
            anchor_record.counterparty_encryption_pubkey = Some(sender_encryption_pubkey);
            if anchor_record.counterparty_decryption_pubkey.is_none() {
                let (_, sender_decryption_pubkey) = fetch_counterparty_key_bytes(
                    sdk,
                    orchardpay_contract.id(),
                    sender_id,
                    Purpose::DECRYPTION,
                )
                .await?;
                anchor_record.counterparty_decryption_pubkey = Some(sender_decryption_pubkey);
            }

            backend.orchardpay_set_contact_state(
                &contract_id,
                &owner_id,
                &sender_id,
                &OrchardPayContactState::Established {
                    my_reference_id,
                    my_anchor_document_id,
                    their_reference_id: their_payload.reference_id,
                    counterparty_encryption_pubkey: anchor_record
                        .counterparty_encryption_pubkey
                        .clone()
                        .expect("set immediately above"),
                    counterparty_decryption_pubkey: anchor_record
                        .counterparty_decryption_pubkey
                        .clone()
                        .expect(
                            "set immediately above, or already present in the decrypted record",
                        ),
                    name,
                    created_at,
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

/// Check for and fire `counterparty`'s due [`ScheduledAnchorReplace`]
/// marker, if any — see the 2026-07-27 adversarial audit's finding 5 (the
/// pending-vs-established pairing-signal mitigation). Called
/// opportunistically from the cold-boot/unlock catch-up pass
/// (`AppContext::bootstrap_wallet_addresses_jit`'s seed scope), not a
/// dedicated timer — see [`crate::model::orchardpay::ANCHOR_REPLACE_DELAY_MS`]'s
/// doc comment for why that's deliberate.
///
/// A no-op (`Ok(())`) if: nothing is scheduled for this counterparty; the
/// marker exists but isn't due yet; or (for [`AnchorRole::Initiator`]
/// specifically) the real `their_reference_id` isn't known locally yet —
/// the counterparty hasn't completed the handshake, so there's nothing
/// real to publish over the filler. In all these cases the marker is left
/// in place, checked again next time this pass runs.
///
/// Takes `&AppContext` rather than the `&Arc<AppContext>` its sibling
/// entry points ([`initiate_contact`], [`accept_contact`],
/// [`handle_incoming_anchor_signal`]) take: this is called from
/// `bootstrap_wallet_addresses_jit`, a plain `&self` method with no `Arc`
/// of its own to hand down. Everything this function needs
/// (`orchardpay_contract()`, `run_document_task`, `network`) works the same
/// either way.
pub async fn fire_due_scheduled_anchor_replace(
    app_context: &AppContext,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<(), TaskError> {
    let owner_id = qualified_identity.identity.id();
    let Some(orchardpay_contract) = app_context.orchardpay_contract() else {
        return Ok(());
    };
    let contract_id = orchardpay_contract.id();
    let backend = app_context.wallet_backend()?;

    let Some(marker) = backend.orchardpay_get_scheduled_anchor_replace(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?
    else {
        return Ok(());
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if !marker.is_due(now_ms) {
        return Ok(());
    }

    // For the initiator role, the real value must actually be known
    // locally (the counterparty must have completed the handshake) before
    // there's anything real to publish over the filler.
    let real_their_reference_id = if matches!(marker.role, AnchorRole::Initiator) {
        match backend.orchardpay_get_contact_state(
            &contract_id,
            &owner_id,
            &counterparty_identity_id,
        )? {
            Some(OrchardPayContactState::Established {
                their_reference_id, ..
            }) => Some(their_reference_id),
            _ => return Ok(()),
        }
    } else {
        None
    };

    let anchor_document_identifier = Identifier::from(marker.anchor_document_id);
    let mut document =
        fetch_anchor_document_by_id(&orchardpay_contract, sdk, anchor_document_identifier)
            .await?
            .ok_or(OrchardPayError::AnchorNotFound)?;

    let anchor_data_key = backend
        .orchardpay_anchor_data_key(&seed_hash, app_context.network)
        .await?;
    let Some(Value::Bytes(bytes)) = document.properties().get(ANCHOR_DATA_FIELD) else {
        return Err(OrchardPayError::AnchorNotFound.into());
    };
    let mut anchor_record =
        AnchorDataRecord::decrypt(&anchor_data_key, bytes).map_err(OrchardPayError::Crypto)?;

    if let Some(real_their_reference_id) = real_their_reference_id {
        // Initiator: swap the filler for the real value. Fixed-size field,
        // so this is a same-length ciphertext change, not a size-changing
        // transition.
        anchor_record.their_reference_id = Some(real_their_reference_id);
    }
    // Acceptor (or initiator with nothing new to change): re-encrypting the
    // unchanged record still produces a different ciphertext — `encrypt()`
    // draws a fresh AEAD nonce on every call (`encryption.rs`) — at the
    // identical total length, with no content change required.

    let anchor_data_bytes = anchor_record
        .encrypt(&anchor_data_key)
        .map_err(OrchardPayError::Crypto)?;
    document.set(ANCHOR_DATA_FIELD, Value::Bytes(anchor_data_bytes));
    document.bump_revision();

    let document_type = orchardpay_contract
        .document_type_cloned_for_name(CONTACT_ANCHOR_DOCUMENT_TYPE)
        .expect("contactAnchor document type is part of the checked-in OrchardPay contract schema");
    let identity_key = own_signing_key(qualified_identity).ok_or(OrchardPayError::OwnKeyMissing)?;

    let task = DocumentTask::ReplaceDocument {
        document,
        document_type,
        data_contract: Arc::new(orchardpay_contract),
        qualified_identity: qualified_identity.clone(),
        identity_key,
        token_payment_info: None,
    };
    app_context.run_document_task(task, sdk).await?;

    backend.orchardpay_clear_scheduled_anchor_replace(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )?;

    Ok(())
}

/// Find `identity`'s own key for `purpose`, bounded via
/// `ContractBounds::SingleContractDocumentType` to OrchardPay's contract +
/// `contactAnchor`. Unlike DashPay's `get_first_public_key_matching` (which
/// has no `contract_bounds` parameter), this only ever returns a key
/// actually scoped to this contract, so it can't accidentally return an
/// unrelated ENCRYPTION/DECRYPTION key the identity happens to also hold.
///
/// `pub(crate)` so `ui::orchardpay::orchardpay_screen` can reuse it for the
/// "does this identity have OrchardPay-bound keys yet" readiness check.
pub(crate) fn own_bounds_verified_key(
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
/// document operations). Used only by [`fire_due_scheduled_anchor_replace`],
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

/// Fetch and bounds-verify `counterparty_id`'s key of `purpose`, returning
/// both the `IdentityPublicKey` (for immediate ECDH use) and its raw public
/// key bytes (for caching in an [`AnchorDataRecord`]) — one fetch serves
/// both needs instead of making the caller choose.
async fn fetch_counterparty_key_bytes(
    sdk: &Sdk,
    orchardpay_contract_id: Identifier,
    counterparty_id: Identifier,
    purpose: Purpose,
) -> Result<(IdentityPublicKey, Vec<u8>), TaskError> {
    let key = fetch_bounds_verified_counterparty_key(
        sdk,
        orchardpay_contract_id,
        counterparty_id,
        purpose,
    )
    .await?;
    let bytes = key.data().as_slice().to_vec();
    Ok((key, bytes))
}

/// Compute the ECDH shared secret from my own `my_key`'s resolved private
/// bytes and an already-fetched `counterparty_key`.
///
/// Symmetric by construction: encrypting *to* someone uses my ENCRYPTION key
/// together with their DECRYPTION key; decrypting *from* someone uses my
/// DECRYPTION key together with their ENCRYPTION key. ECDH's commutativity
/// means both sides land on the same secret for a given direction.
///
/// `pub(crate)` so `orchardpay::messages` can reuse it against a synthetic
/// `IdentityPublicKey` built from `OrchardPayContactState::Established`'s
/// cached counterparty pubkey bytes, with no network fetch needed per
/// message. `counterparty_key.id()` is never read by this function, only
/// `.key_type()`/`.data()` — the synthetic key's placeholder `id` is safe.
///
/// If `my_key`'s private bytes have no local vault record (a reinstalled
/// wallet with only the recovery phrase — no local database left), this
/// falls back to deriving it purely from `seed_hash`'s seed, matching by
/// public key bytes. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
/// "HD-deriving the ENCRYPTION/DECRYPTION identity keys" — this is what
/// makes that recovery actually work, not just the key generation change.
pub(crate) async fn compute_shared_secret_from_key(
    app_context: &Arc<AppContext>,
    my_identity: &QualifiedIdentity,
    my_key: &IdentityPublicKey,
    counterparty_key: &IdentityPublicKey,
    seed_hash: WalletSeedHash,
) -> Result<Zeroizing<[u8; 32]>, TaskError> {
    let resolved = my_identity
        .resolve_private_key_bytes(PrivateKeyTarget::PrivateKeyOnMainIdentity, my_key.id())
        .await?
        .map(|(_, key)| key);

    let my_private_key = match resolved {
        Some(key) => key,
        None => {
            let identity_index = my_identity
                .wallet_index
                .ok_or(OrchardPayError::OwnKeyMissing)?;
            app_context
                .wallet_backend()?
                .orchardpay_find_identity_key_by_pubkey(
                    &seed_hash,
                    app_context.network,
                    identity_index,
                    my_key.data().as_slice(),
                )
                .await?
        }
    };

    crate::backend_task::dashpay::encryption::generate_ecdh_shared_key(
        &my_private_key[..],
        counterparty_key,
    )
    .map_err(|detail| TaskError::EncryptionError { detail })
}

/// Best-effort reverse DPNS lookup for `identity_id`'s registered name, used
/// only to populate `anchorData`'s display-friendly name snapshot. `Ok(None)`
/// when no name is found — not an error, most identities may simply not
/// have registered one.
async fn resolve_dpns_name_for_identity(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    identity_id: Identifier,
) -> Result<Option<String>, TaskError> {
    let mut query =
        DocumentQuery::new(app_context.dpns_contract.clone(), "domain").map_err(|e| {
            OrchardPayError::QueryCreation {
                query_target: "reverse DPNS name lookup",
                source: Box::new(e),
            }
        })?;
    query = query.with_where(WhereClause {
        field: "records.identity".to_string(),
        operator: WhereOperator::Equal,
        value: Value::Identifier(identity_id.to_buffer()),
    });
    query.limit = 1;

    let results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    Ok(results.into_values().flatten().next().and_then(|doc| {
        doc.properties()
            .get("label")
            .and_then(|v| v.as_text())
            .map(|label| format!("{label}.dash"))
    }))
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

/// One page's worth of [`fetch_own_anchors`] — Platform's own
/// `DEFAULT_QUERY_LIMIT`, so a full page is always exactly one query. See
/// [`fetch_all_own_anchors`].
const OWN_ANCHOR_PAGE_SIZE: u32 = 100;

/// Hard cap on how many sequential pages [`fetch_all_own_anchors`] will
/// walk — 400 documents total. Deliberately not a "load more" button: an
/// identity with more than 400 published `contactAnchor` documents (i.e.
/// more established relationships than that) is far outside normal usage,
/// and recovery already runs as a one-shot background task with no
/// incremental UI to extend.
const MAX_OWN_ANCHOR_PAGES: u32 = 4;

/// Fetch one page of `contactAnchor` documents `owner_id` has ever
/// published, via the contract's `byOwner` index (`$ownerId` only — no
/// `$createdAt` component, so results are unordered within a page; callers
/// sort client-side if order matters). Used only by
/// [`fetch_all_own_anchors`] — every other read path in this module fetches
/// by document ID, never by query, to preserve the "no plaintext link"
/// privacy property for anchors *other than my own*. Querying my own
/// anchors by owner leaks nothing new: `$ownerId` is already public on
/// every document I publish.
///
/// `start_after` pages through the `byOwner` index by document ID (via
/// `DocumentQuery::start`) rather than by `$createdAt`, unlike the
/// `encryptedMessage` thread fetch's timestamp cursor — `byOwner` has no
/// `$createdAt` component to range/order on, so a document-ID cursor is
/// the only pagination the existing index supports without a contract
/// migration. Since anchor order is already irrelevant to every caller,
/// this loses nothing.
async fn fetch_own_anchors(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    owner_id: Identifier,
    start_after: Option<Identifier>,
) -> Result<Vec<Document>, TaskError> {
    let mut query = DocumentQuery::new(orchardpay_contract.clone(), CONTACT_ANCHOR_DOCUMENT_TYPE)
        .map_err(|e| OrchardPayError::QueryCreation {
        query_target: "own contactAnchor recovery fetch",
        source: Box::new(e),
    })?;
    query = query.with_where(WhereClause {
        field: "$ownerId".to_string(),
        operator: WhereOperator::Equal,
        value: Value::Identifier(owner_id.to_buffer()),
    });
    query.limit = OWN_ANCHOR_PAGE_SIZE;
    query.start = start_after.map(|id| Start::StartAfter(id.to_vec()));

    let results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    Ok(results.into_values().flatten().collect())
}

/// Fetch every `contactAnchor` document `owner_id` has ever published, up
/// to [`MAX_OWN_ANCHOR_PAGES`] sequential pages of [`OWN_ANCHOR_PAGE_SIZE`]
/// (400 documents total) — automatically, with no pagination UI. Stops
/// early as soon as a page comes back short (fewer than
/// `OWN_ANCHOR_PAGE_SIZE` documents), which means the `byOwner` index is
/// exhausted. If the page cap is hit while the last page was still full,
/// logs a warning rather than surfacing anything to the user — this is a
/// very unlikely edge case (400+ established relationships), not one worth
/// a dedicated UI. Note a later recovery run won't automatically reach
/// further: `start_after` pages by document ID, which sorts independently
/// of publish order, so repeating the same page walk returns the same
/// leading ~400 documents rather than a different, later slice.
async fn fetch_all_own_anchors(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    owner_id: Identifier,
) -> Result<Vec<Document>, TaskError> {
    let mut all = Vec::new();
    let mut start_after = None;

    for _ in 0..MAX_OWN_ANCHOR_PAGES {
        let page = fetch_own_anchors(orchardpay_contract, sdk, owner_id, start_after).await?;
        let page_len = page.len();
        start_after = page.last().map(|document| document.id());
        all.extend(page);

        if (page_len as u32) < OWN_ANCHOR_PAGE_SIZE {
            return Ok(all);
        }
    }

    tracing::warn!(
        owner_id = %owner_id,
        pages = MAX_OWN_ANCHOR_PAGES,
        "OrchardPay: own contactAnchor recovery hit its page cap with the last page still \
         full; some anchors were not recovered."
    );
    Ok(all)
}

/// Outcome of one [`recover_own_anchors`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnchorRecoverySummary {
    pub anchors_found: usize,
    pub contacts_recovered: usize,
    pub already_tracked: usize,
    pub undecryptable: usize,
}

/// Rebuild local contact state from every `contactAnchor` I've ever
/// published (up to [`MAX_OWN_ANCHOR_PAGES`] × [`OWN_ANCHOR_PAGE_SIZE`]) —
/// the "my published anchors" recovery path for a reinstalled/new-device
/// wallet with only the recovery phrase. Queries by
/// [`fetch_all_own_anchors`], decrypts each `anchorData` with the wallet-local
/// key (recoverable from the seed alone — see
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "`anchorData`: a wallet-local
/// recovery record"), and writes local [`OrchardPayContactState`] for every
/// counterparty not already tracked locally. Existing local state is never
/// overwritten — recovery only fills gaps, it never clobbers.
///
/// If a decrypted record's cached counterparty pubkeys are missing (an
/// older anchor, or a partial write) they're re-fetched fresh rather than
/// leaving the recovered contact unable to message — recovery is already
/// paying for several network round trips, one or two more is cheap
/// insurance against a subtly broken recovered contact.
///
/// This closes most, not all, of the relaunch-from-new-wallet gap: it
/// rebuilds every relationship *I* initiated or completed, since I always
/// have my own anchor for those. A relationship where a counterparty sent
/// me a request I never accepted has no anchor of mine to recover from —
/// that `PendingInboundUnaccepted` state only ever lived locally. See
/// `docs/ai-design/2026-07-19-orchardpay-query-workflow-reference/` for the
/// full gap analysis.
pub async fn recover_own_anchors(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    seed_hash: WalletSeedHash,
) -> Result<AnchorRecoverySummary, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();
    let backend = app_context.wallet_backend()?;

    let documents = fetch_all_own_anchors(&orchardpay_contract, sdk, owner_id).await?;
    let anchor_data_key = backend
        .orchardpay_anchor_data_key(&seed_hash, app_context.network)
        .await?;

    let mut summary = AnchorRecoverySummary {
        anchors_found: documents.len(),
        ..Default::default()
    };

    for document in documents {
        let anchor_data_bytes = match document.properties().get(ANCHOR_DATA_FIELD) {
            Some(Value::Bytes(bytes)) if !bytes.is_empty() => bytes,
            _ => {
                summary.undecryptable += 1;
                continue;
            }
        };
        let Ok(anchor_record) = AnchorDataRecord::decrypt(&anchor_data_key, anchor_data_bytes)
        else {
            summary.undecryptable += 1;
            continue;
        };

        let counterparty_id = Identifier::from(anchor_record.counterparty_identity_id);
        if backend
            .orchardpay_get_contact_state(&contract_id, &owner_id, &counterparty_id)?
            .is_some()
        {
            summary.already_tracked += 1;
            continue;
        }

        let name = anchor_record.counterparty_name_snapshot.clone();
        let created_at = document.created_at();
        let state = match anchor_record.their_reference_id {
            // Filler (this identity's own ID, seeded at creation — see
            // `initiate_contact`/finding 5 of the 2026-07-27 adversarial
            // audit) — the real value hasn't been published yet, whether
            // because the counterparty hasn't completed the handshake or
            // `ScheduledAnchorReplace`'s delayed check just hasn't fired
            // yet. Recovers the same as a pre-fix anchor's genuine `None`
            // below: pending, not yet established.
            Some(their_reference_id) if their_reference_id == owner_id.to_buffer() => {
                OrchardPayContactState::PendingOutbound {
                    my_reference_id: anchor_record.my_reference_id,
                    my_anchor_document_id: document.id().to_buffer(),
                    name,
                    created_at,
                }
            }
            Some(their_reference_id) => {
                let counterparty_encryption_pubkey =
                    match anchor_record.counterparty_encryption_pubkey {
                        Some(bytes) => bytes,
                        None => {
                            fetch_counterparty_key_bytes(
                                sdk,
                                orchardpay_contract.id(),
                                counterparty_id,
                                Purpose::ENCRYPTION,
                            )
                            .await?
                            .1
                        }
                    };
                let counterparty_decryption_pubkey =
                    match anchor_record.counterparty_decryption_pubkey {
                        Some(bytes) => bytes,
                        None => {
                            fetch_counterparty_key_bytes(
                                sdk,
                                orchardpay_contract.id(),
                                counterparty_id,
                                Purpose::DECRYPTION,
                            )
                            .await?
                            .1
                        }
                    };
                OrchardPayContactState::Established {
                    my_reference_id: anchor_record.my_reference_id,
                    my_anchor_document_id: document.id().to_buffer(),
                    their_reference_id,
                    counterparty_encryption_pubkey,
                    counterparty_decryption_pubkey,
                    name,
                    created_at,
                }
            }
            None => OrchardPayContactState::PendingOutbound {
                my_reference_id: anchor_record.my_reference_id,
                my_anchor_document_id: document.id().to_buffer(),
                name,
                created_at,
            },
        };

        backend.orchardpay_set_contact_state(&contract_id, &owner_id, &counterparty_id, &state)?;
        summary.contacts_recovered += 1;
    }

    Ok(summary)
}
