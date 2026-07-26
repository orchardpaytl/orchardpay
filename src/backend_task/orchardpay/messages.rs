//! `encryptedMessage` send/receive: `Message`/`Payment`/`PaymentRequest`.
//! See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Message content schema for
//! the three in-scope kinds" for the full design this module implements.
//!
//! Every operation here reads its ECDH inputs from
//! [`OrchardPayContactState::Established`]'s cached counterparty pubkey
//! bytes (populated once, during the `contactAnchor` handshake — see
//! `contact_anchor.rs`) rather than fetching them from Platform again. That
//! caching is the entire point of the `anchorData` redesign: sending or
//! reading a message costs zero network calls beyond the document
//! broadcast/query itself.
//!
//! Two distinct ECDH directions per relationship, matching `contactAnchor`'s
//! own `data` field exactly:
//! - **Outbound** (documents I send, tagged with *my* `refId`): my
//!   ENCRYPTION key + the counterparty's cached DECRYPTION pubkey.
//! - **Inbound** (documents *they* send, tagged with *their* `refId`): my
//!   DECRYPTION key + the counterparty's cached ENCRYPTION pubkey.

use crate::backend_task::document::DocumentTask;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::{
    compute_shared_secret_from_key, own_bounds_verified_key,
};
use crate::backend_task::orchardpay::encryption::MessageContent;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::backend_task::{
    BackendTaskSuccessResult, NETWORK_REQUEST_TIMEOUT, await_network_request_with_timeout,
};
use crate::context::AppContext;
use crate::model::orchardpay::{
    OrchardPayContactState, validate_message_text, validate_payment_memo,
};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use bip39::rand::{SeedableRng, rngs::StdRng};
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::document::{
    Document as DppDocument, DocumentV0, DocumentV0Getters, DocumentV0Setters,
};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::identity_public_key::v0::IdentityPublicKeyV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::dpp::platform_value::{Bytes32, Value};
use dash_sdk::drive::query::{OrderClause, WhereClause, WhereOperator};
use dash_sdk::platform::{
    DataContract, Document, DocumentQuery, FetchMany, Identifier, IdentityPublicKey,
};
use futures::future::join_all;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ENCRYPTED_MESSAGE_DOCUMENT_TYPE: &str = "encryptedMessage";
const REF_ID_FIELD: &str = "refId";
const MSG_DATA_FIELD: &str = "msgData";
const EXTRA_FIELD: &str = "extra";
const CREATED_AT_FIELD: &str = "$createdAt";

/// One page's worth of a single side's `encryptedMessage` documents —
/// Platform's own `DEFAULT_QUERY_LIMIT`, so a full page is always exactly
/// one query, whether that's the initial (newest) page or a "see more
/// history" page further back. See [`fetch_messages_by_ref_id`].
pub const MESSAGE_PAGE_SIZE: u32 = 100;

/// 4-byte tag identifying a real-payment-signaling shielded transfer's
/// memo, mirroring `contact_anchor::MEMO_TAG_ANCHOR`. Followed by a 32-byte
/// DocumentID for a 36-byte memo total — either a freshly-broadcast
/// `Payment` document's own ID (an unprompted payment), or an existing
/// `PaymentRequest`'s ID (a bare fulfillment transfer with no new document
/// at all). See the protocol doc's "Correlating a real payment to its
/// `encryptedMessage`".
pub const MEMO_TAG_PAYMENT: [u8; 4] = *b"OPP1";

/// A decrypted `encryptedMessage`, reconstructed for a thread view.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreadMessage {
    pub document_id: Identifier,
    /// `true` if `qualified_identity` (the thread's owner) sent this
    /// message; `false` if the counterparty did.
    pub from_me: bool,
    pub created_at: Option<u64>,
    pub updated_at: Option<u64>,
    pub content: MessageContent,
    /// For `Payment`/`PaymentRequest` content: the real credits value this
    /// wallet has confirmed for the correlated shielded transfer — see
    /// `decode_thread_message` for exactly which source(s) populate this
    /// per content kind/direction. `None` means not yet confirmed (a
    /// message this wallet's memo scan hasn't reached, an unfulfilled
    /// `PaymentRequest`, or a `Payment` `from_me` — which needs no
    /// verification, since I chose the real amount myself). Compare
    /// against `content`'s own claimed `amount` to detect a mismatch — see
    /// the protocol doc's "Amount trust model". For `PaymentRequest`,
    /// `Some` also means "paid" — the UI hides the "Pay" button and shows
    /// a PAID badge once this is set, on both sides of the relationship.
    pub verified_amount: Option<u64>,
}

/// Why a [`ReceiptAlert`] was raised — mirrors the three ways a
/// `PaymentRequest` the payer already has a `PaymentRequestReceipt` for can
/// no longer be trusted at face value. See [`load_thread`]'s "detect
/// receipt anomalies" pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAlertReason {
    /// No document with the receipt's `original_document_id` was found in
    /// the thread at all — deleted, or never existed on this fetch.
    OriginalDeleted,
    /// A document with that ID exists, but its decrypted content is no
    /// longer `MessageContent::PaymentRequest`.
    OriginalChangedKind,
    /// Still a `PaymentRequest`, not legitimately cancelled, but its
    /// `amount`/`memo` no longer match what the receipt recorded.
    OriginalAmountOrMemoMismatch,
}

/// A payer's saved `PaymentRequestReceipt` whose original `PaymentRequest`
/// no longer matches it — surfaced by [`load_thread`] as a warning, never
/// rendered as a normal thread bubble. Built entirely from data already
/// decrypted while reconstructing the thread; no second Platform fetch.
#[derive(Debug, Clone)]
pub struct ReceiptAlert {
    pub original_document_id: Identifier,
    pub amount: u64,
    pub memo: Option<String>,
    pub original_created_at: Option<u64>,
    pub reason: ReceiptAlertReason,
}

/// How much more `encryptedMessage` history might exist beyond what's
/// currently loaded, tracked independently per side of the conversation
/// since `mine`/`theirs` are two unrelated queries that can run out at
/// different points. `Some(created_at)` means "there may be more before
/// this timestamp on this side — use it as the next page's exclusive
/// `before` cursor"; `None` means that side is fully loaded, nothing more to
/// fetch. See [`load_more_history`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryCursor {
    pub mine_before: Option<u64>,
    pub their_before: Option<u64>,
}

impl HistoryCursor {
    pub fn has_more(&self) -> bool {
        self.mine_before.is_some() || self.their_before.is_some()
    }
}

/// [`load_thread`]/[`load_more_history`]'s result: the real thread (never
/// includes `PaymentRequestReceipt` entries — those are never shown as
/// bubbles) plus any receipts whose original request no longer checks out.
#[derive(Debug, Clone)]
pub struct LoadedThread {
    /// Every decoded document currently held, both sides, receipts
    /// included — not rendered directly, but round-tripped back into
    /// [`load_more_history`] so a later page can be merged in and
    /// [`ReceiptAlert`] detection re-run over the complete accumulated set.
    /// A receipt's original `PaymentRequest` may live further back than
    /// what's loaded at any given point, so that detection can only be
    /// trusted once it sees everything fetched so far, not just the newest
    /// page.
    pub all_decoded: Vec<ThreadMessage>,
    pub messages: Vec<ThreadMessage>,
    pub receipt_alerts: Vec<ReceiptAlert>,
    pub history_cursor: HistoryCursor,
}

/// Build a synthetic `IdentityPublicKey` wrapping raw ECDH public key bytes
/// cached on [`OrchardPayContactState::Established`]. Only
/// `.key_type()`/`.data()` are ever read from this by
/// `compute_shared_secret_from_key` — every other field is a placeholder,
/// never transmitted or compared against real Platform state.
fn synthetic_ecdh_public_key(bytes: &[u8], purpose: Purpose) -> IdentityPublicKey {
    IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: 0,
        purpose,
        security_level: SecurityLevel::MEDIUM,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: false,
        data: bytes.to_vec().into(),
        disabled_at: None,
    })
}

/// The subset of [`OrchardPayContactState::Established`] messaging needs:
/// both ReferenceIDs (to tag outbound documents / query inbound ones) and
/// the counterparty's cached ECDH pubkeys (to derive both directional
/// secrets with no network call).
struct EstablishedRelationship {
    my_reference_id: [u8; 32],
    their_reference_id: [u8; 32],
    counterparty_encryption_pubkey: Vec<u8>,
    counterparty_decryption_pubkey: Vec<u8>,
}

/// Resolve `counterparty_identity_id`'s `Established` local contact state
/// for `owner_id`, or a typed error if no relationship exists yet or the
/// handshake with them hasn't completed.
fn established_state(
    backend: &crate::wallet_backend::WalletBackend,
    owner_id: Identifier,
    counterparty_identity_id: Identifier,
) -> Result<EstablishedRelationship, TaskError> {
    match backend.orchardpay_get_contact_state(&owner_id, &counterparty_identity_id)? {
        Some(OrchardPayContactState::Established {
            my_reference_id,
            their_reference_id,
            counterparty_encryption_pubkey,
            counterparty_decryption_pubkey,
            ..
        }) => Ok(EstablishedRelationship {
            my_reference_id,
            their_reference_id,
            counterparty_encryption_pubkey,
            counterparty_decryption_pubkey,
        }),
        _ => Err(OrchardPayError::ContactNotEstablished.into()),
    }
}

/// The ECDH secret for messages I *send* to `counterparty_identity_id`
/// (tagged with my own `refId`): my ENCRYPTION key + their cached
/// DECRYPTION pubkey.
async fn outbound_shared_secret(
    app_context: &Arc<AppContext>,
    qualified_identity: &QualifiedIdentity,
    orchardpay_contract_id: Identifier,
    counterparty_decryption_pubkey: &[u8],
    seed_hash: WalletSeedHash,
) -> Result<zeroize::Zeroizing<[u8; 32]>, TaskError> {
    let my_encryption_key = own_bounds_verified_key(
        qualified_identity,
        orchardpay_contract_id,
        Purpose::ENCRYPTION,
    )
    .ok_or(OrchardPayError::OwnKeyMissing)?;
    let counterparty_key =
        synthetic_ecdh_public_key(counterparty_decryption_pubkey, Purpose::DECRYPTION);
    compute_shared_secret_from_key(
        app_context,
        qualified_identity,
        &my_encryption_key,
        &counterparty_key,
        seed_hash,
    )
    .await
}

/// The ECDH secret for messages the counterparty *sent me* (tagged with
/// their `refId`): my DECRYPTION key + their cached ENCRYPTION pubkey.
async fn inbound_shared_secret(
    app_context: &Arc<AppContext>,
    qualified_identity: &QualifiedIdentity,
    orchardpay_contract_id: Identifier,
    counterparty_encryption_pubkey: &[u8],
    seed_hash: WalletSeedHash,
) -> Result<zeroize::Zeroizing<[u8; 32]>, TaskError> {
    let my_decryption_key = own_bounds_verified_key(
        qualified_identity,
        orchardpay_contract_id,
        Purpose::DECRYPTION,
    )
    .ok_or(OrchardPayError::OwnKeyMissing)?;
    let counterparty_key =
        synthetic_ecdh_public_key(counterparty_encryption_pubkey, Purpose::ENCRYPTION);
    compute_shared_secret_from_key(
        app_context,
        qualified_identity,
        &my_decryption_key,
        &counterparty_key,
        seed_hash,
    )
    .await
}

/// Broadcast `msg_data` as a new `encryptedMessage` document tagged
/// `refId`, returning the generic broadcast result and the new document's
/// own ID (needed by [`send_payment`] to correlate its on-chain memo).
#[allow(clippy::too_many_arguments)]
async fn broadcast_encrypted_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    orchardpay_contract: &Arc<DataContract>,
    owner_id: Identifier,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    ref_id: [u8; 32],
    msg_data: Vec<u8>,
) -> Result<(BackendTaskSuccessResult, Identifier), TaskError> {
    let document_type = orchardpay_contract
        .document_type_cloned_for_name(ENCRYPTED_MESSAGE_DOCUMENT_TYPE)
        .expect(
            "encryptedMessage document type is part of the checked-in OrchardPay contract schema",
        );

    let mut rng = StdRng::from_entropy();
    let entropy = Bytes32::random_with_rng(&mut rng);
    let document_id = DppDocument::generate_document_id_v0(
        &orchardpay_contract.id(),
        &owner_id,
        ENCRYPTED_MESSAGE_DOCUMENT_TYPE,
        entropy.as_slice(),
    );

    let mut properties = BTreeMap::new();
    properties.insert(REF_ID_FIELD.to_string(), Value::Bytes(ref_id.to_vec()));
    properties.insert(MSG_DATA_FIELD.to_string(), Value::Bytes(msg_data));
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
        data_contract: orchardpay_contract.clone(),
        qualified_identity,
        identity_key,
    };
    let result = app_context.run_document_task(task, sdk).await?;
    Ok((result, document_id))
}

/// Extract the raw encrypted `msgData` bytes from a fetched document.
fn extract_msg_data(document: &Document) -> Result<Vec<u8>, TaskError> {
    match document.properties().get(MSG_DATA_FIELD) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => {
            Err(OrchardPayError::Crypto(super::encryption::OrchardPayCryptoError::Malformed).into())
        }
    }
}

/// Fetch `document_id`, bump its revision, and decrypt its current content
/// under `shared_secret` — the peek step every edit/cancel flow needs
/// before deciding what to replace it with (preserving an immutable field,
/// checking the existing content kind, or checking for a prior cancel).
async fn fetch_and_decrypt_own_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    orchardpay_contract: &Arc<DataContract>,
    document_id: Identifier,
    shared_secret: &[u8; 32],
) -> Result<(Document, MessageContent), TaskError> {
    let document_type = orchardpay_contract
        .document_type_cloned_for_name(ENCRYPTED_MESSAGE_DOCUMENT_TYPE)
        .expect(
            "encryptedMessage document type is part of the checked-in OrchardPay contract schema",
        );
    let document = app_context
        .fetch_document_for_mutation(
            sdk,
            orchardpay_contract.clone(),
            &document_type,
            document_id,
        )
        .await?;
    let content = MessageContent::decrypt(shared_secret, &extract_msg_data(&document)?)
        .map_err(OrchardPayError::Crypto)?;
    Ok((document, content))
}

/// Re-encrypt `new_content` under `shared_secret` into `document` (already
/// fetched + revision-bumped by [`fetch_and_decrypt_own_message`]) and
/// submit the replace transition — the edit/cancel counterpart to
/// [`broadcast_encrypted_message`]. Only ever called with a document this
/// identity owns (the outbound key is the same one used to encrypt it at
/// original send time), so no inbound-direction variant exists.
#[allow(clippy::too_many_arguments)]
async fn replace_encrypted_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    orchardpay_contract: &Arc<DataContract>,
    mut document: Document,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    new_content: MessageContent,
    shared_secret: &[u8; 32],
) -> Result<BackendTaskSuccessResult, TaskError> {
    let document_type = orchardpay_contract
        .document_type_cloned_for_name(ENCRYPTED_MESSAGE_DOCUMENT_TYPE)
        .expect(
            "encryptedMessage document type is part of the checked-in OrchardPay contract schema",
        );

    let msg_bytes = new_content
        .encrypt(shared_secret)
        .map_err(OrchardPayError::Crypto)?;
    document.set(MSG_DATA_FIELD, Value::Bytes(msg_bytes));

    let task = DocumentTask::ReplaceDocument {
        document,
        document_type,
        data_contract: orchardpay_contract.clone(),
        qualified_identity,
        identity_key,
        token_payment_info: None,
    };
    app_context.run_document_task(task, sdk).await
}

/// Edit a `Message` I sent — replaces its text in place, preserving the
/// document's own ID and thread position. Advances `$updatedAt`, which the
/// thread view already renders as an "(edited)" tag.
#[allow(clippy::too_many_arguments)]
pub async fn edit_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    document_id: Identifier,
    new_text: String,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    validate_message_text(&new_text)
        .map_err(|source| TaskError::OrchardPayMessageTooLong { source })?;

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;

    let (document, existing_content) = fetch_and_decrypt_own_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document_id,
        &shared_secret,
    )
    .await?;
    if !matches!(existing_content, MessageContent::Message { .. }) {
        return Err(TaskError::OrchardPayEditTargetMismatch);
    }

    replace_encrypted_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document,
        qualified_identity,
        identity_key,
        MessageContent::Message { data: new_text },
        &shared_secret,
    )
    .await
}

/// Delete a `Message` I sent — a true Platform document delete (the schema
/// is `canBeDeleted: true`), not a soft-delete/tombstone: once this
/// succeeds, the document is gone and disappears from both parties' thread
/// on their next reload, with no trace left behind. Only ever offered for
/// `Message` content — `Payment`/`PaymentRequest` documents are never
/// deleted, only cancelled (see `cancel_payment_request`).
pub async fn delete_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    document_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;

    let (_document, existing_content) = fetch_and_decrypt_own_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document_id,
        &shared_secret,
    )
    .await?;
    if !matches!(existing_content, MessageContent::Message { .. }) {
        return Err(TaskError::OrchardPayDeleteTargetMismatch);
    }

    let document_type = orchardpay_contract
        .document_type_cloned_for_name(ENCRYPTED_MESSAGE_DOCUMENT_TYPE)
        .expect(
            "encryptedMessage document type is part of the checked-in OrchardPay contract schema",
        );
    let task = DocumentTask::DeleteDocument {
        document_id,
        document_type,
        data_contract: orchardpay_contract.clone(),
        qualified_identity,
        identity_key,
        token_payment_info: None,
    };
    app_context.run_document_task(task, sdk).await
}

/// Edit a `Payment`'s memo — the amount is never touched, since it's
/// sourced from the shielded transfer, not the message; the original
/// decrypted amount is always reused verbatim regardless of caller input
/// (the task itself carries no `amount` field, so there's no path for a
/// tampered amount to reach this function).
#[allow(clippy::too_many_arguments)]
pub async fn edit_payment_memo(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    document_id: Identifier,
    new_memo: Option<String>,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    if let Some(memo) = &new_memo {
        validate_payment_memo(memo)
            .map_err(|source| TaskError::OrchardPayMemoTooLong { source })?;
    }

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;

    let (document, existing_content) = fetch_and_decrypt_own_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document_id,
        &shared_secret,
    )
    .await?;
    let MessageContent::Payment { amount, .. } = existing_content else {
        return Err(TaskError::OrchardPayEditTargetMismatch);
    };

    replace_encrypted_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document,
        qualified_identity,
        identity_key,
        MessageContent::Payment {
            amount,
            memo: new_memo,
        },
        &shared_secret,
    )
    .await
}

/// Cancel a `PaymentRequest` I created — never deletes it. Prepends
/// `"CANCELED: "` to its memo (or sets it to `"CANCELED"` if it had none)
/// and replaces the document, which advances `$updatedAt` past
/// `$createdAt`. Since a `PaymentRequest`'s amount/memo are never editable
/// through any other path, that mismatch is this content kind's
/// unambiguous, un-spoofable "cancelled" signal — see
/// `docs/orchardpay/PROTOCOL_DESIGN.md` and the thread UI's status match.
pub async fn cancel_payment_request(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    document_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;

    let (document, existing_content) = fetch_and_decrypt_own_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document_id,
        &shared_secret,
    )
    .await?;
    if document.created_at() != document.updated_at() {
        return Err(TaskError::OrchardPayRequestAlreadyCancelled);
    }
    let MessageContent::PaymentRequest { amount, memo } = existing_content else {
        return Err(TaskError::OrchardPayEditTargetMismatch);
    };
    let cancelled_memo = match memo {
        Some(memo) => format!("CANCELED: {memo}"),
        None => "CANCELED".to_string(),
    };

    replace_encrypted_message(
        app_context,
        sdk,
        &orchardpay_contract,
        document,
        qualified_identity,
        identity_key,
        MessageContent::PaymentRequest {
            amount,
            memo: Some(cancelled_memo),
        },
        &shared_secret,
    )
    .await
}

/// Send a plain-text `Message` to an established contact.
pub async fn send_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    text: String,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    validate_message_text(&text)
        .map_err(|source| TaskError::OrchardPayMessageTooLong { source })?;

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;
    let msg_bytes = MessageContent::Message { data: text }
        .encrypt(&shared_secret)
        .map_err(OrchardPayError::Crypto)?;

    let (result, _document_id) = broadcast_encrypted_message(
        app_context,
        sdk,
        &orchardpay_contract,
        owner_id,
        qualified_identity,
        identity_key,
        my_reference_id,
        msg_bytes,
    )
    .await?;
    Ok(result)
}

/// Send a `PaymentRequest` to an established contact. No transfer
/// accompanies this — a pure document, like [`send_message`].
#[allow(clippy::too_many_arguments)]
pub async fn send_payment_request(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    amount: u64,
    memo: Option<String>,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    if let Some(memo) = &memo {
        validate_payment_memo(memo)
            .map_err(|source| TaskError::OrchardPayMemoTooLong { source })?;
    }

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;
    let msg_bytes = MessageContent::PaymentRequest { amount, memo }
        .encrypt(&shared_secret)
        .map_err(OrchardPayError::Crypto)?;

    let (result, _document_id) = broadcast_encrypted_message(
        app_context,
        sdk,
        &orchardpay_contract,
        owner_id,
        qualified_identity,
        identity_key,
        my_reference_id,
        msg_bytes,
    )
    .await?;
    Ok(result)
}

/// Send a real payment to an established contact — either unprompted (a
/// fresh `Payment` document is broadcast, then the transfer's memo
/// correlates to it) or answering an outstanding `PaymentRequest`
/// (`fulfilling_request_document_id`: a bare transfer memo'd directly to
/// the request's own ID, no new document). See the protocol doc's
/// "Correlating a real payment to its `encryptedMessage`" for both paths.
#[allow(clippy::too_many_arguments)]
pub async fn send_payment(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
    amount: u64,
    memo: Option<String>,
    fulfilling_request_document_id: Option<Identifier>,
    save_receipt: bool,
    original_request_memo: Option<String>,
    original_request_created_at: Option<u64>,
) -> Result<BackendTaskSuccessResult, TaskError> {
    if let Some(memo) = &memo {
        validate_payment_memo(memo)
            .map_err(|source| TaskError::OrchardPayMemoTooLong { source })?;
    }

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let memo_target_document_id = match fulfilling_request_document_id {
        Some(request_document_id) => {
            if save_receipt {
                // Required, not best-effort: broadcast the receipt *before*
                // the real transfer, and propagate any failure via `?` so
                // `shielded_transfer` below is never reached — a payer who
                // asked for a receipt must never have funds sent with no
                // record, per the feature's design.
                let shared_secret = outbound_shared_secret(
                    app_context,
                    &qualified_identity,
                    orchardpay_contract.id(),
                    &dec_pk,
                    seed_hash,
                )
                .await?;
                let receipt_bytes = MessageContent::PaymentRequestReceipt {
                    original_document_id: request_document_id.to_buffer(),
                    amount,
                    memo: original_request_memo.clone(),
                    original_created_at: original_request_created_at,
                }
                .encrypt(&shared_secret)
                .map_err(OrchardPayError::Crypto)?;

                broadcast_encrypted_message(
                    app_context,
                    sdk,
                    &orchardpay_contract,
                    owner_id,
                    qualified_identity.clone(),
                    identity_key,
                    my_reference_id,
                    receipt_bytes,
                )
                .await
                .map_err(|source| TaskError::OrchardPayReceiptSaveFailed {
                    source: Box::new(source),
                })?;
            }
            request_document_id
        }
        None => {
            let shared_secret = outbound_shared_secret(
                app_context,
                &qualified_identity,
                orchardpay_contract.id(),
                &dec_pk,
                seed_hash,
            )
            .await?;
            let msg_bytes = MessageContent::Payment {
                amount,
                memo: memo.clone(),
            }
            .encrypt(&shared_secret)
            .map_err(OrchardPayError::Crypto)?;

            let (_result, document_id) = broadcast_encrypted_message(
                app_context,
                sdk,
                &orchardpay_contract,
                owner_id,
                qualified_identity.clone(),
                identity_key,
                my_reference_id,
                msg_bytes,
            )
            .await?;
            document_id
        }
    };

    let mut transfer_memo = [0u8; 36];
    transfer_memo[..4].copy_from_slice(&MEMO_TAG_PAYMENT);
    transfer_memo[4..].copy_from_slice(&memo_target_document_id.to_buffer());

    backend
        .shielded_transfer(
            &seed_hash,
            0,
            &counterparty_shielded_address,
            amount,
            transfer_memo,
        )
        .await?;

    if fulfilling_request_document_id.is_some() {
        // Optimistic local "paid" record so this wallet's own copy of the
        // PaymentRequest bubble flips to Paid and hides its "Pay" button
        // immediately — without waiting on a shielded sync/OVK-recovery
        // pass to notice the note we just sent (which, for the payer, may
        // never happen locally at all: a payer never receives a transfer
        // for its own outgoing payment, unlike the requester's own
        // incoming-memo scan, which writes this same cache entry from the
        // other direction). Reuses `orchardpay_get/set_verified_payment_amount`
        // rather than a payer-specific key: the value is exactly what that
        // cache already means ("the real credits value confirmed for this
        // document"), and I know it with certainty here since I chose it
        // myself. If this local write is ever lost (reinstall, new
        // device), `orchardpay_outgoing_payments_by_document` reconstructs
        // the same answer straight from chain data as a fallback — see
        // `decode_thread_message`.
        if let Err(e) = backend.orchardpay_set_verified_payment_amount(
            &seed_hash,
            &memo_target_document_id,
            amount,
        ) {
            tracing::warn!(
                document = %memo_target_document_id,
                error = ?e,
                "OrchardPay: payment broadcast succeeded but failed to record the local paid \
                 marker; still recoverable from this wallet's own outgoing notes"
            );
        }
    }

    Ok(BackendTaskSuccessResult::OrchardPayPaymentSent {
        counterparty_identity_id,
        amount,
    })
}

/// One page of [`fetch_messages_by_ref_id`]'s results.
struct MessagePage {
    /// Owner-filtered documents, ready to decode.
    documents: Vec<Document>,
    /// Whether the *raw* (pre-owner-filter) batch was a full page — i.e.
    /// older documents on this side may still exist. Deliberately not based
    /// on `documents.len()`: a counterparty flooding decoys under their own
    /// `$ownerId` could otherwise make a genuinely-full raw page look
    /// partial once filtered, hiding real older history behind a "load
    /// more" button that never appears.
    has_more: bool,
    /// The oldest `$createdAt` seen in the *raw* batch — the next page's
    /// `before` cursor. `None` only when the raw batch was empty.
    oldest_created_at: Option<u64>,
}

/// Fetch one page of `encryptedMessage` documents tagged `ref_id`, via the
/// contract's `byReferenceIdAndCreated` index, newest-first, then filter to
/// only those actually owned by `expected_owner`.
///
/// `refId` alone does not prove who wrote a document: it's a value the
/// counterparty legitimately knows too (it's their own `their_reference_id`),
/// and Platform lets any identity write any `refId` value into a document
/// they own. Without this check, a malicious counterparty could broadcast a
/// decoy document under their own `$ownerId` but tagged with the other
/// party's `refId`; it would decrypt successfully (the ECDH secret for a
/// given direction is computable by both parties by construction) and be
/// silently trusted as if it came from the expected sender. `$ownerId` is
/// the one field here Platform's own signature verification actually
/// guarantees is truthful, so checking it is the correct fix — done
/// client-side, before decryption, since no compound index covers
/// `(refId, $ownerId)` together (only `byReferenceIdAndCreated` and
/// `byOwnerIdAndCreated` exist), so this can't be pushed into the query
/// itself without a contract migration.
///
/// `before` is an exclusive upper bound on `$createdAt` — `None` means "now"
/// (the first/newest page). The `$createdAt < before` range clause is
/// required, not decorative: Drive only reads an `order_by`'s direction from
/// the clause it picks to drive iteration, and that clause defaults to
/// whichever `WhereClause` is an equality match (here, `refId`) when nothing
/// else qualifies — equality clauses always iterate ascending, silently
/// ignoring `order_by`. Adding a *range* clause on the same field the
/// `order_by` targets makes Drive pick that as the deciding clause instead,
/// whose direction genuinely comes from `order_by` (see `rs-drive`'s
/// `get_non_primary_key_path_query`). Without this, a naive limited fetch
/// would silently return the *oldest* [`MESSAGE_PAGE_SIZE`] messages, not the
/// newest — exactly backwards for a conversation view.
async fn fetch_messages_by_ref_id(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    ref_id: [u8; 32],
    expected_owner: Identifier,
    before: Option<u64>,
) -> Result<MessagePage, TaskError> {
    let upper_bound = before.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    });

    let mut query =
        DocumentQuery::new(orchardpay_contract.clone(), ENCRYPTED_MESSAGE_DOCUMENT_TYPE).map_err(
            |e| OrchardPayError::QueryCreation {
                query_target: "encryptedMessage thread fetch",
                source: Box::new(e),
            },
        )?;
    query = query
        .with_where(WhereClause {
            field: REF_ID_FIELD.to_string(),
            operator: WhereOperator::Equal,
            value: Value::Bytes(ref_id.to_vec()),
        })
        .with_where(WhereClause {
            field: CREATED_AT_FIELD.to_string(),
            operator: WhereOperator::LessThan,
            value: Value::U64(upper_bound),
        })
        .with_order_by(OrderClause {
            field: CREATED_AT_FIELD.to_string(),
            ascending: false,
        });
    query.limit = MESSAGE_PAGE_SIZE;

    let results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    let raw: Vec<Document> = results.into_values().flatten().collect();
    let has_more = raw.len() as u32 >= MESSAGE_PAGE_SIZE;
    let oldest_created_at = raw
        .iter()
        .filter_map(|document| document.created_at())
        .min();
    let documents = raw
        .into_iter()
        .filter(|document| document.owner_id() == expected_owner)
        .collect();

    Ok(MessagePage {
        documents,
        has_more,
        oldest_created_at,
    })
}

/// Latest `encryptedMessage` document's `$createdAt` tagged `ref_id` and
/// actually owned by `expected_owner`, via the same `byReferenceIdAndCreated`
/// index as [`fetch_messages_by_ref_id`], sorted descending — for "when did
/// this side of the conversation last say anything" without fetching the
/// whole thread.
///
/// Fetches more than one candidate ([`RECENT_ACTIVITY_FETCH_LIMIT`]) and
/// filters by `expected_owner` client-side, for the same reason
/// [`fetch_messages_by_ref_id`] does: `refId` alone doesn't prove who wrote
/// a document. A `limit = 1` fetch filtered afterward would let a single
/// decoy document (wrong owner, deliberately recent `$createdAt`) hide the
/// real latest activity behind it indefinitely — fetching a small batch and
/// taking the first owner-matching hit is cheap insurance against that.
///
/// The `$createdAt < now` range clause is required, not decorative: Drive
/// only reads an `order_by`'s direction from the clause it picks to drive
/// iteration, and that clause defaults to whichever `WhereClause` is an
/// equality match (here, `refId`) when nothing else qualifies — equality
/// clauses always iterate ascending, silently ignoring `order_by`. Adding
/// a *range* clause on the same field the `order_by` targets makes Drive
/// pick that as the deciding clause instead, whose direction genuinely
/// comes from `order_by` (see `rs-drive`'s `get_non_primary_key_path_query`).
/// Without this, a naive limited fetch would silently return the *oldest*
/// messages, not the newest.
async fn fetch_latest_message_created_at(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    ref_id: [u8; 32],
    expected_owner: Identifier,
) -> Result<Option<u64>, TaskError> {
    /// Candidates fetched per side before filtering by owner — comfortably
    /// more than the handful of decoys a griefing counterparty would
    /// realistically bother paying to create, without fetching the whole
    /// thread just to find the one real latest message.
    const RECENT_ACTIVITY_FETCH_LIMIT: u32 = 10;

    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut query =
        DocumentQuery::new(orchardpay_contract.clone(), ENCRYPTED_MESSAGE_DOCUMENT_TYPE).map_err(
            |e| OrchardPayError::QueryCreation {
                query_target: "encryptedMessage latest-activity fetch",
                source: Box::new(e),
            },
        )?;
    query = query
        .with_where(WhereClause {
            field: REF_ID_FIELD.to_string(),
            operator: WhereOperator::Equal,
            value: Value::Bytes(ref_id.to_vec()),
        })
        .with_where(WhereClause {
            field: CREATED_AT_FIELD.to_string(),
            operator: WhereOperator::LessThan,
            value: Value::U64(now_millis),
        })
        .with_order_by(OrderClause {
            field: CREATED_AT_FIELD.to_string(),
            ascending: false,
        });
    query.limit = RECENT_ACTIVITY_FETCH_LIMIT;

    let results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    Ok(results
        .into_values()
        .flatten()
        .find(|document| document.owner_id() == expected_owner)
        .and_then(|document| document.created_at()))
}

/// One established contact's most-recent-activity summary, used by the
/// "Most Recent" navigation view to order conversations by freshness
/// instead of contact-request order. See [`fetch_recent_activity`].
#[derive(Debug, Clone)]
pub struct RecentContactActivity {
    pub identity_id: Identifier,
    /// The sort key: the latest message timestamp if any messages have
    /// been exchanged, otherwise the `contactAnchor`'s own `$createdAt`
    /// (when the relationship was established) as a fallback, so contacts
    /// with no conversation yet still sort somewhere meaningful.
    pub last_activity: Option<u64>,
    /// `false` means `last_activity` (if `Some`) is the anchor-date
    /// fallback, not a real message timestamp — the UI shows "No messages
    /// yet" instead of a "last activity" label in that case.
    pub has_messages: bool,
}

/// The subset of an established contact's state [`fetch_recent_activity`]
/// needs: both directional reference IDs (to query each side's latest
/// message) and the anchor's own timestamp (the no-messages-yet fallback).
struct EstablishedContactRefs {
    identity_id: Identifier,
    my_reference_id: [u8; 32],
    their_reference_id: [u8; 32],
    anchor_created_at: Option<u64>,
}

/// Build the "Most Recent" ordering: every established contact, sorted by
/// their conversation's latest activity (newest first), with contacts that
/// have no messages yet sorted after those that do, by connection date.
/// One query pair per contact (their sent side + my sent side), run
/// concurrently — there is no single index that covers "most recent across
/// all my relationships" in the current `encryptedMessage` schema
/// (`byReferenceIdAndCreated` is scoped to one `refId` at a time), so this
/// is inherently O(contacts) network calls, computed on-demand rather than
/// cached. A per-contact query failure is treated as "no messages found"
/// rather than failing the whole view, mirroring `recover_own_anchors`'s
/// best-effort handling of individual anchors.
pub async fn fetch_recent_activity(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;

    let contacts = backend.orchardpay_list_contacts(&owner_id)?;
    let established: Vec<EstablishedContactRefs> = contacts
        .into_iter()
        .filter_map(|counterparty| {
            match backend
                .orchardpay_get_contact_state(&owner_id, &counterparty)
                .ok()?
            {
                Some(OrchardPayContactState::Established {
                    my_reference_id,
                    their_reference_id,
                    created_at,
                    ..
                }) => Some(EstablishedContactRefs {
                    identity_id: counterparty,
                    my_reference_id,
                    their_reference_id,
                    anchor_created_at: created_at,
                }),
                _ => None,
            }
        })
        .collect();

    let contract_ref = &orchardpay_contract;
    let futures = established.into_iter().map(move |contact| async move {
        let (mine, theirs) = futures::future::join(
            fetch_latest_message_created_at(contract_ref, sdk, contact.my_reference_id, owner_id),
            fetch_latest_message_created_at(
                contract_ref,
                sdk,
                contact.their_reference_id,
                contact.identity_id,
            ),
        )
        .await;
        let latest_message = mine
            .ok()
            .flatten()
            .into_iter()
            .chain(theirs.ok().flatten())
            .max();
        match latest_message {
            Some(ts) => RecentContactActivity {
                identity_id: contact.identity_id,
                last_activity: Some(ts),
                has_messages: true,
            },
            None => RecentContactActivity {
                identity_id: contact.identity_id,
                last_activity: contact.anchor_created_at,
                has_messages: false,
            },
        }
    });

    let mut entries: Vec<RecentContactActivity> = join_all(futures).await;
    entries.sort_by(|a, b| {
        b.has_messages
            .cmp(&a.has_messages)
            .then(b.last_activity.cmp(&a.last_activity))
    });

    Ok(BackendTaskSuccessResult::OrchardPayRecentActivity(entries))
}

fn decode_thread_message(
    backend: &crate::wallet_backend::WalletBackend,
    seed_hash: &WalletSeedHash,
    document: &Document,
    from_me: bool,
    shared_secret: &[u8; 32],
    outgoing_payments: &BTreeMap<Identifier, u64>,
    incoming_payments: &BTreeMap<Identifier, u64>,
) -> Option<ThreadMessage> {
    let msg_bytes = match document.properties().get(MSG_DATA_FIELD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        _ => return None,
    };
    let content = MessageContent::decrypt(shared_secret, msg_bytes).ok()?;

    let verified_amount = match &content {
        // The k/v cache is the fast path, written by the incoming-memo
        // scan (the other side received a fulfillment/payment) or
        // `send_payment`'s own optimistic post-send record (only written
        // when fulfilling a request — a freeform `Payment` never gets that
        // write) — but both of those can lag or be lost: the scan runs on
        // its own resumable cursor independent of the wallet's normal
        // sync, and the payer's local write doesn't survive a reinstall.
        // `outgoing_payments`/`incoming_payments` reconstruct the same fact
        // straight from this wallet's already-synced notes — keyed by
        // whatever document ID the transfer's memo names, which for a
        // freeform `Payment` is its own document ID (see `send_payment`'s
        // `memo_target_document_id`), not just a fulfilled request's — so
        // a `Payment`/`PaymentRequest`'s status here is never less current
        // than what the Shielded TXs tab already shows for the same note.
        MessageContent::Payment { .. } | MessageContent::PaymentRequest { .. } => backend
            .orchardpay_get_verified_payment_amount(seed_hash, &document.id())
            .ok()
            .flatten()
            .or_else(|| outgoing_payments.get(&document.id()).copied())
            .or_else(|| incoming_payments.get(&document.id()).copied()),
        MessageContent::Message { .. } => None,
        // A receipt is never itself "paid" — it's a payer's private record
        // of a request they already paid, not a payable thing on its own.
        MessageContent::PaymentRequestReceipt { .. } => None,
    };

    Some(ThreadMessage {
        document_id: document.id(),
        from_me,
        created_at: document.created_at(),
        updated_at: document.updated_at(),
        content,
        verified_amount,
    })
}

/// Reconstruct the full two-way thread with `counterparty_identity_id`:
/// documents I sent (tagged with my own `refId`) union documents they sent
/// (tagged with their `refId`, learned from my own anchor's `anchorData`),
/// each decrypted with the matching directional secret, sorted by
/// `$createdAt`.
pub async fn load_thread(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<LoadedThread, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        their_reference_id,
        counterparty_encryption_pubkey: enc_pk,
        counterparty_decryption_pubkey: dec_pk,
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let outbound_secret = outbound_shared_secret(
        app_context,
        qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;
    let inbound_secret = inbound_shared_secret(
        app_context,
        qualified_identity,
        orchardpay_contract.id(),
        &enc_pk,
        seed_hash,
    )
    .await?;

    let mine_page =
        fetch_messages_by_ref_id(&orchardpay_contract, sdk, my_reference_id, owner_id, None)
            .await?;
    let their_page = fetch_messages_by_ref_id(
        &orchardpay_contract,
        sdk,
        their_reference_id,
        counterparty_identity_id,
        None,
    )
    .await?;
    let outgoing_payments = backend
        .orchardpay_outgoing_payments_by_document(&seed_hash)
        .await?;
    let incoming_payments = backend
        .orchardpay_incoming_payments_by_document(sdk, &seed_hash)
        .await?;

    let mut all_decoded =
        Vec::with_capacity(mine_page.documents.len() + their_page.documents.len());
    decode_page(
        &backend,
        &seed_hash,
        &mine_page.documents,
        true,
        &outbound_secret,
        &outgoing_payments,
        &incoming_payments,
        &mut all_decoded,
    );
    decode_page(
        &backend,
        &seed_hash,
        &their_page.documents,
        false,
        &inbound_secret,
        &outgoing_payments,
        &incoming_payments,
        &mut all_decoded,
    );

    let history_cursor = HistoryCursor {
        mine_before: mine_page
            .has_more
            .then_some(mine_page.oldest_created_at)
            .flatten(),
        their_before: their_page
            .has_more
            .then_some(their_page.oldest_created_at)
            .flatten(),
    };
    let (messages, receipt_alerts) = assemble_thread(&all_decoded, &history_cursor);

    Ok(LoadedThread {
        all_decoded,
        messages,
        receipt_alerts,
        history_cursor,
    })
}

/// Decode a fetched page's documents into `out`, one directional secret at a
/// time — the shared per-page body of both [`load_thread`] and
/// [`load_more_history`].
#[allow(clippy::too_many_arguments)]
fn decode_page(
    backend: &crate::wallet_backend::WalletBackend,
    seed_hash: &WalletSeedHash,
    documents: &[Document],
    from_me: bool,
    shared_secret: &[u8; 32],
    outgoing_payments: &BTreeMap<Identifier, u64>,
    incoming_payments: &BTreeMap<Identifier, u64>,
    out: &mut Vec<ThreadMessage>,
) {
    for document in documents {
        if let Some(message) = decode_thread_message(
            backend,
            seed_hash,
            document,
            from_me,
            shared_secret,
            outgoing_payments,
            incoming_payments,
        ) {
            out.push(message);
        }
    }
}

/// Split a decoded, accumulated batch of `encryptedMessage` documents (both
/// sides, receipts included) into the chronological message list plus any
/// [`ReceiptAlert`]s — shared by [`load_thread`] and [`load_more_history`],
/// which both need to re-run this over the *complete* set held so far, not
/// just whatever page was just fetched.
///
/// `OriginalDeleted` is only ever raised once `cursor` reports both sides
/// fully loaded (`!cursor.has_more()`): a receipt's original `PaymentRequest`
/// can live on either side of the conversation (the requester sent it, the
/// payer sent the receipt) and further back than what's paged in so far, so
/// "not found yet" must not be conflated with "genuinely deleted" while more
/// history could still surface it.
fn assemble_thread(
    all_decoded: &[ThreadMessage],
    cursor: &HistoryCursor,
) -> (Vec<ThreadMessage>, Vec<ReceiptAlert>) {
    // Receipts ride along in the same fetches (tagged with the same `refId`
    // as everything else) but are never shown as normal bubbles — split
    // them out, then use each to check whether the `PaymentRequest` it
    // refers to still matches what was paid.
    let (receipts, mut messages): (Vec<ThreadMessage>, Vec<ThreadMessage>) =
        all_decoded.iter().cloned().partition(|message| {
            matches!(
                message.content,
                MessageContent::PaymentRequestReceipt { .. }
            )
        });
    messages.sort_by_key(|message| message.created_at.unwrap_or(0));

    let history_fully_loaded = !cursor.has_more();
    let mut receipt_alerts = Vec::new();
    for receipt in &receipts {
        let MessageContent::PaymentRequestReceipt {
            original_document_id,
            amount: receipt_amount,
            memo: receipt_memo,
            original_created_at,
        } = &receipt.content
        else {
            continue;
        };
        let original_document_id = Identifier::from(*original_document_id);

        let reason = match messages
            .iter()
            .find(|message| message.document_id == original_document_id)
        {
            None if history_fully_loaded => Some(ReceiptAlertReason::OriginalDeleted),
            None => None,
            Some(original) => match &original.content {
                MessageContent::PaymentRequest { amount, memo } => {
                    // Legitimate cancellation (`cancel_payment_request`'s
                    // "CANCELED: " prefix) is signaled the same way the
                    // bubble itself already detects it — not an anomaly.
                    let is_cancelled =
                        original.updated_at.is_some() && original.updated_at != original.created_at;
                    if is_cancelled {
                        None
                    } else if amount != receipt_amount || memo != receipt_memo {
                        Some(ReceiptAlertReason::OriginalAmountOrMemoMismatch)
                    } else {
                        None
                    }
                }
                _ => Some(ReceiptAlertReason::OriginalChangedKind),
            },
        };

        if let Some(reason) = reason {
            receipt_alerts.push(ReceiptAlert {
                original_document_id,
                amount: *receipt_amount,
                memo: receipt_memo.clone(),
                original_created_at: *original_created_at,
                reason,
            });
        }
    }

    (messages, receipt_alerts)
}

/// Fetch the next older page of history for whichever side(s) of
/// `history_cursor` still report more (`Some`), merge it into
/// `all_decoded` (everything already loaded, both sides, receipts
/// included — round-tripped from the previous [`load_thread`]/
/// [`load_more_history`] result), and re-run [`assemble_thread`] over the
/// complete accumulated set. No document already held is re-fetched; only
/// the new page costs a query, one per side that isn't already exhausted.
pub async fn load_more_history(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
    mut all_decoded: Vec<ThreadMessage>,
    history_cursor: HistoryCursor,
) -> Result<LoadedThread, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        their_reference_id,
        counterparty_encryption_pubkey: enc_pk,
        counterparty_decryption_pubkey: dec_pk,
    } = established_state(&backend, owner_id, counterparty_identity_id)?;

    let outbound_secret = outbound_shared_secret(
        app_context,
        qualified_identity,
        orchardpay_contract.id(),
        &dec_pk,
        seed_hash,
    )
    .await?;
    let inbound_secret = inbound_shared_secret(
        app_context,
        qualified_identity,
        orchardpay_contract.id(),
        &enc_pk,
        seed_hash,
    )
    .await?;
    let outgoing_payments = backend
        .orchardpay_outgoing_payments_by_document(&seed_hash)
        .await?;
    let incoming_payments = backend
        .orchardpay_incoming_payments_by_document(sdk, &seed_hash)
        .await?;

    let mut new_mine_before = None;
    if let Some(before) = history_cursor.mine_before {
        let page = fetch_messages_by_ref_id(
            &orchardpay_contract,
            sdk,
            my_reference_id,
            owner_id,
            Some(before),
        )
        .await?;
        decode_page(
            &backend,
            &seed_hash,
            &page.documents,
            true,
            &outbound_secret,
            &outgoing_payments,
            &incoming_payments,
            &mut all_decoded,
        );
        new_mine_before = page.has_more.then_some(page.oldest_created_at).flatten();
    }

    let mut new_their_before = None;
    if let Some(before) = history_cursor.their_before {
        let page = fetch_messages_by_ref_id(
            &orchardpay_contract,
            sdk,
            their_reference_id,
            counterparty_identity_id,
            Some(before),
        )
        .await?;
        decode_page(
            &backend,
            &seed_hash,
            &page.documents,
            false,
            &inbound_secret,
            &outgoing_payments,
            &incoming_payments,
            &mut all_decoded,
        );
        new_their_before = page.has_more.then_some(page.oldest_created_at).flatten();
    }

    let history_cursor = HistoryCursor {
        mine_before: new_mine_before,
        their_before: new_their_before,
    };
    let (messages, receipt_alerts) = assemble_thread(&all_decoded, &history_cursor);

    Ok(LoadedThread {
        all_decoded,
        messages,
        receipt_alerts,
        history_cursor,
    })
}

/// Called by the incoming-memo scan when it detects a
/// [`MEMO_TAG_PAYMENT`]-tagged transfer: cache the real observed amount for
/// `referenced_document_id` so [`load_thread`] can source it without
/// re-scanning. Fire-and-forget from the scan's perspective — the
/// referenced document may belong to a relationship this wallet's other
/// identities haven't loaded yet; the cache just waits until it's read.
pub fn record_verified_incoming_payment(
    backend: &crate::wallet_backend::WalletBackend,
    seed_hash: &WalletSeedHash,
    referenced_document_id: Identifier,
    received_amount_credits: u64,
) -> Result<(), TaskError> {
    backend.orchardpay_set_verified_payment_amount(
        seed_hash,
        &referenced_document_id,
        received_amount_credits,
    )
}
