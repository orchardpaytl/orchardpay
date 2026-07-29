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
    OrchardPayContactState, PendingOperationStep, PendingOrchardPayOperation,
    validate_message_text, validate_payment_memo, validate_send_amount,
};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::validation::strip_unsafe_display_characters_allow_newlines;
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
    /// Whether some documents may not have made it into `all_decoded` —
    /// either [`trim_ambiguous_tail`]'s pathological fallback fired for a
    /// page on either side, or a document failed to decode. Once true for
    /// this thread, stays true across later [`load_more_history`] calls
    /// (round-tripped like `all_decoded`/`history_cursor`) — a gap already
    /// known doesn't un-happen just because a later page came back clean.
    pub may_be_incomplete: bool,
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
/// for `owner_id` under `contract_id`, or a typed error if no relationship
/// exists yet or the handshake with them hasn't completed.
fn established_state(
    backend: &crate::wallet_backend::WalletBackend,
    contract_id: Identifier,
    owner_id: Identifier,
    counterparty_identity_id: Identifier,
) -> Result<EstablishedRelationship, TaskError> {
    match backend.orchardpay_get_contact_state(
        &contract_id,
        &owner_id,
        &counterparty_identity_id,
    )? {
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

/// Build and broadcast a fresh, unprompted `Payment` document, persisting a
/// local recovery marker *before* the broadcast — see M-02 of
/// `docs/ai-design/2026-07-26-m02-atomic-contact-payment-flows/README.md`.
/// If the subsequent shielded transfer fails, a retry finds the marker
/// (checked by `send_payment` before calling this) and is told to
/// explicitly recover rather than silently publishing a second, orphaned
/// `Payment` document. Only used by `send_payment`'s standalone
/// (non-request-fulfilling) path — every other `encryptedMessage` broadcast
/// (`send_message`, `send_payment_request`, receipts) has no follow-up
/// network side effect, so nothing can be left inconsistent for them.
#[allow(clippy::too_many_arguments)]
async fn broadcast_new_payment_message(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    orchardpay_contract: &Arc<DataContract>,
    owner_id: Identifier,
    counterparty_identity_id: Identifier,
    qualified_identity: QualifiedIdentity,
    identity_key: IdentityPublicKey,
    ref_id: [u8; 32],
    msg_data: Vec<u8>,
) -> Result<(BackendTaskSuccessResult, Identifier), TaskError> {
    let backend = app_context.wallet_backend()?;

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

    // Persist intent *before* the first network side effect — the id is
    // already deterministic at this point, so a retry that finds this
    // marker (see `send_payment`) always refers to the same document.
    backend.orchardpay_set_pending_operation(
        &orchardpay_contract.id(),
        &owner_id,
        &counterparty_identity_id,
        &PendingOrchardPayOperation::Payment {
            document_id: document_id.to_buffer(),
            step: PendingOperationStep::DocumentPublished,
        },
    )?;

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
    let new_text = strip_unsafe_display_characters_allow_newlines(&new_text);
    validate_message_text(&new_text)
        .map_err(|source| TaskError::OrchardPayMessageTooLong { source })?;

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    let new_memo = new_memo.map(|memo| strip_unsafe_display_characters_allow_newlines(&memo));
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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    let text = strip_unsafe_display_characters_allow_newlines(&text);
    validate_message_text(&text)
        .map_err(|source| TaskError::OrchardPayMessageTooLong { source })?;

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        counterparty_decryption_pubkey: dec_pk,
        ..
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    validate_send_amount(amount).map_err(|source| TaskError::OrchardPayAmountTooLow { source })?;
    let memo = memo.map(|memo| strip_unsafe_display_characters_allow_newlines(&memo));
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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    validate_send_amount(amount).map_err(|source| TaskError::OrchardPayAmountTooLow { source })?;
    let memo = memo.map(|memo| strip_unsafe_display_characters_allow_newlines(&memo));
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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
            // M-02: a pending marker here means a previous attempt already
            // published a `Payment` document but its transfer never
            // confirmed — don't silently start a fresh send (which would
            // publish a second, orphaned document); surface a distinct
            // error instead so the caller can decide how to recover.
            if let Some(PendingOrchardPayOperation::Payment { document_id, .. }) = backend
                .orchardpay_get_pending_operation(
                    &orchardpay_contract.id(),
                    &owner_id,
                    &counterparty_identity_id,
                )?
            {
                return Err(TaskError::OrchardPayPaymentRecoveryNeeded {
                    document_id: Identifier::from(document_id),
                });
            }

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

            let (_result, document_id) = broadcast_new_payment_message(
                app_context,
                sdk,
                &orchardpay_contract,
                owner_id,
                counterparty_identity_id,
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

    // Whatever the path above, the operation is now consistent — clear any
    // pending-operation marker (a no-op if the `Some(...)` branch never set
    // one, since it targets an already-durable `PaymentRequest`, not a
    // freshly-created document).
    backend.orchardpay_clear_pending_operation(
        &orchardpay_contract.id(),
        &owner_id,
        &counterparty_identity_id,
    )?;

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
    /// Owner-filtered documents (by the query itself, not client-side),
    /// ready to decode.
    documents: Vec<Document>,
    /// Whether this batch was a full page — i.e. older documents on this
    /// side may still exist.
    has_more: bool,
    /// The next page's `before` cursor — the oldest `$createdAt` among
    /// `documents` *after* [`trim_ambiguous_tail`] has held back any
    /// trailing documents whose timestamp can't yet be trusted as complete,
    /// so this is not always literally the oldest timestamp originally
    /// fetched. `None` only when `documents` ended up empty.
    oldest_created_at: Option<u64>,
    /// Whether [`trim_ambiguous_tail`]'s pathological (entire-page-tied)
    /// fallback fired for this page — see its doc comment. Signals that
    /// some of this side's documents at the boundary timestamp may not
    /// have made it into `documents`.
    may_be_incomplete: bool,
}

/// Fetch one page of `encryptedMessage` documents tagged `ref_id` and
/// actually owned by `expected_owner`, via the contract's
/// `byReferenceIdbyOwnerIdAndCreated` index, newest-first.
///
/// `refId` alone does not prove who wrote a document: it's a value the
/// counterparty legitimately knows too (it's their own `their_reference_id`),
/// and Platform lets any identity write any `refId` value into a document
/// they own. Without an owner check, a malicious counterparty could
/// broadcast a decoy document under their own `$ownerId` but tagged with the
/// other party's `refId`; it would decrypt successfully (the ECDH secret for
/// a given direction is computable by both parties by construction) and be
/// silently trusted as if it came from the expected sender. `$ownerId` is
/// the one field here Platform's own signature verification actually
/// guarantees is truthful, so filtering on it is the correct fix. This is
/// now done in the query itself (an `$ownerId Equal` clause, matching the
/// compound index's declared field order `refId, $ownerId, $createdAt`) —
/// previously this had to be a client-side post-fetch filter, since no
/// index covered `(refId, $ownerId)` together. A forged/wrong-owner
/// document is now never fetched in the first place, so `has_more` no
/// longer needs special handling to defend against a decoy flood skewing
/// it. `oldest_created_at` still does, for an unrelated reason: see
/// [`trim_ambiguous_tail`] for why a same-`$createdAt` collision between
/// two of the *same* owner's own documents needs its own handling.
///
/// `before` is an exclusive upper bound on `$createdAt` — `None` means "now"
/// (the first/newest page). The `$createdAt < before` range clause is
/// required, not decorative: Drive only reads an `order_by`'s direction from
/// the clause it picks to drive iteration, and that clause defaults to
/// whichever `WhereClause` is an equality match (here, `refId`/`$ownerId`)
/// when nothing else qualifies — equality clauses always iterate ascending,
/// silently ignoring `order_by`. Adding a *range* clause on the same field
/// the `order_by` targets makes Drive pick that as the deciding clause
/// instead, whose direction genuinely comes from `order_by` (see
/// `rs-drive`'s `get_non_primary_key_path_query`). Without this, a naive
/// limited fetch would silently return the *oldest* [`MESSAGE_PAGE_SIZE`]
/// messages, not the newest — exactly backwards for a conversation view.
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
            field: "$ownerId".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Identifier(expected_owner.to_buffer()),
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

    let mut documents: Vec<Document> = results.into_values().flatten().collect();
    let has_more = documents.len() as u32 >= MESSAGE_PAGE_SIZE;
    let (oldest_created_at, may_be_incomplete) = trim_ambiguous_tail(&mut documents, has_more);

    Ok(MessagePage {
        documents,
        has_more,
        oldest_created_at,
        may_be_incomplete,
    })
}

/// A full page's oldest `$createdAt` may be shared by more documents than
/// made it into this batch — Platform stamps `$createdAt` from block time
/// (`rs-drive`'s document-creation transformer takes it straight from
/// `BlockInfo`, not a per-document precise clock), so two of the same
/// identity's own documents landing in the same block are stamped
/// identically, and Drive gives no ordering guarantee among same-timestamp
/// rows at a `LIMIT` cutoff. Any tied run *earlier* in the
/// (descending-ordered) batch is guaranteed complete, since the limit would
/// have been hit mid-run if it weren't the last one — but the trailing
/// run at the batch's minimum timestamp can never be trusted, **even when
/// it's currently visible as a single document**: one page's results can't
/// distinguish "this timestamp is genuinely unique" from "this timestamp
/// has siblings that the limit's tie-break ordering happened to place just
/// past the cutoff." Both look identical from here, so both must be
/// treated the same way.
///
/// Trims that trailing run out of `documents` — holding it back rather than
/// showing a possibly-incomplete slice of it — and returns the cursor for
/// the next page: the timestamp of the last *kept* document, i.e. the
/// boundary immediately above the trimmed group. The next page's
/// `$createdAt < cursor` then pulls in the entire trimmed group fresh
/// (everything that shares that timestamp, not just what this page
/// happened to see), so nothing already shown is re-displayed and nothing
/// already-existing is lost. In the common case (the boundary value really
/// is unique) this costs nothing visible: the one deferred document simply
/// arrives as part of the next fetch instead of this one, and both
/// `load_thread`/`load_more_history` re-sort everything by `$createdAt`
/// after merging pages anyway, so it renders in exactly the same place it
/// always would have.
///
/// No trimming happens when `has_more` is `false`: a non-full page means
/// nothing was cut off by the limit, so there's no ambiguity to resolve.
///
/// Pathological fallback: if *every* document in a full page shares the
/// same timestamp (would require [`MESSAGE_PAGE_SIZE`]-or-more documents
/// from one identity landing in one block), there's no safe boundary to
/// trim to without emptying the page while still claiming more exists.
///
/// This is treated as an accepted design tradeoff, not a residual gap to
/// keep chasing: engineering that many same-block documents from one
/// identity costs a rogue contact real Platform fees for a griefing-only
/// outcome (permanently hiding one of *their own* earlier messages from the
/// victim), and OrchardPay's P2P model treats a counterparty behaving this
/// way as a social problem — block/walk away — not something the
/// pagination layer owes a perfect technical defense against. See the
/// 2026-07-27 adversarial audit's finding 2. Falls back to the pre-fix
/// behavior (accept the rare loss risk) rather than risk an infinite loop
/// (an unchanged cursor re-fetching the same page forever) or falsely
/// reporting the thread fully loaded (an empty cursor) — mirrors
/// `recover_own_anchors`'s existing warn-and-accept precedent for its own
/// analogous page-cap edge case. The second return value reports whether
/// this branch fired, so the caller can surface a visible notice instead of
/// only the `tracing::warn!` below.
fn trim_ambiguous_tail(documents: &mut Vec<Document>, has_more: bool) -> (Option<u64>, bool) {
    if !has_more || documents.is_empty() {
        return (documents.iter().filter_map(|d| d.created_at()).min(), false);
    }

    let Some(boundary) = documents.last().and_then(|d| d.created_at()) else {
        return (None, false);
    };

    match documents
        .iter()
        .rposition(|d| d.created_at() != Some(boundary))
    {
        Some(last_distinct_index) => {
            documents.truncate(last_distinct_index + 1);
            (documents.last().and_then(|d| d.created_at()), false)
        }
        None => {
            // Entire page shares one timestamp.
            tracing::warn!(
                boundary,
                page_size = MESSAGE_PAGE_SIZE,
                "OrchardPay: an entire encryptedMessage page shared one $createdAt \
                 (block-time collision) — pagination can't safely trim it; \
                 accepting the rare loss risk for this page rather than stalling"
            );
            (Some(boundary), true)
        }
    }
}

/// Latest `encryptedMessage` document's `$createdAt` tagged `ref_id` and
/// actually owned by `expected_owner`, via the same
/// `byReferenceIdbyOwnerIdAndCreated` index as [`fetch_messages_by_ref_id`],
/// sorted descending — for "when did this side of the conversation last say
/// anything" without fetching the whole thread.
///
/// `refId` alone doesn't prove who wrote a document (see
/// [`fetch_messages_by_ref_id`]'s doc comment for the full threat model), so
/// this filters on `$ownerId` too — now via the query's own `$ownerId Equal`
/// clause rather than a client-side post-fetch check, so the single result
/// this function reads is already guaranteed to be owned by `expected_owner`.
/// [`RECENT_ACTIVITY_FETCH_LIMIT`] is `1`: with the query itself owner- and
/// ref-scoped and sorted newest-first, the first (and only) row it can
/// return is already the answer — no decoy can occupy the slot anymore, so
/// there's nothing left to over-fetch for.
///
/// The `$createdAt < now` range clause is required, not decorative: Drive
/// only reads an `order_by`'s direction from the clause it picks to drive
/// iteration, and that clause defaults to whichever `WhereClause` is an
/// equality match (here, `refId`/`$ownerId`) when nothing else qualifies —
/// equality clauses always iterate ascending, silently ignoring `order_by`.
/// Adding a *range* clause on the same field the `order_by` targets makes
/// Drive pick that as the deciding clause instead, whose direction genuinely
/// comes from `order_by` (see `rs-drive`'s `get_non_primary_key_path_query`).
/// Without this, a naive limited fetch would silently return the *oldest*
/// messages, not the newest.
async fn fetch_latest_message_created_at(
    orchardpay_contract: &DataContract,
    sdk: &Sdk,
    ref_id: [u8; 32],
    expected_owner: Identifier,
) -> Result<Option<u64>, TaskError> {
    /// The query is owner- and ref-scoped and sorted newest-first, so the
    /// single matching row (if any) is already the latest message — no
    /// over-fetch headroom needed.
    const RECENT_ACTIVITY_FETCH_LIMIT: u32 = 1;

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
            field: "$ownerId".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Identifier(expected_owner.to_buffer()),
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
        .next()
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
/// (`byReferenceIdbyOwnerIdAndCreated` is scoped to one `refId` at a time),
/// so this is inherently O(contacts) network calls, computed on-demand rather than
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

    let contract_id = orchardpay_contract.id();
    let contacts = backend.orchardpay_list_contacts(&contract_id, &owner_id)?;
    let established: Vec<EstablishedContactRefs> = contacts
        .into_iter()
        .filter_map(|counterparty| {
            match backend
                .orchardpay_get_contact_state(&contract_id, &owner_id, &counterparty)
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
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
    let mine_decode_failed = decode_page(
        &backend,
        &seed_hash,
        &mine_page.documents,
        true,
        &outbound_secret,
        &outgoing_payments,
        &incoming_payments,
        &mut all_decoded,
    );
    let their_decode_failed = decode_page(
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
    let may_be_incomplete = mine_page.may_be_incomplete
        || their_page.may_be_incomplete
        || mine_decode_failed
        || their_decode_failed;

    Ok(LoadedThread {
        all_decoded,
        messages,
        receipt_alerts,
        history_cursor,
        may_be_incomplete,
    })
}

/// Decode a fetched page's documents into `out`, one directional secret at a
/// time — the shared per-page body of both [`load_thread`] and
/// [`load_more_history`]. Returns whether any document in this page failed
/// to decode (wrong-key/tampered ciphertext, or bytes that don't parse as
/// [`MessageContent`]) — those are silently dropped from `out`, so the
/// caller can surface a "some messages may not have loaded" notice instead
/// of the loss being invisible.
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
) -> bool {
    let mut any_decode_failure = false;
    for document in documents {
        match decode_thread_message(
            backend,
            seed_hash,
            document,
            from_me,
            shared_secret,
            outgoing_payments,
            incoming_payments,
        ) {
            Some(message) => out.push(message),
            None => any_decode_failure = true,
        }
    }
    any_decode_failure
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
#[allow(clippy::too_many_arguments)]
pub async fn load_more_history(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: &QualifiedIdentity,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
    mut all_decoded: Vec<ThreadMessage>,
    history_cursor: HistoryCursor,
    mut may_be_incomplete: bool,
) -> Result<LoadedThread, TaskError> {
    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let EstablishedRelationship {
        my_reference_id,
        their_reference_id,
        counterparty_encryption_pubkey: enc_pk,
        counterparty_decryption_pubkey: dec_pk,
    } = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

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
        let decode_failed = decode_page(
            &backend,
            &seed_hash,
            &page.documents,
            true,
            &outbound_secret,
            &outgoing_payments,
            &incoming_payments,
            &mut all_decoded,
        );
        may_be_incomplete = may_be_incomplete || page.may_be_incomplete || decode_failed;
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
        let decode_failed = decode_page(
            &backend,
            &seed_hash,
            &page.documents,
            false,
            &inbound_secret,
            &outgoing_payments,
            &incoming_payments,
            &mut all_decoded,
        );
        may_be_incomplete = may_be_incomplete || page.may_be_incomplete || decode_failed;
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
        may_be_incomplete,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `encryptedMessage`-shaped document carrying only what
    /// [`trim_ambiguous_tail`] reads (`created_at`) — every other field is a
    /// throwaway default, mirroring the fixture style used elsewhere in
    /// this crate's tests for documents that only need one property real.
    fn doc_with_created_at(id_byte: u8, created_at: u64) -> Document {
        DppDocument::V0(DocumentV0 {
            id: Identifier::from([id_byte; 32]),
            owner_id: Identifier::from([0xAAu8; 32]),
            creator_id: None,
            properties: BTreeMap::new(),
            revision: Some(1),
            created_at: Some(created_at),
            updated_at: None,
            transferred_at: None,
            created_at_block_height: None,
            updated_at_block_height: None,
            transferred_at_block_height: None,
            created_at_core_block_height: None,
            updated_at_core_block_height: None,
            transferred_at_core_block_height: None,
        })
    }

    fn created_ats(documents: &[Document]) -> Vec<u64> {
        documents.iter().filter_map(|d| d.created_at()).collect()
    }

    /// Every document has a distinct timestamp — no *visible* tie at all.
    /// The trailing (minimum-timestamp) document must still be deferred:
    /// its apparent uniqueness in this page proves nothing about whether an
    /// identically-timestamped sibling exists just past the limit cutoff, a
    /// single page's data can't tell those two situations apart.
    #[test]
    fn trim_ambiguous_tail_defers_the_last_item_even_with_no_visible_tie() {
        let mut documents: Vec<Document> = (0..5)
            .map(|i| doc_with_created_at(i, 1_000 - u64::from(i)))
            .collect();

        let (cursor, may_be_incomplete) = trim_ambiguous_tail(&mut documents, true);

        assert_eq!(
            created_ats(&documents),
            vec![1_000, 999, 998, 997],
            "the trailing document (996) must be deferred, not just documents with a visible tie"
        );
        assert_eq!(
            cursor,
            Some(997),
            "cursor must be the last kept document's timestamp"
        );
        assert!(
            !may_be_incomplete,
            "a normal trim isn't the pathological fallback"
        );
    }

    /// A tie at the very end of a full page — the exact bug scenario: the
    /// last two documents share the batch's minimum timestamp. Both must be
    /// trimmed (held back for the next page), and the cursor must point at
    /// the distinct timestamp just above them, not at the tied value
    /// itself — using the tied value itself would exclude the trimmed
    /// documents from ever being re-fetched.
    #[test]
    fn trim_ambiguous_tail_trims_a_boundary_tie_and_holds_it_back() {
        let mut documents = vec![
            doc_with_created_at(1, 1_000),
            doc_with_created_at(2, 999),
            doc_with_created_at(3, 998),
            doc_with_created_at(4, 997), // tied with #5 below
            doc_with_created_at(5, 997), // tied with #4 above
        ];

        let (cursor, may_be_incomplete) = trim_ambiguous_tail(&mut documents, true);

        assert_eq!(
            created_ats(&documents),
            vec![1_000, 999, 998],
            "both documents sharing the trailing timestamp must be trimmed"
        );
        assert_eq!(
            cursor,
            Some(998),
            "cursor must be the last kept document's timestamp, not the trimmed tie's"
        );
        assert!(
            !may_be_incomplete,
            "a normal trim isn't the pathological fallback"
        );
    }

    /// A tie earlier in the page, away from the boundary, is guaranteed
    /// complete (the limit can only cut a run short if it's the *last* one
    /// in the batch) and must be left untouched — but the trailing
    /// document, even though it's a singleton with no visible tie of its
    /// own, still gets deferred (same reasoning as the no-visible-tie test
    /// above).
    #[test]
    fn trim_ambiguous_tail_leaves_a_non_boundary_tie_alone() {
        let mut documents = vec![
            doc_with_created_at(1, 1_000),
            doc_with_created_at(2, 999), // tied with #3 — not the trailing run, must survive
            doc_with_created_at(3, 999),
            doc_with_created_at(4, 998), // the lone trailing document — must be deferred
        ];

        let (cursor, may_be_incomplete) = trim_ambiguous_tail(&mut documents, true);

        assert_eq!(
            created_ats(&documents),
            vec![1_000, 999, 999],
            "the non-boundary tie (999, 999) must survive untouched; only the trailing \
             singleton (998) is deferred"
        );
        assert_eq!(cursor, Some(999));
        assert!(
            !may_be_incomplete,
            "a normal trim isn't the pathological fallback"
        );
    }

    /// Pathological fallback: every document in a full page shares the same
    /// timestamp, so there's no safe boundary to trim to. Falls back to the
    /// pre-fix behavior (accept the loss risk, don't stall pagination)
    /// rather than emptying the page or leaving the cursor unable to
    /// progress.
    #[test]
    fn trim_ambiguous_tail_falls_back_when_the_entire_page_is_tied() {
        let mut documents: Vec<Document> = (0..5).map(|i| doc_with_created_at(i, 1_000)).collect();

        let (cursor, may_be_incomplete) = trim_ambiguous_tail(&mut documents, true);

        assert_eq!(
            created_ats(&documents),
            vec![1_000, 1_000, 1_000, 1_000, 1_000],
            "nothing can be safely trimmed, so the full page is kept as-is"
        );
        assert_eq!(cursor, Some(1_000));
        assert!(
            may_be_incomplete,
            "the pathological fallback must report itself so the UI can surface a notice"
        );
    }

    /// A non-full page (`has_more = false`) means nothing was cut off by
    /// the query limit, so there's no ambiguity to resolve even if the
    /// trailing entries happen to share a timestamp — no trimming.
    #[test]
    fn trim_ambiguous_tail_no_op_when_page_is_not_full() {
        let mut documents = vec![
            doc_with_created_at(1, 1_000),
            doc_with_created_at(2, 999),
            doc_with_created_at(3, 999),
        ];

        let (cursor, may_be_incomplete) = trim_ambiguous_tail(&mut documents, false);

        assert_eq!(
            created_ats(&documents),
            vec![1_000, 999, 999],
            "an already-complete last page must never be trimmed"
        );
        assert_eq!(cursor, Some(999));
        assert!(!may_be_incomplete);
    }
}
