//! `OPP2` "silent payment": a real shielded transfer to an `Established`
//! contact with **no** backing `encryptedMessage` document, so no public
//! document-creation event precedes the transfer's broadcast — closing the
//! timing-correlation privacy gap `messages::send_payment` doesn't (it
//! always publishes a `Payment` document first, even for a memo-less
//! payment, then a memo-correlated transfer).
//!
//! Distinct from both siblings:
//! - `direct_send::send_direct` needs no relationship at all, writes an
//!   all-zero memo, and never appears in any conversation — a dead end for
//!   this feature's goal of still showing up in the right thread.
//! - `messages::send_payment` requires `Established` too, but always
//!   creates a document and tags the transfer with that document's ID.
//!
//! A silent payment instead tags the transfer with [`MEMO_TAG_SILENT_PAYMENT`]
//! followed by a sender-written timestamp and a truncated HMAC-SHA256 tag
//! authenticating it under a relationship-specific sub-key
//! (`encryption::derive_opp2_mac_key`) — cryptographically bound to the
//! same ECDH shared secret `MEMO_TAG_PAYMENT` messages are encrypted under,
//! so forging an attribution requires the actual shared secret, not merely
//! a relationship's `refId` (which is publicly queryable once used — see
//! `docs/orchardpay/PROTOCOL_DESIGN.md`'s "silent payments" section for the
//! full rationale). Recipients resolve which contact sent it via the
//! eager incoming-memo scan
//! (`wallet_backend::orchardpay::orchardpay_scan_incoming_memos` +
//! `memo_scan`), not at thread-load time.
//!
//! No document means no [`crate::model::orchardpay::PendingOrchardPayOperation`]
//! marker either — this is a single atomic external call with nothing to
//! resume on crash, the same simplicity class as `send_direct`.

use crate::backend_task::BackendTaskSuccessResult;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::messages::{
    MEMO_TAG_SILENT_PAYMENT, OPP2_MAC_OFFSET, OPP2_TIMESTAMP_OFFSET, established_state,
    outbound_shared_secret,
};
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::backend_task::orchardpay::{encryption, errors::OrchardPayError};
use crate::context::AppContext;
use crate::model::orchardpay::{SilentPaymentRecord, validate_send_amount};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::platform::Identifier;
use std::sync::Arc;

/// Send `amount` credits to `counterparty_identity_id` as a silent payment
/// — no document, no message. Requires the relationship to already be
/// `Established`: sending before that point risks interrupting the
/// in-flight handshake (same reasoning as `contact_anchor`'s deletion
/// guard), a different concern from the timing-correlation one this
/// feature otherwise addresses.
pub async fn send_silent_payment(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
    amount: u64,
) -> Result<BackendTaskSuccessResult, TaskError> {
    validate_send_amount(amount).map_err(|source| TaskError::OrchardPayAmountTooLow { source })?;

    let owner_id = qualified_identity.identity.id();
    let orchardpay_contract = super::ensure_orchardpay_contract(app_context, sdk).await?;
    let backend = app_context.wallet_backend()?;
    let established = established_state(
        &backend,
        orchardpay_contract.id(),
        owner_id,
        counterparty_identity_id,
    )?;

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let shared_secret = outbound_shared_secret(
        app_context,
        &qualified_identity,
        orchardpay_contract.id(),
        &established.counterparty_decryption_pubkey,
        seed_hash,
    )
    .await?;
    let mac_key = encryption::derive_opp2_mac_key(&shared_secret);

    let timestamp: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .try_into()
        .unwrap_or(u32::MAX);
    let mac = encryption::compute_opp2_mac(&mac_key, timestamp);

    let mut transfer_memo = [0u8; 36];
    transfer_memo[..4].copy_from_slice(&MEMO_TAG_SILENT_PAYMENT);
    transfer_memo[OPP2_TIMESTAMP_OFFSET..OPP2_MAC_OFFSET].copy_from_slice(&timestamp.to_be_bytes());
    transfer_memo[OPP2_MAC_OFFSET..].copy_from_slice(&mac);

    backend
        .shielded_transfer(
            &seed_hash,
            0,
            &counterparty_shielded_address,
            amount,
            transfer_memo,
        )
        .await?;

    // The sender already knows exactly who this went to, for how much, and
    // when — no scan/matching needed for this identity's own sent side.
    // Cached under the same fingerprint scheme the incoming-scan resolution
    // path uses (`encryption::opp2_memo_fingerprint`, derived from the
    // memo's own timestamp+MAC — no need for the note's `cmx`, so both
    // sides key identically with no extra plumbing).
    let fingerprint = encryption::opp2_memo_fingerprint(timestamp, &mac);
    if let Err(e) = backend.orchardpay_set_silent_payment(
        &orchardpay_contract.id(),
        &owner_id,
        &counterparty_identity_id,
        &fingerprint,
        &SilentPaymentRecord {
            amount,
            timestamp,
            from_me: true,
        },
    ) {
        tracing::warn!(
            counterparty = %counterparty_identity_id,
            error = ?e,
            "OrchardPay: silent payment broadcast succeeded but failed to record the local \
             sent-side cache entry; the recipient's own incoming scan is unaffected"
        );
    }

    Ok(BackendTaskSuccessResult::OrchardPaySilentPaymentSent {
        counterparty_identity_id,
        amount,
    })
}
