//! Direct Send's "no contact request" branch: a bare shielded transfer to
//! any identity with a published `shieldedAddress`, regardless of any
//! `OrchardPayContactState` for them (including none at all — that's the
//! whole point). No OrchardPay document is created, and no local contact
//! state is read as a precondition or written as a result. Restricting the
//! *button* to `existing_relationship: None` search rows is a UI-level
//! scoping choice (`orchardpay_screen.rs::render_direct_send`), not
//! something this module enforces.
//!
//! Distinct from both siblings:
//! - `contact_anchor::initiate_contact` publishes a `contactAnchor`
//!   document and tags the transfer with its DocumentID
//!   (`contact_anchor::MEMO_TAG_ANCHOR`). Direct Send's *other* branch (its
//!   confirmation modal's checkbox, checked) calls that function directly
//!   with a caller-chosen amount instead of this module.
//! - `messages::send_payment` requires an `Established` relationship and
//!   always references an `encryptedMessage` document.
//!
//! The transfer's memo is `[0u8; 36]` — all zero, the plain wallet Send
//! screen's own convention for a memo-less send — so it matches neither
//! `contact_anchor::MEMO_TAG_ANCHOR` nor `messages::MEMO_TAG_PAYMENT` in the
//! incoming-memo scan (`wallet_backend::orchardpay::orchardpay_scan_incoming_memos`)
//! and just shows up as an ordinary shielded receive for the recipient.

use crate::backend_task::BackendTaskSuccessResult;
use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::context::AppContext;
use crate::model::orchardpay::validate_send_amount;
use crate::model::wallet::WalletSeedHash;
use dash_sdk::Sdk;
use dash_sdk::platform::Identifier;
use std::sync::Arc;

/// Send `amount` credits directly to `counterparty_identity_id`'s published
/// shielded address, with no accompanying document and no contact
/// relationship required.
pub async fn send_direct(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    owner_identity_id: Identifier,
    counterparty_identity_id: Identifier,
    seed_hash: WalletSeedHash,
    amount: u64,
) -> Result<BackendTaskSuccessResult, TaskError> {
    // Same self-send guard `contact_anchor::initiate_contact` applies — DPNS
    // search doesn't exclude the searcher's own name, so this is reachable,
    // not just defensive noise.
    if owner_identity_id == counterparty_identity_id {
        return Err(OrchardPayError::CounterpartyKeyMissing.into());
    }
    validate_send_amount(amount).map_err(|source| TaskError::OrchardPayAmountTooLow { source })?;

    let counterparty_shielded_address =
        lookup_shielded_address(app_context, sdk, counterparty_identity_id)
            .await?
            .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let backend = app_context.wallet_backend()?;
    backend
        .shielded_transfer(
            &seed_hash,
            0,
            &counterparty_shielded_address,
            amount,
            [0u8; 36],
        )
        .await?;

    Ok(BackendTaskSuccessResult::OrchardPayDirectSendCompleted {
        counterparty_identity_id,
        amount,
    })
}
