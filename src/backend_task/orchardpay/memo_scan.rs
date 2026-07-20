//! Thin `backend_task` wrapper around `WalletBackend::
//! orchardpay_scan_incoming_memos` — see
//! `docs/ai-design/2026-07-18-orchardpay-memo-detection/` for why this scan
//! exists and re-fetches independently of the wallet's own sync coordinator.

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::handle_incoming_anchor_signal;
use crate::backend_task::orchardpay::messages;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::IncomingMemoSignal;
use dash_sdk::Sdk;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use std::sync::Arc;

/// Run one pass of the incoming-memo scan for `seed_hash`'s wallet, then
/// dispatch every detected signal:
///
/// - [`IncomingMemoSignal::Anchor`]: tried against every identity in
///   `qualified_identities`. Trying every locally-known identity (rather
///   than resolving which identity a wallet's memo is "for") is deliberate:
///   only the identity actually holding the matching contract-bounded
///   DECRYPTION key can ever decrypt a given anchor, so mismatched attempts
///   fail cheaply and are simply skipped — see
///   `contact_anchor::handle_incoming_anchor_signal`.
/// - [`IncomingMemoSignal::Payment`]: cached directly (no per-identity
///   decryption needed — see `messages::record_verified_incoming_payment`)
///   so `messages::load_thread` can source the real transferred amount
///   without re-scanning.
pub async fn scan_for_incoming_anchors(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identities: Vec<QualifiedIdentity>,
    seed_hash: WalletSeedHash,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let backend = app_context.wallet_backend()?;
    let network = app_context.network;
    let start_index = backend
        .orchardpay_get_memo_scan_cursor(&seed_hash)?
        .unwrap_or(0);

    let (found, next_start_index) = backend
        .orchardpay_scan_incoming_memos(sdk, &seed_hash, network, start_index)
        .await?;

    let mut anything_changed = false;
    for signal in found {
        match signal {
            IncomingMemoSignal::Anchor(anchor_document_id) => {
                for identity in &qualified_identities {
                    match handle_incoming_anchor_signal(
                        app_context,
                        sdk,
                        identity,
                        anchor_document_id,
                        seed_hash,
                    )
                    .await
                    {
                        Ok(true) => anything_changed = true,
                        Ok(false) => {}
                        Err(e) => {
                            // A wrong-identity decrypt attempt or a
                            // transient network error on one signal
                            // shouldn't abort the rest of the pass — log
                            // and move on.
                            tracing::debug!(
                                identity = %identity.identity.id(),
                                anchor = %anchor_document_id,
                                error = ?e,
                                "OrchardPay: incoming anchor signal not handled for this identity"
                            );
                        }
                    }
                }
            }
            IncomingMemoSignal::Payment {
                referenced_document_id,
                received_amount_credits,
            } => {
                if let Err(e) = messages::record_verified_incoming_payment(
                    &backend,
                    &seed_hash,
                    referenced_document_id,
                    received_amount_credits,
                ) {
                    tracing::debug!(
                        document = %referenced_document_id,
                        error = ?e,
                        "OrchardPay: failed to cache a verified incoming payment amount"
                    );
                } else {
                    anything_changed = true;
                }
            }
        }
    }

    backend.orchardpay_set_memo_scan_cursor(&seed_hash, next_start_index)?;

    Ok(if anything_changed {
        BackendTaskSuccessResult::Refresh
    } else {
        BackendTaskSuccessResult::None
    })
}

/// Convenience for callers that only have a `BackendTask` handle (e.g. the
/// event-bridge trigger) and want to dispatch this scan for every local
/// identity without constructing the task variant by hand.
pub fn dispatch_task(
    qualified_identities: Vec<QualifiedIdentity>,
    seed_hash: WalletSeedHash,
) -> BackendTask {
    BackendTask::OrchardPayTask(Box::new(
        crate::backend_task::orchardpay::OrchardPayTask::ScanForIncomingAnchors {
            qualified_identities,
            seed_hash,
        },
    ))
}
