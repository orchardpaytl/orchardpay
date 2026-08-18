//! Thin `backend_task` wrapper around `WalletBackend::
//! orchardpay_scan_incoming_memos` — see
//! `docs/ai-design/2026-07-18-orchardpay-memo-detection/` for why this scan
//! exists and re-fetches independently of the wallet's own sync coordinator.

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::handle_incoming_anchor_signal;
use crate::backend_task::orchardpay::encryption;
use crate::backend_task::orchardpay::messages;
use crate::backend_task::orchardpay::messages::clamp_opp2_timestamp;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::orchardpay::SilentPaymentRecord;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::{IncomingMemoSignal, MEMO_SCAN_ERROR_RETRY_CAP};
use dash_sdk::Sdk;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::platform::Identifier;
use std::sync::Arc;
use zeroize::Zeroizing;

/// One `Established` contact's `OPP2` MAC key, precomputed once per scan
/// pass (not once per note — see [`build_silent_payment_candidates`]).
struct SilentPaymentCandidate {
    owner_id: Identifier,
    counterparty_id: Identifier,
    mac_key: Zeroizing<[u8; 32]>,
}

/// Precompute every locally-known identity's `Established` contacts' `OPP2`
/// MAC keys once per scan pass, so resolving each [`IncomingMemoSignal::SilentPayment`]
/// found this pass is just an HMAC comparison per candidate, not a fresh
/// per-note key derivation. Entirely local: `established_state`/
/// `outbound_shared_secret` never touch the network once a relationship's
/// counterparty pubkeys are already cached, which `Established` guarantees.
/// A single contact whose shared-secret derivation fails (e.g. a locked
/// wallet edge case) is skipped with a warning rather than aborting the
/// whole scan pass.
async fn build_silent_payment_candidates(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identities: &[QualifiedIdentity],
    seed_hash: WalletSeedHash,
) -> Result<Vec<SilentPaymentCandidate>, TaskError> {
    let orchardpay_contract =
        crate::backend_task::orchardpay::ensure_orchardpay_contract(app_context, sdk).await?;
    let contract_id = orchardpay_contract.id();
    let backend = app_context.wallet_backend()?;

    let mut candidates = Vec::new();
    for identity in qualified_identities {
        let owner_id = identity.identity.id();
        for counterparty_id in backend.orchardpay_list_contacts(&contract_id, &owner_id)? {
            let Ok(established) =
                messages::established_state(&backend, contract_id, owner_id, counterparty_id)
            else {
                continue; // Not `Established` yet — no relationship to attribute a silent payment to.
            };
            match messages::outbound_shared_secret(
                app_context,
                identity,
                contract_id,
                &established.counterparty_decryption_pubkey,
                seed_hash,
            )
            .await
            {
                Ok(shared_secret) => candidates.push(SilentPaymentCandidate {
                    owner_id,
                    counterparty_id,
                    mac_key: encryption::derive_opp2_mac_key(&shared_secret),
                }),
                Err(e) => {
                    tracing::warn!(
                        owner = %owner_id,
                        counterparty = %counterparty_id,
                        error = ?e,
                        "OrchardPay: could not derive this contact's OPP2 MAC key for this scan \
                         pass, skipping it — a silent payment from them this pass may go \
                         unattributed"
                    );
                }
            }
        }
    }
    Ok(candidates)
}

/// Try `anchor_document_id` against every identity in `qualified_identities`,
/// applying the first that claims it. Returns `(applied, had_error)`:
/// `applied` is true once some identity successfully claims the signal
/// (`Ok(true)`); `had_error` is true if at least one attempt failed with a
/// genuine processing error, as opposed to a clean "not for this identity"
/// (`Ok(false)`) — see `contact_anchor::handle_incoming_anchor_signal`'s doc
/// comment for why the two are distinguished. Trying every locally-known
/// identity (rather than resolving which identity a wallet's memo is "for"
/// up front) is deliberate: only the identity actually holding the matching
/// contract-bounded DECRYPTION key can ever decrypt a given anchor, so
/// mismatched attempts fail cheaply and are simply skipped.
async fn try_anchor_against_identities(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identities: &[QualifiedIdentity],
    anchor_document_id: Identifier,
    seed_hash: WalletSeedHash,
) -> (bool, bool) {
    let mut applied = false;
    let mut had_error = false;
    for identity in qualified_identities {
        match handle_incoming_anchor_signal(
            app_context,
            sdk,
            identity,
            anchor_document_id,
            seed_hash,
        )
        .await
        {
            Ok(true) => applied = true,
            Ok(false) => {}
            Err(e) => {
                had_error = true;
                tracing::warn!(
                    identity = %identity.identity.id(),
                    anchor = %anchor_document_id,
                    error = ?e,
                    "OrchardPay: incoming anchor signal not handled for this identity, will retry"
                );
            }
        }
    }
    (applied, had_error)
}

/// Run one pass of the incoming-memo scan for `seed_hash`'s wallet, then
/// dispatch every detected signal:
///
/// - [`IncomingMemoSignal::Anchor`]: tried against every identity in
///   `qualified_identities` via [`try_anchor_against_identities`]. An anchor
///   that matches nobody this pass is persisted as unresolved (see
///   `WalletBackend::orchardpay_record_unresolved_anchor_signal`) rather than
///   dropped — the wallet-level decrypt pass above (a single, wallet-wide
///   Orchard viewing key, not identity-specific) never needs to re-walk or
///   re-decrypt this note again; only the cheap identity-match step needs
///   retrying, which happens against the *unresolved list* below, not by
///   holding the resume cursor back. The cursor is held back only for a
///   genuine processing error (`had_error`), and only up to
///   [`MEMO_SCAN_ERROR_RETRY_CAP`] consecutive attempts, so one
///   persistently-failing signal can't wedge every later signal behind it
///   forever.
/// - Previously-unresolved anchors (from an earlier pass) are retried
///   against the current `qualified_identities` first — this is what lets a
///   newly-loaded identity (or one that has since set up OrchardPay) claim a
///   signal that arrived before it existed, without any note-stream
///   re-decrypt.
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
    let mut anchor_signals_seen = 0usize;
    let mut anchor_signals_claimed = 0usize;

    // Built once up front, not per signal — see its own doc comment. Only
    // built if this pass actually contains a silent-payment signal, since
    // it costs a per-established-contact shared-secret derivation.
    let has_silent_payment_signal = found
        .iter()
        .any(|(_, s)| matches!(s, IncomingMemoSignal::SilentPayment { .. }));
    let silent_payment_candidates = if has_silent_payment_signal {
        build_silent_payment_candidates(app_context, sdk, &qualified_identities, seed_hash).await?
    } else {
        Vec::new()
    };
    let silent_payment_contract_id = if has_silent_payment_signal {
        Some(
            crate::backend_task::orchardpay::ensure_orchardpay_contract(app_context, sdk)
                .await?
                .id(),
        )
    } else {
        None
    };

    for anchor_document_id in backend.orchardpay_list_unresolved_anchor_signals(&seed_hash)? {
        anchor_signals_seen += 1;
        let (applied, _had_error) = try_anchor_against_identities(
            app_context,
            sdk,
            &qualified_identities,
            anchor_document_id,
            seed_hash,
        )
        .await;
        if applied {
            backend.orchardpay_clear_unresolved_anchor_signal(&seed_hash, &anchor_document_id)?;
            anything_changed = true;
            anchor_signals_claimed += 1;
        }
        // Still unresolved (whether from a clean "not mine" or a transient
        // error) simply stays recorded — retried again next pass. It's off
        // the resume cursor's critical path, so it can never wedge scanning.
    }

    // Notes whose signal didn't fully resolve this pass (a real processing
    // error, not just "wrong identity") hold the persisted cursor back to
    // their own position, so they get re-decrypted and retried on the next
    // scan pass — up to MEMO_SCAN_ERROR_RETRY_CAP attempts. Tracks the
    // earliest still-retryable position; everything before it is safe to
    // consider permanently scanned.
    let mut retry_from: Option<u64> = None;
    for (note_index, signal) in found {
        match signal {
            IncomingMemoSignal::Anchor(anchor_document_id) => {
                anchor_signals_seen += 1;
                let (applied, had_error) = try_anchor_against_identities(
                    app_context,
                    sdk,
                    &qualified_identities,
                    anchor_document_id,
                    seed_hash,
                )
                .await;
                if applied {
                    anything_changed = true;
                    anchor_signals_claimed += 1;
                    backend.orchardpay_clear_memo_scan_retry_count(&seed_hash, note_index)?;
                } else if had_error {
                    let attempts = backend
                        .orchardpay_increment_memo_scan_retry_count(&seed_hash, note_index)?;
                    if attempts < MEMO_SCAN_ERROR_RETRY_CAP {
                        retry_from = Some(retry_from.map_or(note_index, |r| r.min(note_index)));
                    } else {
                        tracing::warn!(
                            anchor = %anchor_document_id,
                            note_index,
                            attempts,
                            "OrchardPay: giving up retrying a persistently-failing anchor signal, moving past it"
                        );
                        backend.orchardpay_clear_memo_scan_retry_count(&seed_hash, note_index)?;
                    }
                } else {
                    // Decrypted fine, but no currently-loaded identity claims
                    // it — remember it instead of losing it forever.
                    backend.orchardpay_record_unresolved_anchor_signal(
                        &seed_hash,
                        &anchor_document_id,
                    )?;
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
                    let attempts = backend
                        .orchardpay_increment_memo_scan_retry_count(&seed_hash, note_index)?;
                    if attempts < MEMO_SCAN_ERROR_RETRY_CAP {
                        tracing::warn!(
                            document = %referenced_document_id,
                            error = ?e,
                            attempts,
                            "OrchardPay: failed to cache a verified incoming payment amount, will retry next scan pass"
                        );
                        retry_from = Some(retry_from.map_or(note_index, |r| r.min(note_index)));
                    } else {
                        tracing::warn!(
                            document = %referenced_document_id,
                            error = ?e,
                            attempts,
                            "OrchardPay: giving up caching a persistently-failing verified payment amount, moving past it"
                        );
                        backend.orchardpay_clear_memo_scan_retry_count(&seed_hash, note_index)?;
                    }
                } else {
                    anything_changed = true;
                    backend.orchardpay_clear_memo_scan_retry_count(&seed_hash, note_index)?;
                }
            }
            IncomingMemoSignal::SilentPayment {
                timestamp,
                mac,
                received_amount_credits,
            } => {
                // Never guess: 0 matches means it's not for OrchardPay at
                // all (dropped, same as any other foreign/malformed memo —
                // the transfer still counts toward this wallet's normal
                // balance regardless); 2+ matches means it's ambiguous
                // between established contacts, so it's left unattributed
                // rather than risking a misattribution — see
                // `docs/orchardpay/PROTOCOL_DESIGN.md`'s "silent payments"
                // ambiguous-match policy. Either way there is nothing to
                // retry — the signal decrypted and was fully evaluated this
                // pass.
                let matches: Vec<&SilentPaymentCandidate> = silent_payment_candidates
                    .iter()
                    .filter(|c| encryption::compute_opp2_mac(&c.mac_key, timestamp) == mac)
                    .collect();
                if let [candidate] = matches.as_slice() {
                    let clamped_timestamp = clamp_opp2_timestamp(timestamp);
                    let fingerprint = encryption::opp2_memo_fingerprint(timestamp, &mac);
                    let contract_id = silent_payment_contract_id
                        .expect("a match implies silent_payment_candidates was built, which implies the contract was resolved");
                    if let Err(e) = backend.orchardpay_set_silent_payment(
                        &contract_id,
                        &candidate.owner_id,
                        &candidate.counterparty_id,
                        &fingerprint,
                        &SilentPaymentRecord {
                            amount: received_amount_credits,
                            timestamp: clamped_timestamp,
                            from_me: false,
                        },
                    ) {
                        tracing::warn!(
                            owner = %candidate.owner_id,
                            counterparty = %candidate.counterparty_id,
                            error = ?e,
                            "OrchardPay: failed to cache a resolved silent payment, will not retry \
                             (the transfer still counts toward the normal wallet balance)"
                        );
                    } else {
                        anything_changed = true;
                    }
                } else if matches.len() > 1 {
                    tracing::warn!(
                        note_index,
                        candidate_count = matches.len(),
                        "OrchardPay: a silent payment's memo matched more than one established \
                         contact's key — leaving it unattributed rather than guessing"
                    );
                }
                backend.orchardpay_clear_memo_scan_retry_count(&seed_hash, note_index)?;
            }
        }
    }

    backend.orchardpay_set_memo_scan_cursor(&seed_hash, retry_from.unwrap_or(next_start_index))?;

    let anchor_signals_still_unresolved = backend
        .orchardpay_list_unresolved_anchor_signals(&seed_hash)?
        .len();

    tracing::info!(
        wallet = %hex::encode(seed_hash),
        anchor_signals_seen,
        anchor_signals_claimed,
        anchor_signals_still_unresolved,
        "OrchardPay: incoming anchor scan pass complete"
    );

    Ok(BackendTaskSuccessResult::OrchardPayIncomingAnchorsScanned {
        anything_changed,
        anchor_signals_seen,
        anchor_signals_claimed,
        anchor_signals_still_unresolved,
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
