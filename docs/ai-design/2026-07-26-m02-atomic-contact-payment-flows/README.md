# M-02: Multi-step contact/payment flows aren't atomic

Status: **implemented**. One of three independent follow-ups to
`docs/ORCHARDPAY_COMPREHENSIVE_REVIEW_2026-07-25.md` — see
`docs/ai-design/2026-07-26-comprehensive-review-response/README.md` for how
this relates to the other two (M-05, M-08).

## The problem

Three flows publish a permanent Platform document, then perform a shielded
transfer, then write local state — with no recovery path if something
fails in between:

- **`contact_anchor::initiate_contact`**: broadcasts the `contactAnchor`
  document, *then* sends the memo-tagged signaling transfer, *then* writes
  local `OrchardPayContactState::PendingOutbound`.
- **`contact_anchor::accept_contact`**: identical shape — document,
  transfer, `Established` state.
- **`messages::send_payment`**: broadcasts the `Payment` document (its
  standalone path — fulfilling an existing `PaymentRequest` targets that
  request's already-durable id instead, so it doesn't have this risk),
  *then* the real shielded transfer.

If the transfer step failed after the document already broadcast: a naive
retry from the UI would republish a **second**, orphaned document with a
new `document_id`/`my_reference_id` — the pre-publish "already exists"
guards (`orchardpay_get_contact_state` for the contact flows; none at all
for `send_payment`) only see state written at the *end* of a successful
run.

## Implemented fix: a local "operation intent" marker, not a full state machine

A narrower fix than the review's suggested formal per-document state
machine (`proposed`/`submitted`/`confirmed`/`failed`) — this only prevents
the application from choosing to double-broadcast, and gives a resume path
for the two flows where auto-resume is safe.

- **New model type** (`model/orchardpay.rs`): `PendingOrchardPayOperation`
  (`ContactAnchor { my_reference_id, my_anchor_document_id, step }` /
  `Payment { document_id, step }`) and `PendingOperationStep`
  (`DocumentPublished` / `TransferSent`).
- **New KV state** (`wallet_backend/orchardpay.rs`): `KV_PREFIX_PENDING_OPERATION`,
  scoped `DetScope::Identity` + keyed by counterparty (same shape as
  `KV_PREFIX_CONTACT`), with `orchardpay_get/set/clear_pending_operation`.
  Swept by `orchardpay_clear_owner_overlays` alongside contact state.
- **`initiate_contact`/`accept_contact`**: the marker is written (step
  `DocumentPublished`) right after `my_reference_id`/`document_id` are
  generated, *before* `run_document_task` — the first network side effect.
  Both functions now check for a pending marker before doing any fresh
  work: if one exists, they **reuse** its `document_id`/`my_reference_id`
  instead of generating new ones, skip re-publishing if the document is
  already out, and — critically — skip re-sending the transfer too if it
  already went through (`step == TransferSent`), so a retry can never
  double-send the anchor-signal transfer. The marker is cleared only after
  the final `OrchardPayContactState` write succeeds. `accept_contact`
  additionally re-fetches the counterparty's public keys and DPNS name
  unconditionally (cheap, read-only, safe to repeat) so the final
  `Established` state is complete on a resume without needing to persist
  that data too.
- **`send_payment`**: a fresh, standalone `Payment` document's `document_id`
  is now generated *before* broadcasting (previously buried inside
  `broadcast_encrypted_message`, only known *after* broadcast) via a new
  `broadcast_new_payment_message`, which persists the marker first. Unlike
  the contact flows, `send_payment` does **not** auto-resume: if a pending
  `Payment` marker already exists for the counterparty when a fresh send is
  attempted, it returns `TaskError::OrchardPayPaymentRecoveryNeeded`
  instead of silently publishing a second document or automatically
  resending real funds. The marker is cleared once the transfer succeeds
  (a no-op if none was set — the request-fulfilling path never sets one).

## Explicitly out of scope (unchanged from the original proposal)

- A fully modeled per-document lifecycle stored *in* the Platform document
  itself — schema migration decision, separate from this local-recovery
  fix.
- SDK/network-level broadcast idempotency — this only stops the
  application from choosing to double-broadcast.
- The receipt-first ordering for `send_payment`'s "Save Receipt" path —
  left as-is; it already propagates failure via `?` before the transfer,
  independent of anything here.

## Verification

- New unit tests in `wallet_backend/orchardpay.rs`: pending-operation
  round-trip for both `ContactAnchor` and `Payment` variants, per-counterparty
  scoping, and the `orchardpay_clear_owner_overlays` sweep clearing them.
  (Full async integration tests of `initiate_contact`/`accept_contact`/
  `send_payment` themselves aren't feasible without SDK-mocking
  infrastructure that doesn't exist in this codebase yet — consistent with
  these functions having no prior test coverage either.)
- `cargo test --all-features orchardpay` (66 passed), `cargo clippy --bin
  orchardpay --all-features -- -D warnings` (clean), `cargo fmt --all`.
