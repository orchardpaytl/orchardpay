# OrchardPay incoming-memo detection: gap, decision, and revisit plan

Status: **decided (2026-07-18)** — DET-side duplicate scan, implemented as
part of Milestone D. Revisit once upstream `platform-wallet` has bandwidth.

## The gap

OrchardPay's contact-establishment handshake (`docs/orchardpay/
PROTOCOL_DESIGN.md`, "Two anchors per relationship") signals a new contact
request by sending a shielded transaction to the counterparty's published
`shieldedAddress`, with the sender's `contactAnchor` DocumentID packed into
the transaction's 36-byte memo. The recipient is expected to notice the
incoming transfer, read the memo, and fetch the referenced anchor directly by
ID (never by query — that's the actual privacy property: no document is ever
publicly discoverable as "a request to Bob").

This requires memo bytes to survive from the chain into OrchardPay's
application code. They currently don't, anywhere in the stack.

### Where it breaks

Everything below is in the vendored `platform-wallet` dependency
(`Cargo.toml`: `git = "https://github.com/dashpay/platform", rev =
"d18020f526e2a8eb1d1e868b436a7a9735795abb"`) — **not** OrchardPay's own code.

- The wallet's incoming-note sync loop,
  `rs-platform-wallet/src/wallet/shielded/sync.rs` (~line 467), calls
  `try_decrypt_note(&views.prepared_ivk, raw_note)` for every incoming note.
  This is the SDK's **compact** trial-decryption path
  (`rs-sdk/src/platform/shielded/notes_sync/decrypt.rs`) — it only reads the
  52-byte compact prefix of `enc_ciphertext`. The 36-byte Dash memo lives
  past that prefix, so this function structurally cannot recover it (its own
  doc comment says so).
- The note shape this produces and persists, `DiscoveredNote`/`ShieldedNote`
  (`rs-platform-wallet/src/wallet/shielded/store.rs:63-81`), has no memo
  field at all — `position, cmx, nullifier, block_height, is_spent, value,
  note_data`, nothing else.
- `ShieldedActivityEntry` (`rs-platform-wallet/src/wallet/shielded/
  activity.rs:135-175`) *does* carry `pub memo: Option<Vec<u8>>`, but it's
  only populated by the **outgoing** live-recorder path (a wallet's own
  sends) and by the restore path, which reconstructs from the same
  memo-less `ShieldedNote` store — so it can't surface an incoming memo
  either.
- DET's own `EventBridge` (`src/wallet_backend/event_bridge.rs`,
  `on_shielded_sync_completed`) only receives aggregate per-account
  balances (`ShieldedSyncPassSummary` → `summary_ok_balances`), no per-note
  data whatsoever.

Net effect: as wired today, an incoming shielded transfer's memo is dropped
before it reaches any layer OrchardPay can observe.

### The primitive that *would* fix it — confirmed real, not a stub

The SDK already has a memo-preserving counterpart,
`try_decrypt_note_with_memo` (`rs-sdk/src/platform/shielded/notes_sync/
decrypt.rs:221-253`). It decrypts the *full* 104-byte `enc_ciphertext` (not
just the compact prefix) via `try_note_decryption`, which is re-exported
straight from the real `orchard` crate (Zcash's own canonical Orchard
note-encryption implementation, via `grovedb-commitment-tree`) — not
something hand-rolled or partial.

It is also genuinely tested end-to-end, not merely present:
`rs-platform-wallet/src/wallet/shielded/sync/memo_roundtrip_tests.rs`,
`shield_memo_round_trips_through_ivk_decryption` builds a real Type-15
Shield state transition carrying a memo, decrypts it with
`try_decrypt_note_with_memo` under the recipient's IVK, and asserts the
exact memo bytes (and their decoded text) come back out. This is a real
round trip through real cryptography, not a mock.

**So the gap is narrow, not fundamental**: the sync loop's incoming-note
call site uses the wrong (memo-discarding) function. The fix — swap
`try_decrypt_note` for `try_decrypt_note_with_memo` at that one call site,
then thread the recovered `[u8; 36]` through `DiscoveredNote` / `ShieldedNote`
/ the changeset / the persister so it's retrievable — is a small, low-risk
change *in principle*. The reason it isn't "just do it" is entirely about
where the code lives, covered next.

## Options considered

1. **DET-side duplicate scan.** OrchardPay re-derives the wallet's Orchard
   incoming viewing key and calls `try_decrypt_note_with_memo` itself,
   directly against the raw note stream, independent of the wallet's own
   sync coordinator (which is still doing its own, separate trial
   decryption with `try_decrypt_note` for its normal balance/activity
   bookkeeping). Fully self-contained in this repo; no dependency on
   `dashpay/platform`'s release cadence. Cost: every incoming note gets
   trial-decrypted twice per sync pass — once by the coordinator (compact,
   for balance/activity), once by OrchardPay (full, for the memo) — genuine
   redundant compute, though bounded by wallet note-count, not chain size.

2. **Patch the sync loop upstream.** Swap the call in
   `rs-platform-wallet/src/wallet/shielded/sync.rs` and thread the memo
   through the note/store/activity types. Architecturally correct — no
   duplicate decryption, incoming memos become a first-class part of the
   wallet's own note model, available to any future feature, not just
   OrchardPay. Cost: this code is not ours. It lives in the `dashpay/platform`
   git dependency pinned by commit rev, so making this change means either
   forking that repo and pointing `Cargo.toml` at the fork (taking on
   maintenance of a diverging patch until upstream accepts it) or opening a
   PR against `dashpay/platform` and waiting on their review timeline before
   OrchardPay can depend on it.

## Decision

**Option 1 for now.** Ship the DET-side duplicate scan as part of Milestone
D so contact establishment works end-to-end without taking on a fork or an
external review dependency. The redundant-decryption cost is real but
bounded and not a correctness risk — `try_decrypt_note_with_memo` is proven
correct via the round-trip test cited above, so duplicating its use is safe,
just not free.

## Send-side verification (2026-07-18)

Before trusting the send side given the decrypt-side gap above, verified
independently whether a memo passed into `shielded_transfer` actually
survives into the on-chain note, or gets silently dropped/zeroed somewhere
in the builder chain.

**Plumbing is sound.** `WalletBackend::shielded_transfer` (`src/
wallet_backend/shielded.rs:205-227`) passes its `memo: [u8; 36]` parameter
unmodified through every hop: `platform_wallet::PlatformWallet::
shielded_transfer_to` → `platform-wallet`'s `shielded::operations::transfer`
→ `dpp::shielded::builder::build_shielded_transfer_transition`. That builder
calls the exact same `Builder::<DashMemo>::add_output(...)` →
`OrchardNoteEncryption::<DashMemo>::new(ovk, note, memo)` code the already-
proven shield path uses (`memo_roundtrip_tests.rs`) — shield and transfer are
not parallel implementations, they share the same output-construction code.
The memo type (`DashMemo::Memo = [u8; 36]`) is identical on both the encrypt
side (`Builder<DashMemo>`) and the decrypt side (`OrchardDomain<DashMemo>`,
`DASH_MEMO_SIZE = 36`) — a size mismatch would be a compile error, not
silent drift. The transfer builder's *change* output (back to the sender)
correctly hardcodes `[0u8; 36]` regardless of caller memo — expected, not a
bug, since the change output isn't the message-bearing one.

**Two real gaps found, worth tracking:**

1. **No dedicated test proves the transfer-builder memo path.** The only
   memo round-trip test in the vendored tree
   (`memo_roundtrip_tests.rs::shield_memo_round_trips_through_ivk_decryption`)
   exercises `build_shield_transition` (transparent → shielded), not
   `build_shielded_transfer_transition` (shielded → shielded, what
   OrchardPay actually uses for anchor-signaling transfers). Code-sharing
   with the proven path (previous paragraph) makes this low-risk, but it is
   genuinely unverified by test today. Worth adding a transfer-path
   equivalent of that test (upstream, alongside the existing one) before
   leaning on this in production.
2. **No call site in this repo currently sends a non-zero memo.** Despite
   the `memo: [u8; 36]` parameter existing end-to-end since the earlier
   memo-plumbing work, every current caller of `ShieldedTask::
   ShieldedTransfer` — `src/ui/wallets/send_screen.rs`, `src/mcp/tools/
   shielded.rs`, `tests/backend-e2e/shielded_tasks.rs` — hardcodes `memo:
   [0u8; 36]`. The contact-anchor-tagging behavior this document and
   `PROTOCOL_DESIGN.md` describe is not implemented at any caller yet; it's
   Milestone D's job to add the first real one (the anchor-signaling
   transfer in `contact_anchor.rs`).

## Implementation (2026-07-18, Milestone D)

Shipped as designed: `WalletBackend::orchardpay_scan_incoming_anchor_memos`
(`src/wallet_backend/orchardpay.rs`) re-derives the wallet's Orchard IVK
through the secret chokepoint (mirroring `ensure_shielded_bound_jit`'s
pattern) and walks `dash_sdk::platform::shielded::sync_shielded_notes_stream`
independently, calling `try_decrypt_note_with_memo` on every raw note. A
per-wallet resume cursor (`DetScope::Wallet`, not `DetScope::Identity` — the
scan is wallet-level, not identity-level) avoids re-scanning from genesis
every pass.

Triggering is automatic, not manual: `EventBridge::on_shielded_sync_completed`
(`src/wallet_backend/event_bridge.rs`) emits a new
`BackendTaskSuccessResult::OrchardPayShieldedSyncCompleted(seed_hashes)` for
every wallet whose pass just succeeded — the same "sync callback pushes a
typed result into the task-result channel" pattern DashPay's
`DetectIncomingContactPayments` already uses for incoming-payment detection
(`emit_incoming_payment_candidates`). `AppState::update` (`src/app.rs`)
picks it up and dispatches `OrchardPayTask::ScanForIncomingAnchors` for
every locally-known identity — deliberately not narrowed to "identities
belonging to this wallet," since a wrong-identity decrypt attempt fails
cheaply (see `contact_anchor::handle_incoming_anchor_signal`) and resolving
that association correctly would have added real complexity for a case that
degrades safely anyway. Skipped entirely when
`AppContext::orchardpay_contract_id()` is `None` for the active network.

## Revisiting this later

Once OrchardPay's contact/messaging feature is validated and the redundant
scan's cost is actually measured (not just theorized), option 2 becomes
worth pursuing — either as a fork we maintain or, preferably, as a real PR
upstream to `dashpay/platform` (the fix benefits any future feature that
wants incoming memo data, not just OrchardPay). Concretely, revisiting means:

- Swap the call at `rs-platform-wallet/src/wallet/shielded/sync.rs`'s
  incoming-note path (currently `try_decrypt_note`) for
  `try_decrypt_note_with_memo`.
- Add a `memo: Option<[u8; 36]>` field to `DiscoveredNote`/`ShieldedNote`
  (`rs-platform-wallet/src/wallet/shielded/store.rs`) and thread it through
  the changeset/persister so it survives a restart.
- Decide whether `ShieldedActivityEntry`'s existing `memo` field
  (`activity.rs`) should be populated from this on the incoming side too,
  for symmetry with the outgoing live-recorder path.
- Once that lands (forked or upstreamed and pulled in via a `Cargo.toml` rev
  bump), delete OrchardPay's duplicate-scan code and read memos straight off
  the wallet's own note store instead.
- Re-run the redundant-decryption cost comparison to confirm the change was
  worth it before calling this migration done.

See `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Contact establishment flow" and
the OrchardPay milestone plan for how this fits into the broader feature.
