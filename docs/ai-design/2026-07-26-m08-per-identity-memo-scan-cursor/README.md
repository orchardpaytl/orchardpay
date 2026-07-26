# M-08: Memo-scan cursor can permanently miss a signal for a not-yet-loaded identity

Status: **implemented**. One of three independent follow-ups to
`docs/ORCHARDPAY_COMPREHENSIVE_REVIEW_2026-07-25.md` — see
`docs/ai-design/2026-07-26-comprehensive-review-response/README.md` for how
this relates to the other two (M-02, M-05).

The design below was revised mid-review from the original proposal (a
per-identity resume cursor) after tracing the actual scan code — see
"Why not a per-identity cursor" for what changed and why.

## The problem, confirmed against current code

`orchardpay_scan_incoming_memos` (`src/wallet_backend/orchardpay.rs`)
walks the wallet's shielded notes from a persisted resume cursor, and
`scan_for_incoming_anchors` (`src/backend_task/orchardpay/memo_scan.rs`)
tries each detected `Anchor` signal against every identity in whatever
`qualified_identities` list was passed in for *that* call.

The cursor is keyed per wallet, not per identity
(`orchardpay_get_memo_scan_cursor`/`orchardpay_set_memo_scan_cursor`,
`DetScope::Wallet(seed_hash)`). Before this fix: if a signal didn't match
*any* currently-loaded identity and no error occurred, the loop didn't hold
`retry_from` back for it — the shared cursor advanced past that note and
the signal was simply discarded. If a new OrchardPay identity was created
or loaded into the wallet *later*, and that note's signal was actually
meant for it, it was gone for good — the cursor had already moved on, and
nothing re-walked notes before it regardless of which identities were
passed into a future scan call.

The opposite failure mode also existed and was already partially handled:
`had_error` cases *did* hold `retry_from` back indefinitely — good for
recoverability, but the review also flagged that this can wedge all
*later* signals behind one persistently-failing one, since `retry_from`
always takes the minimum position across every signal in the batch.

## Why not a per-identity cursor

The original proposal here was a resume cursor keyed by `(wallet,
identity)` instead of just `wallet`, with a full rescan-from-zero for each
newly-loaded identity. Tracing `orchardpay_scan_incoming_memos` before
implementing anything revealed why that would have been the wrong fix:

The note-stream decrypt pass is **genuinely wallet-level, not
identity-level**. It derives exactly one Orchard viewing key from the
wallet seed (`OrchardKeySet::from_seed(seed, network, 0)`) and trial-
decrypts every note in the stream with that single key — this has nothing
to do with which identities exist. The identity match happens *after*, in
`scan_for_incoming_anchors`, against an already-decrypted signal.

A per-identity cursor would have forced that expensive, wallet-level
decrypt pass to repeat once per identity (a full historical re-walk of the
note stream, with real network and decrypt cost that grows with wallet
history) even though decryption was never identity-specific to begin with.
That's not "a bit more CPU" — it's a redundant full chain-scan per
identity, for a step that only ever needed to run once per wallet.

## Implemented fix: persist unmatched anchor signals, retry the match step only

Rather than re-running the wallet-level decrypt pass per identity, an
`Anchor` signal that doesn't match any currently-loaded identity is now
persisted (its document ID only — the decrypt work is already done and
never needs repeating), and retried against the identity-match step alone
on every subsequent scan pass. This closes the same gap as the original
proposal, with no redundant note-stream decrypt or re-fetch cost:

- `src/wallet_backend/orchardpay.rs`: new `KV_PREFIX_UNRESOLVED_ANCHOR`
  (`DetScope::Wallet`, key shape
  `det:orchardpay:unresolved_anchor:<document_id_b58>`), with
  `orchardpay_list_unresolved_anchor_signals`,
  `orchardpay_record_unresolved_anchor_signal`, and
  `orchardpay_clear_unresolved_anchor_signal`.
- `src/backend_task/orchardpay/memo_scan.rs`: `scan_for_incoming_anchors`
  now retries every persisted unresolved anchor against the current
  `qualified_identities` list *before* processing this pass's freshly
  decrypted signals (via a shared `try_anchor_against_identities` helper).
  A match clears it from the unresolved list; no match leaves it recorded,
  to be retried again next pass. This is off the resume cursor's critical
  path entirely, so it can never block scanning — an anchor meant for
  nobody currently loaded costs one cheap identity-match attempt per pass,
  forever, which is acceptable since unmatched anchors are rare (bounded by
  how many contact requests arrive before their target identity exists).
- A freshly-decrypted `Anchor` signal that matches nobody this pass is now
  recorded via `orchardpay_record_unresolved_anchor_signal` instead of
  being dropped, and the cursor advances past its note normally (the
  signal's content is already captured; there's nothing left to re-decrypt
  it for).

## Quarantine for persistent processing errors (the review's second failure mode)

Implemented as originally proposed, unchanged by the above revision:

- New `KV_PREFIX_MEMO_SCAN_RETRY_COUNT` (`DetScope::Wallet`, keyed by note
  index) with `orchardpay_get_memo_scan_retry_count`,
  `orchardpay_increment_memo_scan_retry_count`, and
  `orchardpay_clear_memo_scan_retry_count`, plus a
  `MEMO_SCAN_ERROR_RETRY_CAP` constant (`5`).
- `scan_for_incoming_anchors` increments a note's retry count on a genuine
  processing error (`had_error` — a real failure, not "wrong identity") and
  holds the resume cursor back for it, same as before, but only up to the
  cap. Past the cap, it logs a warning, clears the counter, and lets the
  cursor advance past that note — so one persistently-failing signal can no
  longer wedge every later signal behind it forever. Applied uniformly to
  both `Anchor` processing errors and `Payment`-cache write failures.

`orchardpay_clear_wallet_overlays` (the sweep run on wallet removal) was
extended to clear both new prefixes alongside the existing cursor and
verified-payment-cache sweep — see its updated doc comment.

## Trade-off accepted

Unmatched anchors are retried against every currently-loaded identity on
every scan pass, with no "already tried this identity, skip" tracking —
deliberately simple, since an identity's OrchardPay setup (its
contract-bound DECRYPTION key) could itself appear after the anchor
already failed once, so skipping "already-tried" pairs would risk missing
that legitimate case. This is accepted as cheap in practice because
unmatched anchors are expected to be rare and the list naturally stays
small — not the unbounded, ever-growing cost the per-identity-cursor design
would have had.

## Verification

- Unit tests added in `src/wallet_backend/orchardpay.rs`:
  `unresolved_anchor_signal_round_trips`,
  `unresolved_anchor_signals_are_wallet_scoped`,
  `memo_scan_retry_count_increments_and_clears`,
  `wallet_overlays_sweep_clears_unresolved_anchors_and_retry_counts`.
- `cargo test --all-features orchardpay` (62 passed), `cargo clippy --bin
  orchardpay --all-features -- -D warnings` (clean), `cargo fmt --all`.
