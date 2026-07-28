# OrchardPay incoming contact requests: bug hunt and fixes

Status: **resolved (2026-07-28)** — confirmed end to end with a live
Testnet send between two identities on current code. Seven commits,
`ab30b81b`..`836174aa`.

## Summary

A user testing OrchardPay's contact-request flow reported a chain of
symptoms over one session: a `Direct Send` with an attached contact request
threw a `KeyTooLong` error after already broadcasting; the send button then
stayed stuck on "Sending…" after navigating away; and — the deepest problem
— a recipient's "Check for New Requests" never found an incoming request no
matter how long it waited or how many times the sender retried, even once
both sides were confirmed to be running identical, current code.

Each symptom had an independent root cause. The first three were UI/local-storage
bugs, straightforward once found. The last was the real prize: the
incoming-memo scan's persisted resume cursor could only ever move forward,
and a latent bug let it jump past the position of real, undecrypted notes
whenever a scan pass happened to end on an empty batch — a permanent,
self-inflicted "stuck ahead of the data" state with no error, no log line,
and no way to self-heal. Two earlier, unrelated bugs (a sidecar KV key-length
overflow, and a `$id`-query using the wrong internal value encoding) had to
be found and fixed first, because both of them were quietly producing
"document not found" results that looked identical to the cursor bug from
the outside and had to be ruled out one at a time.

## Timeline / bug chain

### 1. Sidecar KV key too long (`ab30b81b`)

**Symptom**: `Direct Send` with a contact request checked threw
`OrchardPaySidecarStorage { source: Store(KeyTooLong { len: 129 }) }` — after
the `contactAnchor` document had already broadcast successfully to Platform.

**Root cause**: `scheduled_anchor_replace_key()` (`wallet_backend/orchardpay.rs`)
built its sidecar-storage key as `<40-char prefix>:<contract_id b58>:<counterparty
b58>`. A 32-byte `Identifier` base58-encodes to up to 44 characters — the
*common* case, not an edge case — so the worst-case key was `40 + 44 + 1 + 44
= 129` characters, one over the upstream `platform_wallet_storage` crate's
hard `MAX_KEY_LEN` of 128. This is why it surfaced now and not earlier: the
`ScheduledAnchorReplace` mechanism (the delayed anchor-data replace that
hides initiator/acceptor timing, see the 2026-07-27 adversarial audit) was
brand new that same day.

**Fix**: shortened the prefix (`det:orchardpay:anchor_replace:`, 30 chars,
worst case 119 — a real safety margin, not a knife's-edge fit at exactly
128), matching the ~13-16 char margin its sibling key builders already had.
Added a regression test (`two_identifier_keys_stay_within_kv_max_len`) that
constructs the worst-case 44-char identifiers (`[0xff; 32]`, the numerically
largest possible 32-byte value, so this is a proof, not a probabilistic
check) and asserts every two-identifier key builder in the file stays under
the limit — covering the whole class of bug, not just this one instance.

### 2. "Sending…" stuck forever after navigating away (`95811341`)

**Symptom**: After a contact-request send, the "Send Friend Request" and
"Direct Send" buttons stayed on their busy label indefinitely if the user
switched to a different root screen before the (multi-round-trip, so
sometimes slow) async task finished.

**Root cause**: `app.rs`'s task-result poll loop delivers most result
variants only to `self.visible_screen_mut()` — whichever root screen the
user happens to be looking at *when the async task completes*, with no
affinity back to the screen that dispatched it. `OrchardPayScreen`'s
`contact_actions` in-flight guard only gets released inside
`display_task_result`, so if the user had navigated away, that call simply
never happened on the right screen instance.

**Fix**: this exact problem, and its fix, already existed for DashPay
(`route_contact_request_result_to_hidden_hub` /
`IdentityHubScreen::handle_contact_request_result`) — mirrored it for
OrchardPay. Extracted the guard-release logic into
`OrchardPayScreen::handle_contact_send_result(&result) -> bool` (borrows
instead of owning, so it's callable from outside `display_task_result`), and
added `route_orchardpay_result_to_hidden_screen` in `app.rs`, called
unconditionally alongside the existing DashPay call, which forwards the
result straight to the `OrchardPayScreen` instance in `main_screens` when it
isn't the currently-visible screen.

### 3. "Check for New Requests" was completely silent (`cc30b398`, `1933e00c`)

**Symptom**: not yet a specific bug — a diagnosability gap that made
everything after it much harder to debug. Clicking the button gave zero
feedback in every outcome: nothing found, found-but-unmatched, and a
genuine processing error all looked identical (no banner, and — for two of
the three cases — no log line either).

**What was added, not fixed**: `OrchardPayIncomingAnchorsScanned` gained
`anchor_signals_seen` / `anchor_signals_claimed` / `anchor_signals_still_unresolved`
counts, `scan_for_incoming_anchors` logs an info-level summary every pass,
and (later disabled, see below) the click surfaced a banner distinguishing
the three outcomes. A second pass (`1933e00c`) tagged every silent
early-return inside `handle_incoming_anchor_signal` with a `reason` (
`document_not_found`, `own_anchor`, `data_field_missing`,
`no_bound_decryption_key`, `aead_decrypt_failed`, `already_tracked`) — the
five branches that can each produce a clean "not applicable," previously
indistinguishable from outside.

**Also fixed in `cc30b398`, found while in this code**: `own_bounds_verified_key`
picked the first `BTreeMap`-order match on purpose + contract-bounds,
which could resolve a stale/disabled key if an identity ever ends up with
more than one bound key of the same purpose (e.g. after rotating a published
shielded address). Changed to filter out disabled keys and prefer the
newest match. Not the active cause of anything in this session (confirmed:
the affected identity had published exactly once), but a real latent defect
worth fixing while already auditing this function.

**Why this mattered**: every subsequent step in this investigation depended
on being able to see *which* of several indistinguishable failure modes was
actually happening. Without this, the rest of the hunt would have been pure
guesswork.

### 4. The `$id` query silently never matched (`26c1e1ad`)

**Symptom**: with diagnostics from step 3 in place, a live repro showed the
same 2 anchor signals decrypted every scan pass, 0 claimed, and — critically
— zero `Err`-level output anywhere. `fetch_anchor_document_by_id` was
cleanly returning "not found" for document IDs that, per the *sender's* own
"Recover from Network" (a different, working query), definitely existed on
Platform.

**Root cause**: `fetch_anchor_document_by_id` built its own `$id`-equality
`WhereClause` by hand:
```rust
value: Value::Identifier(document_id.to_buffer())
```
The SDK's own dedicated helper for this exact operation,
`DocumentQuery::with_document_id()` (already used correctly elsewhere in
this repo, in DashPay's `contact_requests.rs`), instead builds the value via
`platform_value!(document_id)`, which expands to a **serde-based**
conversion (`to_value(&document_id)`) — not the direct `From<&Identifier>
for Value` impl. Traced through the vendored SDK source:
`platform_value`'s serializer reports `is_human_readable() == false`, so
`Identifier`'s `Serialize` impl takes the raw-bytes branch
(`serializer.serialize_bytes(&self.0)`), and that serializer's
`serialize_bytes` for an exactly-32-byte input produces
**`Value::Bytes32([u8; 32])`** — not `Value::Identifier([u8; 32])`. Same 32
bytes, different enum variant, and `Value` has no custom cross-variant
equality (`#[derive(PartialEq)]`).

Crucially, this mismatch doesn't affect every field equally: Drive's query
engine (`rs-drive/src/query/mod.rs`, `WhereClause::is_identifier()`) routes
`$id`-equality clauses into a separate `primary_key_equal_clause` bucket,
distinct from the generic `equal_clauses` path every other indexed field —
including `$ownerId` — goes through. That's why the sibling `$ownerId` query
in `fetch_own_anchors`, using the *exact same* `Value::Identifier(...)`
construction, had always worked fine, and was the reason this specific bug
survived unnoticed: the identical-looking pattern was correct everywhere
else it was used.

**Fix**: switched to `DocumentQuery::with_document_id(&document_id)` +
`Document::fetch` (singular; returns `Option<Document>` directly, dropping
the now-unneeded `IndexMap` collapse), matching the proven DashPay pattern
exactly.

**A wrong turn worth recording**: fixing this alone did *not* resolve the
live repro. The two stuck signals kept failing identically after the fix
shipped (verified via binary checksum + process-start-time that the fix was
genuinely running). This led to a real, if ultimately unnecessary, scare:
the user independently looked up one of the "document IDs" on an explorer
and found it was actually the *sender's own identity ID* — raising a serious
concern that the `their_reference_id` filler mechanism (from the same day's
earlier "remove the pending-vs-established anchor timing signal" work,
`2a7b8a78`) had leaked into the wrong field. A careful line-by-line re-read
of both `initiate_contact` and `accept_contact`'s memo-construction code
confirmed current code was clean — the filler is confined to the encrypted
`anchorData.their_reference_id` field and never reaches the plaintext memo.
The corrupted memo turned out to be an artifact of the sender's identity
running an outdated build during earlier testing, not a bug in current
code — resolved by having the sender rebuild and send fresh.

### 5. The real root cause: a scan cursor that could only advance (`b0666921`, `dfd99d84`)

**Symptom**: sender rebuilt on current code and sent a fresh request.
Recipient's Shielded Txs tab showed the new transaction as confirmed and
correctly tagged "Contact request signal" — proof the wallet's own routine
note sync saw it fine. But "Check for New Requests" still only ever
reported the same 2 old (now-understood-to-be-poisoned) signals. No third
signal ever appeared, no matter how long the wait.

**Diagnosis**: added a second logging layer inside
`orchardpay_scan_incoming_memos` itself (not just the downstream
anchor-matching step) — its own `start_index`/`next_start_index` and how
many notes it examined/decrypted. First result:
```
start_index=3829760 next_start_index=3854336 notes_examined=0 notes_decrypted=0
```
The persisted cursor was sitting at a position in the millions, finding
nothing there, and still advancing further into empty territory on every
pass.

**Root cause**: `orchardpay_scan_incoming_memos` computed its persisted
resume cursor by unconditionally overwriting `next_start_index` on *every*
batch from the stream, including trailing empty ones:
```rust
next_start_index = if batch.is_partial {
    batch.start_index
} else {
    batch.start_index + batch.notes.len() as u64
};
```
`sync_shielded_notes_stream`'s sliding window naturally produces some empty
batches while draining near the current chain tip. Whenever a scan pass
happened to end its processing on one of those, the persisted cursor jumped
to that empty batch's position — and because the cursor only ever moves
forward, it could never recover. Every later scan started from that
inflated position and permanently skipped the region where real notes
actually were, including this new incoming signal.

The fix was found by comparing against the SDK's *own* proven algorithm for
this exact problem: `sync_shielded_notes` (the one-shot convenience wrapper
around the same stream, in the vendored `rs-sdk` source) tracks the **last
non-empty** batch across the whole pass, and only resumes from it if that
batch was itself partial (i.e. still possibly growing) — explicitly
documented in its own comments as ignoring "trailing empty chunks from the
still-draining sliding window." Our code did neither.

**Fix**: mirrored that exact algorithm — track `last_nonempty: Option<(u64,
bool)>`, updated only when a batch is non-empty, and compute
`next_start_index` from it after the loop instead of inside it. Minimal
diff: no change to the decrypt/tag-extraction logic, no signature or caller
changes.

**Recovery**: fixing the computation doesn't retroactively repair an
already-inflated persisted cursor (it can only move forward). Decided
against adding a reset mechanism to the app (a one-time recovery from a bug
that, once fixed, can't recur again didn't seem worth new UI surface) — the
recipient instead cleared local config and reloaded the wallet from its
12-word phrase, which rebuilds the cursor from 0 along with everything else.

**Verification**: rebuilt, wallet reset, fresh send from the sender.
Resulting log:
```
incoming memo scan (note-level) pass complete start_index=0 next_start_index=0
    notes_examined=2454 notes_decrypted=14 anchor_or_payment_signals_found=6
incoming anchor scan pass complete anchor_signals_seen=4 anchor_signals_claimed=2
    anchor_signals_still_unresolved=2
```
Two real anchor signals claimed. The remaining 2 unresolved are the
original poisoned signals from the sender's old build — permanently
unmatchable (they don't reference real documents), harmless, and expected.

### 6. Banner disabled (`836174aa`)

The result banner added in step 3 (distinguishing "nothing new" / "found N"
/ "found but unmatched") was disabled per request after the investigation
concluded — not wanted surfaced to users for now. The underlying counts and
the `tracing::info!` summary log in `scan_for_incoming_anchors` were kept
as-is; they're what actually did the diagnostic work and remain useful.
Re-enabling is a small, self-contained change: restore the `msg`/
`message_type` computation and the `MessageBanner::set_global(...)` call in
`app.rs`'s `OrchardPayIncomingAnchorsScanned` handler (removed in
`836174aa`; the git history has the exact prior text).

## The investigation method

Worth recording explicitly, since the pattern is reusable well beyond this
bug:

- **Add diagnostics before guessing at fixes, then let each layer of
  logging pose the next, more specific question.** Blind first: no error,
  no log line, nothing to reason from. Layer 1 (counts + a summary log)
  turned "nothing happens" into "2 signals decrypted, 0 claimed, no
  errors" — already enough to rule out several hypotheses. Layer 2
  (per-`reason` tagging inside the matching function) turned that into
  "always `document_not_found`" — a specific, checkable claim. Layer 3
  (logging the note-scan's own range) turned "the document doesn't exist"
  into "the scan isn't even looking at the right region" — the actual
  answer. Each step was a small, low-risk, additive change; none of them
  guessed at a fix before having evidence for what to fix.
- **Cross-check against a known-working sibling instead of reasoning about
  the SDK in the abstract.** The `$id`-query bug was found by comparing
  against DashPay's `contact_requests.rs` (a working example of the exact
  same "fetch one document by ID" operation in this same repo) and the
  cursor bug was found by comparing against the SDK's own
  `sync_shielded_notes` one-shot wrapper (a working example of the exact
  same stream-consumption pattern, in the vendored dependency source). Both
  times, the working reference made the defect obvious by contrast in a way
  that reading the broken code in isolation hadn't.
- **Rule out confounds one at a time, explicitly, before trusting a
  root-cause theory.** Wallet topology (same vs. separate wallets), key
  rotation history, contract redeploys, and a sender/recipient code-version
  mismatch were each raised as plausible explanations and checked directly
  with the user rather than assumed — several were live possibilities that
  turned out not to apply, and ruling them out (rather than skipping past
  them) is what kept the later, real findings credible.
- **A user's raw memory of "we touched something like this recently" is
  worth a direct re-audit, even when confident the current code is
  clean.** The "is my identity ID showing up as a document ID?" concern
  (step 4) turned out not to be a current-code bug, but re-reading both
  `initiate_contact` and `accept_contact` line-by-line to check was cheap
  and the alternative — dismissing it without checking — would have been a
  bad trade against the cost of being wrong.

## What's still open / follow-ups not taken

- **The banner is off.** See step 6 for how to bring it back if wanted
  later.
- **`OrchardPayScreen::handle_contact_send_result` matches the generic
  `BackendTaskSuccessResult::BroadcastedDocument`**, not an OrchardPay-specific
  variant, so it also fires (harmlessly — a cheap no-op) for unrelated
  document broadcasts elsewhere in the app while OrchardPayScreen is the
  hidden root screen. Pre-existing imprecision (it already fired for the
  *visible*-screen case before this session), slightly widened by the
  hidden-screen routing fix in step 2. Not worth a fix on its own; noted
  for anyone touching this function next.
- **The two poisoned anchor signals from the sender's old build stay
  permanently unresolved** on that specific wallet unless it's reset again
  — expected and harmless, but worth knowing if they ever show up in a
  support question ("why does the log always mention these two IDs").
- **No automatic detection for a cursor that's drifted ahead of real data**
  was added. The fix stops new drift from happening; it doesn't add
  monitoring to catch a similar class of bug faster if one is ever
  reintroduced elsewhere in this scan. Considered and deliberately not
  built — would be speculative infrastructure for a problem that, per the
  fix, shouldn't recur.
