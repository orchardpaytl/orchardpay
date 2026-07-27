# Response to the 2026-07-25 comprehensive security and zero-knowledge review

Tracks this project's disposition on every finding in
`docs/ORCHARDPAY_COMPREHENSIVE_REVIEW_2026-07-25.md` (reviewed at commit
`aa70924d`), cross-checked against `git diff aa70924d..HEAD` rather than
assumed from memory. Three findings (M-02, M-05, M-08) have their own
separate, independently-decidable design docs linked below — this file
does not resolve them, only tracks that they're open and where their
proposals live.

## H-01 — message forgery via missing `$ownerId` check

**Resolved** in `bda6f0e7`: `fetch_messages_by_ref_id` now filters both the
"mine" and "theirs" buckets to documents actually owned by the expected
identity before decryption, closing the forgery/replay path the review
describes.

### Decision: no compound `($ownerId, refId, $createdAt)` index

The review's fix list also asked for a new three-field compound index, on
the grounds that query-side owner binding is "needed to prevent an
attacker from filling the first result page with wrong-owner documents."
This project's decision is **not to add that index** — the client-side
`$ownerId` filter already fully closes the security property the index
would have protected (a forged/replayed message can never be trusted or
displayed, regardless of which page it lands on), and every Platform index
carries a permanent per-document creation-fee and per-write cost, paid by
every single document ever created under this contract, forever.

Optimizing for a low-frequency, self-defeating griefing scenario (the
attacker pays their own document-creation cost per decoy, for a payoff
that's now nothing more than a few extra clicks) at the expense of raising
the cost floor for every legitimate user's every future message is the
wrong trade. This is the same reasoning behind the project's separate,
already-tracked decision to drop the confirmed-unused `byOwnerIdAndCreated`
index rather than keep paying for it — see
`project_orchardpay_contract_planned_changes` in this assistant's memory
and the "Not yet done" section of `docs/orchardpay/PROTOCOL_DESIGN.md`.
Lower per-document cost for the many is prioritized over marginal
convenience for the few, in the spirit of Jevons's paradox: making an
already-solved problem "more efficient" to query doesn't reduce total
system cost, it just shifts a permanent tax onto every future write in
exchange for closing a residual that was never a security gap to begin
with.

To put a number on it: traced against the pinned `platform`/`drive`/`grovedb`
source (rev `288a6ca`) and its real fee constants (`FEE_STORAGE_VERSION1`:
27,000 credits/byte storage, 400 credits/byte processing, 2,000
credits/seek; 1 DASH = 10^11 credits per this project's own
`MIN_SEND_AMOUNT_CREDITS`), an index's per-field tree overhead dwarfs
ordinary field storage by roughly two orders of magnitude:

| Cost source | Per-document, per-write | Order of magnitude |
|---|---|---|
| An unused optional field's presence byte (e.g. `encryptedMessage`'s `extra` field, `contract_schema.json:94-100` — declared, never populated, still taxed) | ~27,400 credits ≈ 0.00000027 DASH | baseline |
| One extra *indexed* field's tree-level overhead (property-name tree + value tree + seek, per `add_indices_for_index_level_for_contract_operations_v1`) | ~1.7–2.6 million credits ≈ 0.000017–0.000026 DASH | ~60–95x larger |

The takeaway: an unindexed field sitting in a schema, even permanently
unused, is close to free. Index structure is where the real, compounding,
forever-recurring cost lives — confirming that indexing is exactly the
right thing to be economizing on, and unused schema fields are not worth
the same scrutiny.

**Timing**: not implemented yet. The `byOwnerIdAndCreated` drop stays
bundled with the already-planned `shieldedAddress` field widening, both
landing together before Mainnet/Devnet contract registration, rather than
as a one-off schema edit now.

**Accepted residual risk**: a counterparty willing to pay Platform's own
per-document publish cost can still flood a conversation's result page
with wrong-owner decoys, forcing extra "See more conversation history"
clicks before reaching real messages. This never hides or loses a real
message — `messages::fetch_messages_by_ref_id`'s `has_more` is computed
from the raw, pre-filter batch size specifically so a decoy flood can't
make a genuinely-full page look exhausted. The residual is bounded,
self-funded by the attacker, and accepted as a low-severity inconvenience
rather than a security defect.

### Addendum (2026-07-27): decision reversed

This project has reversed course and added the compound index after all —
`byReferenceIdbyOwnerIdAndCreated`: `refId asc, $ownerId asc, $createdAt asc`,
replacing both `byReferenceIdAndCreated` and `byOwnerIdAndCreated`.
`messages::fetch_messages_by_ref_id`/`fetch_latest_message_created_at` now
filter by `$ownerId` in the query itself (an equality clause matching the
index's declared field order), eliminating the client-side post-fetch
filter and its residual entirely — a wrong-owner decoy is never fetched in
the first place, so it can no longer occupy a result-page slot at all.

Because a registered Platform contract's indices can only be *added*, never
removed or altered (confirmed directly against `rs-dpp`'s
`IndexLevel::validate_update`), this was deployed as a brand-new Testnet
contract registration rather than an update to the existing one — see
`docs/ORCHARDPAY_MIGRATION.md` for the new contract ID and
`docs/orchardpay/PROTOCOL_DESIGN.md`'s `encryptedMessage` section for the
full before/after.

The cost-tradeoff reasoning above remains accurate and is not being
retracted — the per-document index-write cost this decision originally
declined to pay is real and is now being paid on every future
`encryptedMessage` write, forever. The index was added anyway based on a
reassessment of priorities (closing the residual outright was judged worth
that permanent cost), not a correction of the prior analysis.

The review's other three H-01 asks — a versioned envelope with KDF-derived
keys and associated authenticated data, and adversarial tests for
wrong-owner ciphertext/replay/page-flooding — are still open. The envelope
redesign is folded into M-05's design doc (linked below) since they're the
same underlying change; the adversarial tests are not yet written anywhere
in this codebase (`messages.rs` currently has zero `#[test]`s).

### Addendum (2026-07-27, later): adversarial tests declined

Decision: **not writing the four adversarial tests.** The specific mechanism
they'd exercise (a counterparty forging a document under their own identity
but tagged with the victim's `refId`, landing in the wrong bucket) is already
closed by the query-side `$ownerId` fix above — Platform's own document
signature verification means an attacker can never set `$ownerId` to the
victim's identity, and both query buckets now require the correct owner
before a document is even fetched. Proving this holds against *live*
Platform query enforcement would require new backend-e2e infrastructure (a
`shared_orchardpay_pair()` fixture: two funded, DPNS'd, fully
contactAnchor-established identities) — real cost for re-confirming a
property the fix already guarantees by construction, not for catching
anything currently broken.

One narrower residual was identified and is **explicitly accepted, not
tested**: an established counterparty can still re-broadcast one of their
*own* previously-sent, genuinely-owned ciphertext as a new document (same
true `$ownerId`, same true `refId`, copied `msgData`, new document ID) — the
`$ownerId` check can't help here since ownership is genuine. This could make
an already-fulfilled `PaymentRequest` look unfulfilled again in the
recipient's thread. Low severity (the real transferred amount is still
independently verified against the decrypted shielded note, per the
existing amount-trust model; this is a UI/thread-confusion nuisance, not a
funds-redirection or impersonation path) and distinct from what H-01 or its
four named tests were actually about. No action planned.

## H-02 — mutable `@main` GitHub Action with secrets and OIDC authority

**Resolved** in `502f6568`/`d5976eb2`: every third-party action pinned to a
reviewed commit SHA, `id-token: write` dropped from the review job,
CODEOWNERS added for `.github/workflows/`/`.github/actions/`, Dependabot
added for the `github-actions` ecosystem.

## M-01 — thread and recovery queries silently capped at 100 documents

**Resolved** in `cee71857` (message threads: `$createdAt`-cursor pagination,
descending order, "See more conversation history" button) and `6f7bc265`
(contactAnchor recovery: `$id`-cursor pagination, up to 400 documents
automatically, no button — `byOwner` has no `$createdAt` component to page
on, so recovery uses a document-ID cursor instead, which needs no order
guarantee since recovery already treats anchor order as irrelevant).

**Gap, same-`$createdAt` collision — fixed (2026-07-27).** Investigated
after the user asked whether this gap was real or just a test suggestion:
confirmed genuinely exploitable, not theoretical. `rs-drive`'s
document-creation transformer stamps `$createdAt` from block time, not a
per-document clock, so two of the same identity's own `encryptedMessage`
documents (same `refId`, same `$ownerId` — an entirely ordinary occurrence,
e.g. two chat messages sent seconds apart landing in the same block) get
the identical timestamp. If that shared timestamp fell exactly at the
100-document page boundary, the documents Drive's `LIMIT` happened to
exclude were permanently unrecoverable: excluded from the current page by
the limit, and excluded from the next page's `$createdAt < cursor` clause
(equal, not less than). Fixed in `fetch_messages_by_ref_id`
(`messages.rs`) via a new `trim_ambiguous_tail` helper: the trailing run of
documents sharing a full page's minimum timestamp is always held back for
the next page — even when it's currently visible as a single document,
since one page's data can never prove a boundary timestamp is truly unique
versus having siblings the limit's tie-break ordering placed just past the
cutoff. Pure client-side fix, no contract/index change; the *other*
pagination path (contactAnchor recovery, document-ID cursored) was already
immune, since document IDs can't collide. 5 new deterministic unit tests
(no network needed — this is pure computation over an already-fetched
list), covering the exact collision case plus the pathological "entire page
tied" fallback.

**Gap, 99/100/101/200-count boundary tests — still open.** A distinct,
lower-severity concern (a potential off-by-one in the `has_more`/limit
check itself, not data loss) for either pagination path. Not yet written.

## M-02 — multi-step contact/payment flows aren't atomic

**Resolved.** `initiate_contact`/`accept_contact` still publish-then-transfer-
then-write-local-state, but now persist a local recovery marker before the
first network side effect and reuse it on retry — no more orphaned
duplicate anchors, and no risk of double-sending the signaling transfer.
`send_payment`'s standalone path does the same for the `Payment` document,
but deliberately does not auto-resume (returns a distinct
`OrchardPayPaymentRecoveryNeeded` error instead) since silently resending
real funds is a different risk profile than a free-to-retry contact
handshake. A fully modeled per-document lifecycle (the review's original
ask) remains out of scope — this is the narrower local-recovery fix. See
the design doc for the full implementation:
`docs/ai-design/2026-07-26-m02-atomic-contact-payment-flows/README.md`.

## M-03 — Tier-1 unprotected wallet storage is the default

**Out of scope for OrchardPay.** This is DET's whole secret-storage
architecture (`wallet_backend/single_key.rs`, the Tier-1/Tier-2 scheme
documented in `CLAUDE.md`), applying to every wallet in the app regardless
of feature — not something OrchardPay's own protocol controls or should
change unilaterally.

## M-04 — remote MCP exposure uses plaintext HTTP

**Out of scope for OrchardPay.** DET's general MCP server
(`src/mcp/config.rs`, `src/mcp/mod.rs`) is shared infrastructure for every
feature's MCP tools, not an OrchardPay-specific surface.

## M-05 — no forward secrecy or transcript-bound key schedule

**Accepted risk, deferred (2026-07-27).** Confirmed unchanged:
`generate_ecdh_shared_key` (`dashpay/encryption.rs`) derives the AES key as a
single `SHA256(prefix || x)` over the raw ECDH point, no HKDF, no context
binding; `encrypt`/`decrypt` (`orchardpay/encryption.rs`) pass no associated
authenticated data to AES-GCM at all. Full proposal and rationale:
`docs/ai-design/2026-07-26-m05-message-envelope-and-forward-secrecy/README.md`
(see its 2026-07-27 addendum for the disposition below).

The proposal bundled three independent pieces; each was assessed on its own
merits rather than accepted or declined as a block:

- **HKDF/purpose-splitting a static per-relationship secret into labeled
  sub-keys — declined.** No live confusion risk exists to close:
  `anchorData` already uses a wholly separate key (the wallet-local fixed
  key, not the relationship ECDH secret at all), and the only real overlap
  — `contactAnchor.data` vs. `encryptedMessage.msgData` sharing today's
  single derived key — decodes into different Rust structs, so a ciphertext
  moved between them would decrypt fine and then almost certainly fail to
  parse as the wrong type. Real value, but purely speculative (insurance
  against a future schema change making those structs more alike), not
  worth the crypto-surface churn now.
- **AAD (binding `refId`/owner/message-type/etc. into the AES-GCM tag) —
  declined for now, real but redundant.** This is an integrity/authenticity
  control, not a privacy one — it doesn't hide anything, it makes a
  ciphertext moved into the wrong context fail to decrypt. Its actual value
  is as an independent regression guard over the H-01 fix (if a future
  refactor ever weakens the `$ownerId` query filter, AAD would still catch a
  moved/replayed ciphertext) — genuine, but redundant with a fix that's
  already sufficient on its own. Tracked as a future roadmap possibility,
  not active work.
- **Forward secrecy itself (a real ratchet — new key material per message,
  so a compromised key can't decrypt past messages) — this is the one piece
  with actual, non-redundant value**, and it's also the one thing this
  proposal, as scoped, never delivered: splitting one static secret into two
  labeled static sub-keys provides *no* forward secrecy at all — a leaked
  ECDH secret still decrypts the whole relationship's history either way.
  A real fix needs an actual ratchet, which the original proposal already
  flagged as substantially bigger (session state, out-of-order message
  handling, a real UX question about lost ratchet state on reinstall/
  multi-device) and deliberately left undecided. Tracked as a future roadmap
  possibility, alongside AAD but sized and prioritized separately — a real
  ratchet is a much larger design effort than AAD, not a bundled pair.

## M-06 — lockfile contains known advisories and unmaintained crates

**Out of scope for OrchardPay.** One `Cargo.lock` for the whole
application; unrelated to the OrchardPay protocol itself.

## M-07 — GroveSTARK verifier lacks a challenge/state-root policy

**Out of scope for OrchardPay.** The review's own words: "GroveSTARK is
separate from the Orchard shielded payment system." It's a standalone
research tool under Tools (`backend_task/grovestark.rs`,
`ui/tools/grovestark_screen.rs`), already labeled research-only/unaudited
in its own UI — not part of OrchardPay's contact/messaging/payment
protocol.

## M-08 — memo-scan cursor can permanently miss a signal for a not-yet-loaded identity

**Resolved.** The resume cursor itself stays wallet-scoped (correct — the
note-decrypt pass is genuinely wallet-level, one shared Orchard viewing
key, not per-identity), but an `Anchor` signal that matches no
currently-loaded identity is now persisted (`KV_PREFIX_UNRESOLVED_ANCHOR`)
and retried against the identity-match step on every later scan pass,
instead of being silently dropped when the cursor advances past its note.
A separate retry-cap/quarantine mechanism
(`KV_PREFIX_MEMO_SCAN_RETRY_COUNT`, `MEMO_SCAN_ERROR_RETRY_CAP = 5`) stops
a persistently-erroring signal from wedging every later signal behind it.
The original proposal (a per-identity resume cursor with a full rescan per
new identity) was revised before implementation — tracing the actual scan
code showed the decrypt pass is wallet-level, so a per-identity cursor
would have forced a redundant full historical re-decrypt per identity for
no reason. See the design doc for the full before/after:
`docs/ai-design/2026-07-26-m08-per-identity-memo-scan-cursor/README.md`.

## L-01 — recovery and privacy claims need narrower wording

**Partially stale, mostly still open.** The README changed since the
review (`53b6910b`), but for unrelated reasons (Direct Send, payment
framing) — the specific claims the review flagged (recovery doesn't cover
unaccepted inbound requests; Platform observers still see owner IDs,
reference IDs, timing, and counts) are still unaddressed in the README
text. The 100-anchor cap concern it also raised is now moot — recovery
covers up to 400 (M-01).

## L-02 — positive-amount checks not enforced at the backend boundary

**Resolved**, and exceeded — `1f73b575` added
`model::orchardpay::validate_send_amount`, enforced authoritatively in
`send_payment`, `send_payment_request`, `direct_send::send_direct`, and
`contact_anchor::initiate_contact`. The review asked for `amount > 0`; the
shared floor is `>= 0.001 DASH`, a strictly stronger guarantee.

## L-03 — CI has a false-red lint job and disabled live E2E coverage

**Partially resolved.** `clippy.yml` no longer uses the archived
`actions-rs/clippy-check@v1` reporting action — replaced with a plain
`cargo clippy --all-features --all-targets -- -D warnings` run step
(`502f6568`). The backend E2E lane in `tests.yml` is still commented out,
pending the `TaskError` migration noted in its own TODO — unchanged.

## L-04 — public security governance is incomplete

**Partially resolved.** `.github/CODEOWNERS` and `.github/dependabot.yml`
now exist (`502f6568`/`d5976eb2`), covering `.github/workflows/` and
`.github/actions/` ownership. No `SECURITY.md` exists anywhere in the tree
— still open, and CODEOWNERS doesn't yet cover wallet/cryptography/protocol
schema/MCP paths the review specifically recommended.

## Summary

| Finding | Status |
|---|---|
| H-01 | Resolved (owner check, now query-side via a compound index — see 2026-07-27 addendum, reversing the earlier no-new-index decision); envelope redesign → M-05; adversarial tests explicitly declined (2026-07-27) — query-side fix already closes the exercised mechanism |
| H-02 | Resolved |
| M-01 | Resolved; same-`$createdAt` collision confirmed real and fixed (2026-07-27, `trim_ambiguous_tail`); 99/100/101/200-count boundary tests still missing |
| M-02 | Resolved — see linked design doc |
| M-03 | Out of scope (DET-wide) |
| M-04 | Out of scope (DET-wide) |
| M-05 | Accepted risk, deferred (2026-07-27) — HKDF/purpose-splitting and AAD declined as insufficient value now; forward-secrecy ratchet is the one substantive piece, tracked as a future roadmap item, not this review's scope — see linked design doc |
| M-06 | Out of scope (DET-wide) |
| M-07 | Out of scope (separate tool, not OrchardPay) |
| M-08 | Resolved — see linked design doc |
| L-01 | Mostly open (100-cap concern moot) |
| L-02 | Resolved, exceeded |
| L-03 | Partially resolved (lint fixed; E2E lane still disabled) |
| L-04 | Partially resolved (CODEOWNERS/Dependabot added; no SECURITY.md) |
