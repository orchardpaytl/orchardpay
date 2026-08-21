# OrchardPay — Adversarial Conversation Audit (2026-07-27)

Status: **implemented (2026-07-28); re-audited (2026-08-21), see addendum
below — 4 new findings (8-11), all shipped as code fixes the same day.**
All seven
confirmed-exploitable findings and four low-severity findings from the
original pass reached agreed remediation designs (see the `Resolution`
block under each), then were cross-checked holistically (see the bottom
section) before any code was touched. Of the seven confirmed-exploitable
findings, five (1, 2, 3, 5, 7) shipped as code fixes in `7aa61dbc`
(spoofed-payment headline, flood-tolerant message loading, bidi/zero-width
sanitization, ciphertext-length padding) and `2a7b8a78` (pending-vs-established
anchor timing signal); two (4, 6) were accepted as architectural limitations
with no code fix, per their own `Resolution` sections. Of the four
low-severity items, two shipped in `7aa61dbc` (defensive encrypt-layer size
cap, reused flood/decode-failure notice) and two were deliberately left
as-is, per their own `Resolution` sections. Follow-up work should be tracked
as further dated addendums to this file or new entries in
`docs/ai-design/2026-07-26-comprehensive-review-response/README.md`, per this
repo's established convention (see that doc for the H-01/L-01/M-01/M-05
findings this audit builds on).

## Scope

Requested: "audit OrchardPay if you were an adversary to either try to break
a conversation or try to discover contact relationships, or poison
conversation in some way," plus general attack-surface coverage (amounts,
text inputs). Threat-model scope was narrowed by the user, via explicit
choice, to two adversary types:

- **Anonymous Platform observer** — no special access; only reads whatever
  any Dash Platform user can read (documents by public index, timestamps,
  counts, sizes). Cannot decrypt anything.
- **A known contact gone rogue** — an established, accepted counterparty.
  Has the shared ECDH secret, knows both `refId`s in the relationship, can
  publish arbitrary-content documents under their own genuine identity at
  will (paying normal Platform document-creation fees).

**Explicitly out of scope for this pass** (not audited): a network-level/relay
attacker (malicious DAPI node, MITM before documents are finalized) and
local device/DB access (someone with the SQLite file or KV sidecar, outside
the secret-seam vault).

A third, adversary-agnostic pass covered general input-handling attack
surface (amounts, text validation, injection, overflow) regardless of who
submits the input.

Methodology: three parallel read-only audits (no code changes), each given
full context on the protocol (`docs/orchardpay/PROTOCOL_DESIGN.md`,
`docs/ai-design/2026-07-19-orchardpay-query-workflow-reference/README.md`,
the H-01/L-01/M-01/M-05 dispositions in the comprehensive-review-response
doc) and told explicitly to be creative rather than just verify a checklist.

## Confirmed exploitable

### 1. Fake "Payment" notifications are not gated on verification

`src/ui/orchardpay/message_thread_screen.rs:947`:

```rust
let display_amount = message.verified_amount.unwrap_or(*amount);
```

The bold "Payment: X DASH" headline shows the **sender's claimed** `amount`
whenever `verified_amount` is `None` — only a small italic caption below it
("Checking payment status…" / "Awaiting Shielded Sync Completion", lines
1037-1050) hints the amount is unconfirmed.

A rogue contact can broadcast a bare `MessageContent::Payment{ amount:
<anything>, memo }` `encryptedMessage` under their own genuine `refId`/
`$ownerId` — **no real shielded transfer required at all**. `verified_amount`
is sourced only from `orchardpay_get_verified_payment_amount` /
`orchardpay_outgoing_payments_by_document` /
`orchardpay_incoming_payments_by_document` (`messages.rs:1500-1525`); if no
matching real transfer is ever sent, it stays `None` **forever**, and the
false headline is never corrected — only ever softened by the caption.

This directly contradicts the trust-model claim in `PROTOCOL_DESIGN.md`
("the recipient's own wallet independently observes the real transferred
value… always the authoritative source for the amount the UI displays") —
and the same claim used to downgrade H-01's accepted replay residual ("the
real transferred amount is independently verified… regardless"). That
verification exists, but only as a later correction, never as a display
gate. Cost to attacker: one ordinary document-creation fee, no funds moved.

Rated a stronger, cheaper, more directly damaging vector than the accepted
H-01 residual — arguably a worse consequence of the same underlying
"claimed data displayed before verification" pattern. (`PaymentRequest`'s
own headline is fine — it's inherently just a request, not a claim that
funds moved.)

**Resolution (2026-07-28, agreed design — not yet implemented):** an
unverified `Payment` bubble (`verified_amount: None`) gets the plain/neutral
`Message`-style background instead of today's money-tinted frame, and its
headline reads `"Payment: Pending…"` instead of the claimed amount — no
number is shown at all until verification resolves. Once `verified_amount`
becomes `Some`, both the background and headline switch to today's existing
verified behavior unchanged, including the existing mismatch-warning path
("Verified — but the amount received was X (message said Y)"). The two
status captions below ("Checking payment status…" / "Awaiting Shielded Sync
Completion") stay exactly as-is — deliberately not escalated even once a
full sync pass completes with no match, since that still isn't proof the
payment won't arrive on a later pass.

### 2. A rogue contact can permanently erase their own inconvenient message from the victim's view

`src/backend_task/orchardpay/messages.rs:1256-1283`, `trim_ambiguous_tail`
(added this session to fix M-01's same-`$createdAt` collision bug). Its doc
comment frames "100+ documents from one identity in one block" as an
unlikely edge case — but a funded rogue contact can **deliberately engineer
it**: broadcast ≥100 `encryptedMessage` documents in a tight burst (cheap,
each pays only the ordinary per-document fee). If a full 100-doc page (the
attacker's own side) shares one `$createdAt`, the code accepts the loss
risk and returns that shared timestamp as the next cursor; every later page
uses `$createdAt < cursor`, permanently excluding any of the attacker's
documents beyond the first 100 sharing that exact timestamp — with only a
server-side `tracing::warn!` the user never sees.

Consequence: a rogue contact can selectively and permanently hide one of
their own earlier messages (a `PaymentRequest`, a receipt, an inconvenient
admission) from the victim's thread view by timing a flood into the same
block, with no visible indication anything was lost. Confined to the
attacker's own side of the conversation — the victim's own sent messages
are unaffected (Platform ownership prevents write access there).

**Resolution (2026-07-28, agreed design — not yet implemented):** no change
to the pagination/cursor mechanism — the existing fallback (accept the loss,
cursor = the shared boundary timestamp) is correct as-is and is reframed as
a deliberate, accepted design tradeoff rather than a residual gap: flooding
100+ same-block messages costs the attacker real Platform fees for a
griefing-only outcome, and OrchardPay's P2P model treats a clearly malicious
counterparty as a social problem (block/walk away) rather than something the
pagination layer owes a perfect technical defense against. What does change:
add a neutral, non-speculative UI notice when the fallback fires —
`"Some messages from this contact may not have loaded."` — instead of only
a server-side `tracing::warn!` the affected party never sees. This same
notice is reused for the low-severity decode-failure case below, since both
represent "a document was fetched but didn't become a displayed message."
Update `trim_ambiguous_tail`'s doc comment to state this accepted-tradeoff
reasoning explicitly.

### 3. No content sanitization on message/memo text — bidi/zero-width visual spoofing

`src/model/orchardpay.rs:335-346` (`validate_message_text`/
`validate_payment_memo`, backed by `validate_char_count`,
`src/model/validation.rs:13-24`) enforce only a character-count range — no
content filtering. Unlike DPNS's pending-username display, which has a
dedicated sanitizer (`sanitize_pending_username_for_display`,
`src/model/contested_name.rs:144`, stripping `is_control()` and bidi
overrides U+202A-U+202E / isolates U+2066-U+2069), **no such sanitizer is
ever applied to OrchardPay message/memo text**. Decrypted text goes
straight to egui widgets in `message_thread_screen.rs`: message body (890,
897), payment memo (961, 970), payment-request memo (1064), receipt-alert
memo (1209).

A counterparty (or the user's own fat-fingering) can embed U+202E or
zero-width sequences to make a message or memo visually read as something
other than its real content — e.g. a memo that displays as "10 DASH" but
copies/decodes as something else. Both server-side validators run at every
send call site (`messages.rs:801-802, 857-861, 924-928`), so this is a
validation **gap** (content), not a validation **bypass** (length is
checked).

**Resolution (2026-07-28, agreed design — not yet implemented):**
generalize `model/contested_name.rs`'s `is_bidi_control`/
`sanitize_pending_username_for_display` into a shared helper in
`model/validation.rs`, extending the exclusion set to also strip zero-width
characters (U+200B, U+200C, U+200D, U+FEFF) alongside the existing
control/bidi-override set — DPNS's own sanitizer doesn't cover these either
today, so this closes a gap in both call sites, not just OrchardPay's.
Refactor DPNS's call site to use the shared helper rather than leaving a
near-duplicate behind. Apply the shared sanitizer in two places: (a) render
time in `message_thread_screen.rs`, at all four display sites (message
body, payment memo, payment-request memo, receipt-alert memo) — the
load-bearing defense, since it protects the recipient regardless of what a
rogue counterparty's client actually sends; (b) send time, silently
stripping these characters from the local user's own composed text before
encryption (including `edit_message`/`edit_payment_memo`, not just the
original send call sites) — consistent with how it renders anyway, and
avoids blocking a probably-accidental paste with a confusing error over
invisible characters the user can't even see.

### 4. Platform observer: free network-wide census, no per-target lookup needed

Traced against the pinned `rs-drive` source (rev `288a6ca`,
`query/mod.rs::find_best_index`/`is_for_primary_key`): a query needs **no
equality WHERE clause** — Drive only requires that supplied fields
(including order-by-only fields) match a defined index. Since
`contactAnchor`, `shieldedAddress`, and `encryptedMessage` each expose their
sole/leading index (`byOwner`, `byOwner`, `refId` respectively)
unconditionally, an observer can page `order_by: [{"$ownerId":"asc"}]` (or
`refId asc`) with an **empty WHERE clause** and enumerate every document of
that type ever created, network-wide — full membership census, not just
documents for an identity already suspected. This meaningfully escalates
L-01's existing "observer sees owner IDs/refIds/timing/counts" finding: no
prior targeting is required at all.

**Resolution (2026-07-28): accepted as an architectural limitation, same
disposition as L-01.** No code fix exists — the enumerability is an
inescapable property of the same indices (`byOwner`, `refId`) the app's own
legitimate features require (resolving a name to an address, listing my own
anchors for recovery, reading a contact's messages to me); removing or
restricting them would break the app itself, not just block an adversary.
Platform's permissiveness about empty-WHERE + order-by queries is a protocol
property, not something a contract schema or client-side code can opt out
of — anyone with `dash-sdk` can issue the query directly against the public
contract, entirely bypassing OrchardPay's own UI and code. A real fix would
need a Platform-level document-ACL/private-document feature that doesn't
exist today.

### 5. Platform observer: pending-vs-established relationship pairing signal

Per the documented handshake, only the **initiator's** anchor is ever
mutated (`ReplaceDocument` at accept time, filling `anchorData`); the
**acceptor's** anchor is created already-complete and never replaced. Both
`$createdAt`/`$updatedAt` are mandatory public fields. This gives an
observer, for free:
- `$updatedAt == $createdAt` → still-pending outbound request, forever,
  until accepted.
- `$updatedAt != $createdAt` → completed relationship, with the replace
  timestamp landing shortly after some *other* identity's anchor
  `$createdAt` (bounded by sync-scan interval, not human response time) —
  a real pairing signal, not coincidence-hunting.
- The simultaneous-initiate case is distinguishable too: both sides'
  anchors get replaced, a symmetric pattern the normal accept flow never
  produces.

Confidence degrades as total anchor volume grows (more anchors → more
coincidental near-simultaneous unrelated pairs); strongest during
low-adoption periods.

**Resolution (2026-07-28, agreed design — not yet implemented):** the most
involved of the seven, arrived at over several rounds — a synthetic no-op
replace was considered and refined into a real mechanism instead:

- Both sides create `anchorData.their_reference_id` already `Some(...)` at
  creation time, never `None`. The **initiator** (who doesn't yet know the
  real value) seeds it with a self-recognizable filler — their own identity
  ID, a fixed value with negligible collision risk against a genuine random
  32-byte `reference_id`. The **acceptor** already populates the real value
  at creation today — unchanged.
- Both sides perform **exactly one** delayed replace, gated by the
  identical rule: a persisted scheduling marker (same shape as the existing
  `PendingOrchardPayOperation` pattern, but see the dedicated-key note
  below) tracks each anchor's creation time; checked opportunistically on
  app use (not a precise background timer, to avoid its own clustering
  artifact — should hook into whatever existing idempotent cold-boot/
  foreground catch-up pattern OrchardPay already uses, e.g. the
  `ensure_shielded_bound`/`ensure_upstream_registered` style checks, rather
  than a new timer construct); fires once `now >= creation_time + 10 hours`.
  - **Initiator's delayed replace**: publish the real `reference_id` over
    the filler once it's actually been discovered *and* the threshold has
    passed (`Some(filler) → Some(real)` — a fixed-size field, so this is a
    same-length ciphertext swap, not a size-changing transition). If not
    yet discovered when the threshold passes, keep deferring. This also
    closes the timing-distribution gap a first version of this design
    missed: without this gate, the initiator's *real* replace would fire
    as soon as they discover the response (often much sooner than 10h),
    producing a distinguishable "fast" cluster vs. the acceptor's "always
    ≥10h" cluster — holding the initiator's publish to the same threshold
    (even though they may know the truth sooner) makes both sides' delay
    distributions genuinely identical, not just their sizes.
  - **Acceptor's delayed replace**: decrypt and re-encrypt the **unchanged**
    `AnchorDataRecord` content and replace. No data change is needed for the
    ciphertext to differ — confirmed against `orchardpay/encryption.rs:59-61`:
    `encrypt()` draws a fresh `OsRng` nonce on every call, so re-encrypting
    identical plaintext already produces a different ciphertext at the
    identical total length (same nonce size + same plaintext size + same
    fixed AEAD tag size), automatically, with no fabricated content
    required.
- Local KV contact state (`Established`) is set immediately at
  accept/discovery time on both sides, exactly as today — only the
  Platform-side `anchorData` publish is deferred. Messaging and all real
  app functionality are unaffected by the delay.
- **Needs its own dedicated KV key, not `PendingOrchardPayOperation`'s
  slot** — found during the holistic cross-check (below):
  `pending_operation_key(contract_id, counterparty)` is a single
  overwrite-only slot also used for contact-anchor creation and M-02's
  atomic payment-flow resumable marker. If this scheduling marker reused
  that same slot, an in-flight `Payment`/`PaymentRequest` to the same
  counterparty during the 10-hour window would clobber it (or be clobbered
  by it). Use a new, separate key instead.
- `recover_own_anchors` (and anything else that reads `anchorData`) needs
  to learn the filler-detection rule (`their_reference_id == my own
  identity ID` → not yet real) so a recovery run during the delay window
  doesn't misinterpret a still-pending initiator anchor as already
  resolved.
- **Known, accepted cost**: the acceptor's anchor is always
  recovery-correct (content was never actually wrong, only re-sealed for
  pattern-matching) — zero new cost there. The **initiator's** anchor
  genuinely shows the filler (not the real reference_id) until their
  delayed publish fires — a reinstall within that window means
  `recover_own_anchors` finds "an anchor for this counterparty, but their
  reference_id isn't known yet" rather than a fully-recoverable
  relationship. This is a real, new, narrow cost this design introduces
  (today, with no delay, the initiator publishes the real value as soon as
  they discover it — often much sooner than 10h) — accepted as the
  tradeoff for closing the timing-correlation signal.

### 6. Platform observer: mandatory "uses OrchardPay" fingerprint, before any contact exists

`requiresIdentityEncryptionBoundedKey`/`requiresIdentityDecryptionBoundedKey`
force any valid OrchardPay ENCRYPTION/DECRYPTION key to carry
`ContractBounds::SingleContractDocumentType` pointing at this exact contract
ID + `contactAnchor`. Identity public keys (including `contract_bounds`) are
baseline-public Platform data. Combined with finding 4's index scan, an
observer gets the complete OrchardPay user census — including everyone who
only ever published a `shieldedAddress` and made zero contacts — from
identity/key metadata alone.

**Resolution (2026-07-28): accepted as an architectural limitation, same as
#4.** Three mitigations were considered and ruled out: loosening the
contract-bounds scope (e.g. to the whole contract rather than one document
type) doesn't help, since the contract ID itself is the identifying signal,
not which document type it's further scoped to; dropping the contract bound
entirely would remove the fingerprint but trades away a real security
property (limiting the key's blast radius/cross-context reuse) for a
privacy gain #4 already concedes anyway; and making the key shape blend in
with other apps' contract-bounded keys (e.g. DashPay's) doesn't help either,
since the distinguishing fact is *which* contract ID the bound points to,
and that has to be explicit and public for the bounding to do its job at
all. No code fix — identity public keys (including `contract_bounds`) are
baseline-public Platform metadata, same as #4's documents.

### 7. Platform observer: ciphertext length leaks message *kind*

`encryption.rs`'s AEAD envelope (`nonce(12) ‖ AES-256-GCM(plaintext)`) adds
no padding — ciphertext = plaintext + 28 bytes exactly. With
`bincode::config::standard()` (varint ints, no length prefix on fixed
`[u8;32]`), `PaymentRequestReceipt` has a hard minimum plaintext floor of
~36 bytes (mandatory 32-byte `original_document_id`) → ciphertext floor ~64
bytes, while `Payment`/`PaymentRequest` float near a ~31-40-byte floor
(indistinguishable from each other, but well below Receipt's floor) and
`Message` is unbounded/text-length-driven. An observer can bucket `msgData`
lengths and infer message kind for every document in finding 4's corpus,
without decrypting anything.

**Resolution (2026-07-28, agreed design — not yet implemented):** pad
`MessageContent`'s serialized plaintext up to a **64-byte minimum** before
encryption (`padded_len = max(natural_bincode_len, 64)`) — no bucket ladder
needed, to avoid raising the per-message storage-fee cost more than
necessary. Verified against bincode 2.0.1's actual varint encoding rules
(values ≤~250 encode to 1 byte, up to `u16::MAX` to 3, up to `u32::MAX` to
5, up to `u64::MAX` to 9) that 64 bytes comfortably covers all four kinds in
memo-less/shortest form: `Message` (e.g. "hi") ~4 bytes; `Payment`/
`PaymentRequest` with no memo ~7 bytes; `PaymentRequestReceipt` with no memo
~49 bytes — the tightest fit, driven by its mandatory 32-byte
`original_document_id` plus an `original_created_at` field that always
needs the largest (9-byte) varint encoding, since a millisecond Unix
timestamp today already exceeds `u32::MAX`. No decrypt-side change is
needed: `bincode::serde::decode_from_slice` returns `(value, bytes_consumed)`
and already ignores trailing bytes beyond what the decoded value needs, so
the padding is a pure encrypt-side addition. Residual, accepted: a variant
carrying more than roughly 10-15 characters of memo/text grows past 64
bytes and becomes visible again — but the classification signal is much
weaker there anyway, since a `Payment` with a 100-byte memo and a `Message`
with ~100 bytes of text land at similar overall sizes regardless of kind.

## Theoretical / low severity

- **No independent size cap at the encryption layer**
  (`orchardpay/encryption.rs`'s `MessageContent::encrypt()` performs no
  byte-length check of its own). Every current call site validates via the
  model layer first, and no MCP/CLI tool exists yet for OrchardPay
  messaging — so no live unvalidated path exists today. Becomes a real risk
  the moment a future caller (an MCP tool, a bulk-import path) constructs
  `MessageContent` directly.
  **Resolution (2026-07-28):** add a defensive maximum-length check
  directly inside `MessageContent::encrypt()` itself (new
  `OrchardPayCryptoError::PayloadTooLarge` variant), rejecting anything
  beyond a sane ceiling matching the existing ~4096-5120 byte range the
  char-limit constants imply. Cheap add-on since `encrypt()` is already
  being modified for finding 7's padding. Ordering matters: check the
  natural (pre-padding) length against the cap first, then pad up to 64 if
  smaller — never compare a padded length against the cap.
- **No upper bound on `validate_send_amount`** — only a floor
  (`MIN_SEND_AMOUNT_CREDITS`) is enforced. Not independently exploitable
  (an amount exceeding real balance fails at the transfer layer), but an
  unenforced assumption for any future caller.
  **Resolution (2026-07-28):** left as-is — the network/transfer layer
  already rejects amounts exceeding real balance, so there's no live gap
  to close.
- **Decode-failure messages vanish silently, per-document, no crash**
  (`decode_thread_message`, `messages.rs:1493-1535`, returns `Option`). A
  rogue contact can cheaply flood a thread with own-owner garbage-content
  documents (valid AEAD, but undecodable as `MessageContent`) at the same
  cost/impact as the already-accepted H-01 replay residual.
  **Resolution (2026-07-28):** reuse finding 2's same notice ("Some
  messages from this contact may not have loaded.") rather than building a
  separate indicator — both represent "a document was fetched but didn't
  become a displayed message."
- **Handshake-window griefing**: a rogue initiator can delete/replace their
  own `contactAnchor` mid-handshake before the victim's memo scan fetches
  it, silently failing that one attempt. Self-limited — only stalls a
  request the rogue party themselves initiated.
  **Resolution (2026-07-28):** left as-is, no change — no victim-facing
  harm, only wastes the griefer's own initiation attempt.
- **Char-count-vs-byte-count multiplier is already accounted for** — not a
  bug. `MAX_MESSAGE_CHARS`/`MAX_PAYMENT_MEMO_CHARS` = 1000, worst case
  exactly 4000 bytes (4-byte UTF-8 max), matching the code's own comments.

## Checked, not exploitable / clean

- **`refId` brute force**: real 256-bit CSPRNG (`OsRng.fill_bytes`,
  `contact_anchor.rs` ~214-218/466-470) — no seeding weakness, no reduced
  keyspace.
- **`shieldedAddress` publish-timing vs. shielded receive-timing**: Orchard
  transfers reveal no plaintext sender/recipient/amount to a
  non-participant — no observable event to correlate against.
- **Compound `refId`+`$ownerId` decoy/forgery**: already closed query-side
  (H-01 addendum, `byReferenceIdbyOwnerIdAndCreated`); re-confirmed it
  doesn't reopen under the finding-4 full-scan angle (a decoy still
  requires the attacker's own real, signed `$ownerId`).
- **Contact-state poisoning via re-sent/replayed anchor signals**: not
  possible — `handle_incoming_anchor_signal`'s match on existing state
  only ever *advances* it; a signal arriving once already
  `PendingInboundUnaccepted` or `Established` is a no-op.
- **Post-establishment anchor tampering**: not possible — once
  `Established`, messaging/state reads come from the victim's locally
  cached state, never re-fetched from the counterparty's `contactAnchor`.
- **Recovery-path poisoning**: `recover_own_anchors` only queries the
  victim's own `$ownerId`-scoped anchors — a rogue contact's anchor
  mutations can't influence victim recovery.
- **Crafted-timestamp reordering of the victim's own messages**: not
  possible — `$createdAt` is Platform/block-stamped, and a rogue contact
  cannot write into the victim's own `refId`+`$ownerId` bucket at all.
- **SQL injection**: fully parameterized throughout (`wallet_backend/kv.rs`
  → upstream `SqlitePersister`); no string-concatenated SQL from user data.
- **Integer overflow/underflow**: `model/fee_estimation.rs` uses
  `saturating_add`/`saturating_mul`/`saturating_sub`/`saturating_div`
  throughout — no raw arithmetic on user-controlled amounts.
- **Zero/negative amounts**: `u64` can't be negative; zero and
  sub-`MIN_SEND_AMOUNT_CREDITS` values are rejected.
- **`decrypt()` panic-safety**: bounds-checked before `split_at`; AEAD
  decrypt and bincode decode both return typed `Result`s — no
  `unwrap`/`expect`/raw indexing on attacker-controlled-length ciphertext.
- **Malformed-payload size blow-up**: not possible — Platform's
  `max_field_value_size` (5120 bytes) consensus cap plus bincode 2.0.1's
  `claim_bytes_read`/`claim_container_read` read-budgeting (rejects a
  length-prefix claim larger than the remaining buffer before allocating).
- **Backend re-validation**: `send_message`, `send_payment_request`,
  `send_payment`, `edit_message`, `edit_payment_memo` all independently
  call the model validators server-side rather than trusting the UI.
- **No `unwrap`/`expect`/`panic!` on attacker-controlled data** anywhere in
  `messages.rs`, `contact_anchor.rs`, or `encryption.rs` — decrypt/decode
  is `Result`/`Option` all the way to the UI.

## Holistic cross-check (2026-07-28)

After all seven confirmed-exploitable findings and the four low-severity
findings reached agreed designs individually, they were cross-checked
together for interactions before any implementation began.

**One real conflict found**, now folded into finding 5's resolution above:
finding 5's scheduling marker cannot reuse `PendingOrchardPayOperation`'s
key (`pending_operation_key(contract_id, counterparty)`) — that's a single
overwrite-only slot also used by contact-anchor creation and M-02's atomic
payment flow. An in-flight `Payment`/`PaymentRequest` to the same
counterparty during finding 5's 10-hour delay window would clobber the
scheduling marker, or be clobbered by it. Fix: a new, separate KV key for
this scheduling marker.

**No other cross-finding conflicts found:**
- Finding 7's padding is invisible to legitimate decoders (bincode ignores
  the trailing padding bytes) and doesn't affect finding 1's UI logic, which
  reads the already-decoded `MessageContent`/`verified_amount`, not raw
  bytes.
- Finding 3's sanitizer and finding 1's background/headline change touch
  the same `render_message_bubble` function in different, non-overlapping
  spots (memo/text content vs. headline/background) — co-located, not
  conflicting.
- Finding 2 and the low-severity decode-failure item deliberately share one
  notice mechanism (by design, not a conflict).
- Finding 5 is fully isolated from the messaging-side fixes (1/2/3/7) —
  different document type (`contactAnchor` vs `encryptedMessage`) and a
  separate `encrypt()` implementation (`AnchorDataRecord` vs
  `MessageContent`).

**Standout items**: findings **1** (fake payment headline) and **2**
(selective message erasure via flood) remain concrete, currently-live
application bugs with direct user harm — distinct from the observer-side
findings (4, 5, 6, 7), which are largely architectural/inherent tradeoffs of
a public-Platform-documents design rather than code defects. All designs
above are agreed but **not yet implemented** — building them is the next,
separate phase.

## Addendum (2026-08-21) — re-run against current code

Requested: re-run this same audit against the current codebase, given ~4
weeks and 30+ commits of further OrchardPay work since the original pass
(`7aa61dbc`..`HEAD`), including entirely new features the original audit
never saw — most significantly OPP2 "documentless silent payments"
(`0dd20f18`), deletable `contactAnchor` documents (`b42f8b60`), the `shie_id`
field (`7f1447a8`), and initial-message/bundled-amount contact requests
(`3d51f405`).

Methodology: same as the original — three parallel read-only audits (no
code changes), one per original adversary type plus the general
input-handling pass, each given the original audit doc, the protocol/query
docs, and told to (a) re-verify every original finding's fix against current
code, not just trust this doc's own "implemented" claims, and (b) audit
every new feature shipped since for issues under the same threat model.

**Result: all seven original confirmed-exploitable findings and all four
low-severity findings hold as previously resolved or accepted** — no
regressions. Findings 1, 2, 3 (rogue contact), 4, 6 (observer, accepted
limitations), and 5, 7 (observer, code-fixed) were each independently
re-verified against current source, including against every commit flagged
as touching relevant code (`8f9eb6be`, `572352bd`, `dfd99d84`, `b0666921`,
`26c1e1ad`). Finding 5's dual-replace mechanism in particular was traced
end-to-end and confirmed live-wired (`app.rs` dispatches it on every
`OrchardPayShieldedSyncCompleted` event, not just designed-but-dormant).

Four new findings surfaced, all in code that postdates the original audit:

### 8. OPP2 silent payments verify against the wrong ECDH secret — genuine payments go unrecognized, and a rogue contact can forge attributed payment signals at will

**Confirmed exploitable (new), high severity.**

`src/backend_task/orchardpay/memo_scan.rs:56-67` (`build_silent_payment_candidates`)
derives its MAC-verification key via `outbound_shared_secret(me, counterparty_decryption_pubkey)`
— the formula for *encrypting what I send* — instead of
`inbound_shared_secret(me, counterparty_encryption_pubkey)`, the formula
`load_thread`/`load_more_history` correctly use for verifying what a
counterparty sent me (`messages.rs:1696/1704`). Since each identity's
`ENCRYPTION` and `DECRYPTION` Platform keys are independently derived
(confirmed via `keys.rs:201-259`), these two ECDH values only match by
commutativity across the *correct* sender/receiver pairing — the code as
written checks against a value with no cryptographic relationship to what a
genuine sender actually used.

Two consequences, both confirmed against live code:

- **Correctness**: a genuine `send_silent_payment` call, used exactly as the
  UI intends, is never recognized by the recipient's scan — funds arrive in
  the wallet balance normally, but the feature's entire point (attributed
  display in the thread / Recent Payments / Most Recent sort) silently never
  fires for anyone. No test anywhere in the repo exercises a real
  two-identity OPP2 round trip, consistent with this shipping unnoticed.
- **Security**: the victim's actual (buggy) verification key is
  `ECDH(VICTIM_enc, ROGUE_dec)` — which, by commutativity, is exactly
  `ECDH(ROGUE_dec_priv, VICTIM_enc_pub)`, a value the rogue contact can
  compute independently from key material they already legitimately hold
  (their own `DECRYPTION` private key, the victim's public `ENCRYPTION`
  key). The rogue can craft one dust-value real shielded transfer with a
  self-forged `MEMO_TAG_SILENT_PAYMENT ‖ T(attacker-chosen) ‖ HMAC(...)` and
  have it land as a fully "wallet-verified" green payment bubble and Recent
  Payments row, for any amount/timestamp of their choosing, at the cost of
  one minimum-value transfer. `T` is only future-clamped
  (`OPP2_TIMESTAMP_FUTURE_TOLERANCE_SECS`), so entries can be backdated
  anywhere into existing history too.

Files: `memo_scan.rs:56-67` (bug), `silent_payment.rs:81-89` (sender side,
correct in isolation but mismatched with the verifier), `messages.rs:313-370`
(the correct pattern this deviates from). Suggested fix direction (not
implemented): change `build_silent_payment_candidates` to derive via
`inbound_shared_secret`, matching `load_thread`'s existing pairing.

**Resolution (2026-08-21, shipped):** `build_silent_payment_candidates` now
derives via `messages::inbound_shared_secret(app_context, identity,
contract_id, &established.counterparty_encryption_pubkey, seed_hash)`,
matching `load_thread`'s receiver-side pairing exactly. `inbound_shared_secret`
was widened from private to `pub(crate)` so `memo_scan` can call it directly
instead of re-deriving the (buggy) formula locally. Residual, accepted: this
fix has no dedicated regression test — a real check needs a two-identity
round trip (genuine sender via `silent_payment.rs`'s `outbound_shared_secret`
path, genuine receiver via this fixed `inbound_shared_secret` call,
confirming they land on the same key by ECDH commutativity), which is
`tests/backend-e2e/` territory, not a unit test. This gap predates the fix —
the original finding already noted "no test anywhere in the repo exercises a
real two-identity OPP2 round trip" — and remains open.

### 9. `SilentPaymentRecord`'s cache key has no direction discriminator — a rogue contact can overwrite a victim's own outgoing payment record

**Confirmed exploitable (new), high severity — compounds with #8, but stands independently of it.**

`silent_payment_key(contract_id, counterparty, fingerprint)`
(`src/wallet_backend/orchardpay.rs:387-397`) omits any `from_me`/direction
component; `orchardpay_set_silent_payment` (same file, :622-635) is a blind
overwrite at that key. Because a rogue contact who legitimately received a
real silent payment from the victim can always decrypt its memo and read
back the exact `(timestamp, mac)` used, they can later craft a new transfer
reusing those identical bytes — the victim's own "verify incoming from
rogue" computation is, by construction, the identical value the victim used
for their own prior send to that same counterparty (both are
`outbound_shared_secret(victim, rogue_dec_pub)`; this sub-case doesn't even
require finding #8's ECDH-direction bug). The victim's next scan then
overwrites their own genuine sent-payment record with a fabricated
"received dust from rogue" one, at the identical sort position, in both the
thread and Recent Payments. Cheaper and more targeted than the original
finding 2's 100-document flood: one dust transfer, at a time of the
attacker's choosing.

Files: `wallet_backend/orchardpay.rs:387-397` (unscoped key), `:622-635`
(blind overwrite). Suggested fix direction (not implemented): fold a
direction/role component into `silent_payment_key` so a party's own sent
record and a same-fingerprint incoming-attributed record cannot collide.

**Resolution (2026-08-21, shipped):** `silent_payment_key` takes a `from_me:
bool` parameter and folds a trailing `:o`/`:i` (outgoing/incoming) segment
into the key, so a party's own sent record and an incoming-attributed record
can never collide even on an identical `(timestamp, mac)` fingerprint.
`orchardpay_set_silent_payment` passes `record.from_me` through.
`orchardpay_list_silent_payments` (the only read path) already worked off a
prefix scan (`silent_payment_key_prefix`, no fingerprint/direction in the
prefix) and needed no change — both directions still list together. Worst-
case key length re-verified against `MAX_KEY_LEN` (126 of 128 chars) with a
dedicated test. Regression test:
`silent_payment_records_of_opposite_direction_do_not_collide` writes a real
sent record and a same-fingerprint replayed incoming record and confirms
both survive independently.

### 10. `contactAnchor.data` has no ciphertext padding — leaks the presence and approximate length of the new `initial_message` field

**Confirmed exploitable (new), moderate-high severity — finding 7's fix never extended to this document type.**

Finding 7's 64-byte padding (`MESSAGE_PADDING_FLOOR`, `encryption.rs:362`)
is applied only at `MessageContent::encrypt`'s call site. `ContactAnchorPayload::encrypt`
(`encryption.rs:192-199`) — the encrypt path for `contactAnchor.data`, whose
`initial_message` field (`3d51f405`, shipped *after* finding 7's fix) is a
real user-typed `Option<Vec<u8>>` up to `MAX_INITIAL_MESSAGE_CHARS` (250)
chars — has no padding call at all. An observer running finding 4's free,
unauthenticated `byOwner` census over `contactAnchor` can read every
anchor's public `data` byte length directly: absent-vs-present is
distinguishable at a ~95-byte baseline, and the actual message byte length
is recoverable to within a handful of bytes, immediately at publish time
(`data` is written once at creation and untouched by finding 5's
deferred-replace mechanism, which only ever rewrites `anchorData`) — no
10-hour delay softens this the way finding 5's fix softens the pairing
signal. It also reopens a narrow role-identification signal: only an
initiator's anchor can carry `initial_message` (`accept_contact` hard-codes
`None`), so any anchor with above-baseline `data` length is provably an
initiator's.

Files: `encryption.rs:192-199` (missing padding), `contact_anchor.rs:171-191`
(unpadded `initial_message` encode). Suggested fix direction (not
implemented): apply the same padding-floor treatment `MessageContent::encrypt`
already uses to `ContactAnchorPayload::encrypt`.

**Resolution (2026-08-21, shipped):** two padding floors, applied at
encrypt-side only (decrypt already ignores trailing bytes, same as finding
7). `ContactAnchorPayload::encrypt` pads to a 128-byte floor (covers a
no-fields payload plus a short ~55-60-byte greeting). `AnchorDataRecord::encrypt`
— covering `anchorData`'s own `my_initial_message` mirror, a *more*
persistent instance of the same leak since `anchorData` is re-published at
accept time and again by finding 5's delayed-replace mechanism — pads to a
384-byte floor, sized for that struct's larger fixed baseline. Residual,
accepted, same framing as finding 7: a message past either floor is
length-distinguishable again; `AnchorDataRecord` also still leaks
`counterparty_name_snapshot`'s DPNS-name length, a pre-existing, unrelated
signal this fix doesn't address. Regression tests:
`contact_anchor_payload_with_and_without_short_message_pad_to_the_same_ciphertext_length`
and
`anchor_data_record_with_and_without_short_message_pad_to_the_same_ciphertext_length`.

### 11. Deletable `contactAnchor` gives an observer a hard proof that a relationship reached `Established`

**Confirmed exploitable (new), low-moderate severity.**

`delete_own_contact_anchor` (`contact_anchor.rs:800-873`) is reachable only
from `Established` state — enforced backend-side, not just in the UI. Since
`documentsKeepHistory: false`, deletion is a genuine, permanent disappearance
from any future census (finding 4). An observer maintaining a running
`contactAnchor` census can therefore treat "this owner's previously-seen
anchor vanished between two scans" as a hard, code-guaranteed proof the
relationship reached `Established` before deletion — a narrower instance of
exactly what finding 5's fix was built to keep hidden for *live* anchors,
via a mechanism (`b42f8b60`) that shipped after finding 5's fix and wasn't
reasoned about against it. No counterparty-pairing is revealed, and it's
conditional on the owner choosing to delete, so severity is lower than
finding 5's original issue — closer to findings 4/6's "architectural,
inherent to a public/deletable-by-owner document" category.

**Resolution (2026-08-21, shipped):** tombstone instead of a real Platform
delete. `delete_own_contact_anchor` no longer issues `DocumentTask::DeleteDocument`
— it does a `ReplaceDocument` that overwrites `anchorData` with a tombstone
`AnchorDataRecord` (`counterparty_identity_id` set to the new
`ANCHOR_TOMBSTONE_SENTINEL`, an all-zero 32-byte value with negligible
collision risk against a real identity ID; every other field cleared),
re-encrypted under the same wallet-derived key and still padded to the same
384-byte floor every live anchor uses (finding 10). Removal now looks
exactly like any other `ReplaceDocument` event — the same noise finding 5
already made unremarkable — instead of a document vanishing.
`recover_own_anchors` recognizes the sentinel and skips tombstoned anchors
(counted in a new `AnchorRecoverySummary::tombstoned` field, kept separate
so `anchors_found` still equals the sum of all four buckets), preserving
the original feature's point: a removed relationship doesn't come back on
wallet restore. The document's `data` field (encrypted for the
counterparty) is left untouched — already-opaque ciphertext, never
re-read by the counterparty once `Established`. **Cost, same flavor as
finding 5's own accepted cost:** the anchor's Platform storage fee is never
reclaimed — a removed contact's document, and its storage-fee footprint,
now persist forever, which is the real tradeoff against the true delete
this replaces. Regression test:
`anchor_data_record_tombstone_sentinel_round_trips`.

### Also checked, re-verified clean or not yet exploitable

- **OPP2 vs. the observer adversary**: a silent payment creates no
  Platform document of any kind (a raw shielded transfer only) — invisible
  to a Platform-document-only observer; "absence is itself informative" was
  specifically checked and ruled out, since a real OPP2 transfer and no
  transfer at all both produce an empty result set to every query this
  adversary can issue.
- **`shie_id`**: fully traced lifecycle, mirrors `their_reference_id`'s
  existing filler/deferred-replace protection exactly (one combined
  `ReplaceDocument` swap). Currently inert — zero readers anywhere in the
  codebase (the consuming feature doesn't exist yet) — so not yet
  exploitable; flagged only for review once its consumer ships.
- **Deletable `contactAnchor` vs. the rogue-contact adversary**: only
  operates on the caller's own anchor; cannot affect a counterparty's local
  state (messaging/payment reads never re-fetch a live counterparty
  `contactAnchor`); deleting-and-recreating mid-`Established` is silently
  ignored by the victim's scan (no desync, no handshake replay). One
  low-severity, non-regression note: OrchardPay has no way for a victim to
  *permanently* refuse a specific identity — a removed rogue can always
  re-request via a fresh anchor.
- **Non-constant-time OPP2 MAC comparison** (`memo_scan.rs:330`, derived
  `[u8; 28]` `PartialEq`): theoretical/low severity hygiene note — no live
  timing-oracle path exists (comparison runs locally against a small,
  already-fetched local candidate set, not a network-facing oracle).
- **`\n` now allowed in message/memo text** (`8f9eb6be`): theoretical/low
  severity — bounded "vertical flood" nuisance (up to ~500 blank lines
  within the existing char cap), not a content-spoofing regression of
  finding 3.
- Everything else re-audited — the bundled-amount contact-request display,
  the initial-message UI rework, the `5901baa0` key-resolution API
  adaptation, `Cargo.toml`'s platform-pin consistency, and the full original
  "checked, not exploitable / clean" list (SQL injection, integer overflow,
  zero/negative amounts, decrypt panic-safety, malformed-payload size
  blow-up, backend re-validation, no unwrap/expect/panic on attacker data)
  — re-verified clean against all 30+ commits since `7aa61dbc`.

### Summary

| # | Item | Adversary | Classification | Severity | Status |
|---|---|---|---|---|---|
| 8 | OPP2 verifies against wrong ECDH secret | Rogue contact | Confirmed exploitable | High | **Shipped 2026-08-21** |
| 9 | `SilentPaymentRecord` key has no direction discriminator | Rogue contact | Confirmed exploitable | High | **Shipped 2026-08-21** |
| 10 | `contactAnchor.data` unpadded, leaks `initial_message` presence/length | Observer | Confirmed exploitable | Moderate-high | **Shipped 2026-08-21** |
| 11 | Deletable anchor proves "reached Established" | Observer | Confirmed exploitable | Low-moderate | **Shipped 2026-08-21** |
| — | OPP2 MAC comparison not constant-time | — | Theoretical/low severity | Low | Not planned |
| — | `\n` allowed in message/memo text | — | Theoretical/low severity | Low | Not planned |
| — | No permanent block for a removed rogue contact | Rogue contact | Theoretical/low severity | Low | Not planned |
| 1-7 | All original findings | Both | Re-verified clean, no regressions | — | — |

Findings 8 and 9, both in the OPP2 feature (`0dd20f18`, shipped 2026-08-18,
zero round-trip test coverage anywhere in the repo), were the most
significant results of this re-run — 8 alone meant the feature did not work
as designed for honest use, independent of the security angle. All four new
findings shipped as code fixes on 2026-08-21 (see each finding's own
`Resolution` block above). Finding 8 has no dedicated regression test (see
its `Resolution` block — needs `tests/backend-e2e/` coverage, not a unit
test); findings 9, 10, and 11 each have one. Unlike the rest, finding 11
went through an explicit accept-vs-fix decision first (the user chose "design
a fix" over accepting it as an architectural limitation like findings 4/6),
matching the disposition process the original audit used for those two.
