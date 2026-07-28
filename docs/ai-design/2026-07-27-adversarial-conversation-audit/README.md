# OrchardPay — Adversarial Conversation Audit (2026-07-27)

Status: **implemented (2026-07-28).** All seven confirmed-exploitable
findings and four low-severity findings reached agreed remediation designs
(see the `Resolution` block under each), then were cross-checked
holistically (see the bottom section) before any code was touched. Of the
seven confirmed-exploitable findings, five (1, 2, 3, 5, 7) shipped as code
fixes in `7aa61dbc` (spoofed-payment headline, flood-tolerant message
loading, bidi/zero-width sanitization, ciphertext-length padding) and
`2a7b8a78` (pending-vs-established anchor timing signal); two (4, 6) were
accepted as architectural limitations with no code fix, per their own
`Resolution` sections. Of the four low-severity items, two shipped in
`7aa61dbc` (defensive encrypt-layer size cap, reused flood/decode-failure
notice) and two were deliberately left as-is, per their own `Resolution`
sections. Follow-up work should be tracked as further dated addendums to
this file or new entries in
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
