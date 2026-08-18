# `OPP2`: authenticated, documentless "silent payments"

Status: **implemented**.

## The problem

`messages::send_payment` is document-first: even for a payment with no text
memo, it always broadcasts a `Payment`-kind `encryptedMessage` document,
waits for it to succeed, then sends the memo-correlated shielded transfer
(`MEMO_TAG_PAYMENT`/`OPP1`). That leaves a public, timestamped
document-creation event on Platform immediately followed by a shielded
transfer's broadcast on Dash Core — a chain observer who correlates the two
events can infer that a payment probably just happened around that time,
narrowing that specific shielded transfer's anonymity set. Neither the
2026-07-27 adversarial audit nor the comprehensive review examined this
particular correlation (they checked `shieldedAddress`-publish timing and
`contactAnchor`-to-`contactAnchor` linkage timing, both filed as "clean" —
this is a distinct gap).

`direct_send::send_direct` already avoids the correlation (bare transfer,
all-zero memo, no document) but is a dead end for anything beyond that: it
never appears in any conversation, since `ThreadMessage`/`load_thread` only
ever render from a fetched Platform document.

## Why not just tag the transfer with a raw reference-ID fragment?

The first design considered: tag the transfer `OPP2` + a fragment of the
sender's own `reference_id` + a coarse embedded timestamp, so the recipient
could locally match it to a contact and place it in the conversation. Two
problems killed this:

1. **No authentication.** `messages::send_payment`'s trust doesn't actually
   come from the memo — it comes from the fact that only the two
   established parties can produce ciphertext that survives
   `MessageContent::decrypt` under their shared ECDH secret (an implicit
   AEAD-tag check). A bare reference-ID fragment has no equivalent: `refId`
   is **publicly queryable** once a relationship has any published message
   (`PROTOCOL_DESIGN.md`'s `refId` section), so anyone who's seen a
   relationship's `refId` could, in principle, forge a memo that makes a
   tiny payment look like it came from a specific established contact —
   undermining the "wallet-verified" guarantee the Recent Payments panel
   (ORP-017) is built on. The amount would be real (the wallet did see DASH
   move); the attributed *sender* would not be trustworthy.
2. **The embedded timestamp couldn't do its job.** The shielded note's own
   `block_height` field turned out not to be a real per-note confirmation
   height at all — `platform-wallet`'s own doc comments describe it as "the
   proof-anchor height of the sync-fetch chunk that surfaced the note",
   stamped identically across an entire batch. On a cold restore (exactly
   the scenario ORP-005 recovery exists for), one chunk can span many
   unrelated historical blocks. There's also no working height→time
   conversion anywhere in this codebase to fall back on.

## The implemented design

`MEMO_TAG_SILENT_PAYMENT = *b"OPP2"` (`messages.rs`), 36-byte memo:
`tag(4) ‖ timestamp(4, sender-written Unix seconds, big-endian) ‖
mac(28, truncated HMAC-SHA256)`.

- **Authentication**: `mac = HMAC-SHA256(opp2_mac_key, timestamp_bytes)`,
  truncated to 28 bytes (224 bits — far beyond the ~128-bit
  forgery-infeasibility bar). `opp2_mac_key = HKDF-SHA256(shared_secret,
  info = "orchardpay-opp2-mac-v1")` (`encryption::derive_opp2_mac_key`) —
  domain-separated from the raw ECDH secret, which every other primitive in
  `encryption.rs` uses directly as an AEAD key with no KDF step. This
  restores parity with `OPP1`: forging an attribution requires the actual
  per-relationship shared secret, not just a public `refId` value.
- **Timestamp**: sender-written, folded into the HMAC's authenticated
  content (not decorative) — the recipient reads it directly instead of
  trying to reconstruct it from `block_height`. It's still self-reported
  (a dishonest sender's clock could be wrong), so it's treated as a
  cosmetic ordering hint only, clamped at cache-write time
  (`messages::clamp_opp2_timestamp`, `OPP2_TIMESTAMP_FUTURE_TOLERANCE_SECS
  = 300`) so a skewed or malicious timestamp can't pin an entry
  permanently at the top of a sort order.

## Sending (`silent_payment.rs`)

`send_silent_payment` requires the relationship to already be `Established`
(same guard as `send_payment`) — sending before that point risks
interrupting the in-flight handshake, a different concern from the
timing-correlation one this feature otherwise addresses. No document, no
`PendingOrchardPayOperation` marker — a single atomic external call with
nothing to resume on crash, the same simplicity class as `send_direct`.
`identity_key` isn't a parameter at all: nothing gets signed, since no
document is created. After a successful transfer, the sender writes its own
local cache entry directly (see below) — it already knows every field with
certainty, no scan/matching needed for its own sent side.

## Receiving: eager global scan, never guess

Detection is wired into the *existing* wallet-wide incoming-memo scan
(`WalletBackend::orchardpay_scan_incoming_memos`), which already decrypts
every incoming note once per pass — a third `else if tag ==
MEMO_TAG_SILENT_PAYMENT` branch alongside the existing `Anchor`/`Payment`
handling, so a silent payment surfaces in Most Recent / activity sort
without requiring the recipient to open that specific conversation first.

Resolution (`memo_scan.rs::build_silent_payment_candidates` +
the `SilentPayment` match arm in `scan_for_incoming_anchors`): for every
locally-known identity, every `Established` contact's `opp2_mac_key` is
derived **once per scan pass**, not once per note (local-only —
`established_state`/`outbound_shared_secret` never touch the network once a
relationship's counterparty pubkeys are cached, which `Established`
guarantees). Each `SilentPayment` signal is then checked against every
candidate key:

- **Zero matches** → dropped, same treatment as any other foreign or
  malformed memo. The transfer still counts toward the wallet's normal
  balance regardless — only conversational attribution is what's foregone.
- **Exactly one match** → cached (`WalletBackend::orchardpay_set_silent_payment`,
  `model::orchardpay::SilentPaymentRecord`).
- **Two or more matches** → left unattributed rather than guessed. This
  requires an actual forgery attempt to trigger organically (an honest
  sender's MAC can't collide with another contact's key by chance), and
  even then costs only "this transfer doesn't show up in any conversation"
  — never a misattribution to the wrong contact. Not separately persisted
  or surfaced in the UI for v1: the underlying value is already reflected
  in the normal wallet balance, and building dedicated "unrecognized
  activity" UI for what should be a vanishingly rare, attacker-only case
  wasn't judged worth the scope.

Cache key: `det:orchardpay:silent:<contract_id_b58>:<counterparty_b58>:<fingerprint>`,
scoped `DetScope::Identity` (cascades on identity removal, same reasoning as
`KV_PREFIX_CONTACT`). `<fingerprint>` is `encryption::opp2_memo_fingerprint`
— a 12-hex-char (48-bit) digest of `timestamp ‖ mac`, deliberately short
rather than the full timestamp+MAC: two full 44-char Identifiers already
consume most of `platform_wallet_storage::kv`'s 128-byte key budget (the
same constraint documented on `KV_PREFIX_SCHEDULED_ANCHOR_REPLACE`'s
prefix). 48 bits is comfortably collision-free at any realistic
per-relationship payment volume; it's a uniqueness identifier, not a
security property — the actual authentication is the MAC itself. Both the
sender's own self-write and the recipient's scan-resolved write use the
same fingerprint scheme, so no note-internal field (like the underlying
Orchard note's `cmx`) needs to be threaded out of the scan loop at all.

## Thread rendering: reused the existing `TimelineItem` merge pattern

`ThreadMessage`/`LoadedThread.messages` stay **unchanged** — every existing
edit/delete/cancel code path keys off a real `document_id`, and a
documentless entry has none. Instead, `LoadedThread` gained a sibling field,
`silent_payments: Vec<SilentPaymentRecord>` (a plain local cache read, no
network, so both `load_thread` and `load_more_history` just fetch it fresh
every time — no pagination story needed).

`message_thread_screen.rs` already had exactly the right pattern for this:
`ReceiptAlert`s are a second kind of timeline entry, merged with
`ThreadMessage`s into one sorted `TimelineItem` list purely at render time.
Silent payments became a third `TimelineItem` variant the same way, with
its own `render_silent_payment_bubble` (reuses the money-tint color logic
and header/timestamp layout from `render_message_bubble`; no context menu,
since there's no document to edit/delete/reply to). `recent_verified_payments`
(the Recent Payments panel, ORP-017) and `fetch_recent_activity` (Most
Recent's sort) both fold in the same cache — a silent payment is a real
wallet-verified transfer, same trust category as a document-backed
`Payment`, just without a document.

## UI trigger

A "Send without a message" checkbox on the existing payment composer
(`message_thread_screen.rs`), visible only for `ComposeKind::Payment`. When
checked, the memo field hides (a silent payment carries no message at all)
and `send_clicked` dispatches `OrchardPayTask::SendSilentPayment` instead of
`SendPayment`. No separate compose flow — one mental model, minimal new UI
surface.

## Explicitly out of scope for this increment

- **Fulfilling an existing `PaymentRequest` via `OPP2`.** Fresh/unprompted
  transfers only. Correlating to a specific request would need the payload
  to also identify which request is being fulfilled, and the 32-byte slot
  is already fully used by the timestamp + MAC.
- **Sending before `Established`** (e.g. "silently cancel a pending
  request"). Out of scope, same reasoning `contact_anchor`'s own
  `Established`-only restrictions use elsewhere.
- **A dedicated "unrecognized activity" UI** for the 2+-match case — see
  above.
