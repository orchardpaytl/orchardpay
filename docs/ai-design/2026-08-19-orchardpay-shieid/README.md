# `shie_id`: a forward-looking identifier for shielded documents

Status: **implemented** (plumbing only — no consumer yet).

## Why

Dash Platform will support shielded documents — documents with no `ownerId`,
built for privacy use cases the same way `contactAnchor`/`encryptedMessage`
already are. OrchardParty, the next dApp planned inside OrchardPay, will need
a way for each side of a contact relationship to find shielded documents the
*other* side later publishes. That requires a Platform identifier, agreed
during the `contactAnchor` handshake, that the receiving party can use as a
lookup key once shielded documents (and OrchardParty's own query logic) exist.

`reference_id` already solves the equivalent problem for `encryptedMessage`:
each side generates one, exchanges it during the handshake, and later reuses
it as `encryptedMessage.refId` so the other party can query for their
messages (`PROTOCOL_DESIGN.md`'s "Payload shape" section). `shie_id` is the
same idea, generated and exchanged alongside `reference_id`, for shielded
documents instead of `encryptedMessage`.

## Why mirror `reference_id` instead of designing something new

Nothing about the eventual shielded-document lookup mechanism is known yet —
OrchardParty doesn't exist, and neither does Platform's shielded-document
support. Inventing a bespoke exchange mechanism now would be designing
against a moving target. `reference_id`'s handshake-time lifecycle is already
built, tested, and reviewed (including its anti-fingerprinting treatment —
see below), so reusing it exactly:

- Costs nothing extra in the handshake (`shie_id` rides along in the same
  `data`/`anchorData` payloads, encrypted the same way, at the same points).
- Keeps the two identifiers consistent — no observer can distinguish
  `shie_id`'s presence/timing from `reference_id`'s.
- Leaves the actual lookup design fully deferred to whenever OrchardParty's
  own design work starts, informed by whatever Platform's real
  shielded-document query shape turns out to be.

## What changed

Two 32-byte identifiers per relationship instead of one, generated the same
way (`OsRng`, once, at anchor creation) and carried through the same three
places `reference_id` already lives:

1. **`ContactAnchorPayload.shie_id`** — sent to the counterparty inside
   `contactAnchor.data`, ECDH-encrypted so only they can decrypt it. Each
   side generates and sends their own.
2. **`AnchorDataRecord.my_shie_id` / `their_shie_id`** — the wallet-local
   `anchorData` field's durable copy of both my own and the counterparty's
   `shie_id`, encrypted under the wallet's own local key. `their_shie_id`
   is seeded with the same self-recognizable filler `their_reference_id`
   gets (this identity's own ID) until the real value is known, and swapped
   for the real value by the same deferred `ScheduledAnchorReplace` that
   already swaps `their_reference_id` — one combined `ReplaceDocument`
   publish covers both fields, so no new timing signal is introduced.
3. **`OrchardPayContactState`** (`PendingOutbound`/`PendingInboundUnaccepted`/
   `Established`) and **`PendingOrchardPayOperation::ContactAnchor`** — the
   in-memory/local-KV mirrors, gaining `my_shie_id`/`their_shie_id` fields
   alongside their `reference_id` counterparts, including the
   generated-once-reused-on-resume treatment `PendingOrchardPayOperation`
   already gives `my_reference_id`.

See `PROTOCOL_DESIGN.md`'s "`shie_id`: a forward-looking identifier for
shielded documents" section for the payload-shape details.

## Scope boundary

This change is plumbing only: generate, exchange, persist. No Platform
schema change (both fields already fit inside `contactAnchor`'s existing
opaque `data`/`anchorData` byte blobs), no query/lookup logic, no UI.
`src/backend_task/orchardpay/messages.rs` (the `encryptedMessage`/`refId`
messaging layer) and all of `src/ui/orchardpay/` are untouched — `shie_id`
has no reader anywhere in the codebase yet. That's deliberate: the lookup
mechanism is OrchardParty's own design problem, not this change's.

## Accepted breakage

`ContactAnchorPayload`, `AnchorDataRecord`, `OrchardPayContactState`, and
`PendingOrchardPayOperation` are all bincode-encoded (non-self-describing)
before encryption/storage. Adding fields to them means already-published
`contactAnchor` documents and already-persisted local KV state (from before
this change) will fail to decode after upgrade — anchors show up as
`undecryptable` in recovery scans; local contact state read errors surface
as `TaskError::OrchardPaySidecarStorage`. This matches documented project
precedent (`PROTOCOL_DESIGN.md`'s "Dropped: `protocolVersion`": *"if a
protocol change is ever needed, a new data contract gets built rather than
versioning within this one"*) and how `initial_message` was previously added
to `ContactAnchorPayload` with no migration path. No versioning/migration
work is in scope here either.
