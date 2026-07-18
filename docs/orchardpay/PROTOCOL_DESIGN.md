# OrchardPay Protocol Design

Status: **schema finalized** (Milestone B, refined 2026-07-19 after direct
design review). Identity-key wiring landed. Not yet done: the contract
itself is not registered on any network yet (a one-time per-network
operational step — see `docs/ORCHARDPAY_MIGRATION.md`), and no encryption
module or contact-establishment flow is implemented (Milestones C-E). See
`docs/ORCHARDPAY_MIGRATION.md` for how this relates to DashPay, and
`docs/GLOSSARY.md` for the "Orchard" vs "OrchardPay" naming note.

## Goal

Private P2P contact establishment and messaging on Dash Platform: no public
social graph, no mutual-handshake requirement, and a single extensible channel
that carries payments, memos, payment requests, purchase orders, and receipts
indistinguishably from one another ("anonymity of usecases").

## Privacy constraint that shapes every schema below

Every Dash Platform document exposes its `$ownerId` publicly — that's a
platform-level baseline no contract schema can suppress. So **the counterparty
identity must never appear as a plaintext field** on any of these document
types, or OrchardPay recreates exactly the public social graph DashPay has.
This is also why a `contactAnchor`'s encrypted payload doesn't need to name
the counterparty explicitly — the reader already learns "whose anchor this
is" from the document's own `$ownerId`, so encoding it again inside the
ciphertext would be redundant, not an additional privacy measure.

## Document conventions used

Following Dash Platform's actual data-contract schema conventions (see
`src/ui/contracts_documents/register_contract_screen.rs`,
`contracts_documents_screen.rs`): each document type is a JSON-Schema object
with `properties` (byte-array fields as `"type":"array","byteArray":true` with
`minItems`/`maxItems`), a `required` array, `additionalProperties:false`, an
`indices` array (`{"name":..., "properties":[{"field":"asc|desc"}], "unique": bool}`),
and optional `documentsMutable`/`documentsKeepHistory`/`canBeDeleted` flags.

---

## 1. `shieldedAddress` — publicly queryable

The dapp fetches this document to know where to send the initial ZK/shielded
transaction. `documentsMutable: true` so an identity rotates its address by
updating the same document in place, avoiding "which is the latest" query
logic. `canBeDeleted: true` — an identity can fully opt out of OrchardPay
discoverability by deleting this document, not just leaving it stale.
Unique index on `$ownerId` means one active shielded address per identity.

```json
{
  "shieldedAddress": {
    "type": "object",
    "documentsKeepHistory": false,
    "documentsMutable": true,
    "canBeDeleted": true,
    "properties": {
      "shieldedAddress": {
        "type": "array",
        "byteArray": true,
        "minItems": 40,
        "maxItems": 250,
        "position": 0
      }
    },
    "required": ["shieldedAddress", "$updatedAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byOwner", "properties": [{ "$ownerId": "asc" }], "unique": true }
    ]
  }
}
```

The current Orchard raw payment address is exactly 43 bytes (confirmed
against `SHIELDED_ADDRESS_RAW_LEN` in `src/model/address.rs`), but the field
allows `40..250` bytes deliberately — headroom for a future/different address
encoding without a contract migration. Nothing generates anything other than
today's 43-byte address yet; the range is reserved capacity, not an active
feature. No `protocolVersion` field — see "Dropped: protocolVersion" below.

## 2. `contactAnchor` — encrypted, publishes no plaintext link to the counterparty

`documentsMutable: true`, `canBeDeleted: false` (permanent — the anchor is
meant to survive as a durable personal recovery record, see below),
`documentsKeepHistory: false` (only the current revision is ever retrievable
— fine here, since neither party ever needs a prior revision, see the flow
below). No field or index exposes the counterparty's identity in plaintext.

```json
{
  "contactAnchor": {
    "type": "object",
    "documentsKeepHistory": false,
    "documentsMutable": true,
    "canBeDeleted": false,
    "requiresIdentityEncryptionBoundedKey": 2,
    "requiresIdentityDecryptionBoundedKey": 2,
    "properties": {
      "data": {
        "type": "array",
        "byteArray": true,
        "minItems": 32,
        "maxItems": 5120,
        "position": 0
      },
      "anchorData": {
        "type": "array",
        "byteArray": true,
        "minItems": 0,
        "maxItems": 5120,
        "position": 1
      },
      "extra": {
        "type": "array",
        "byteArray": true,
        "minItems": 0,
        "maxItems": 5120,
        "position": 2
      }
    },
    "required": ["data", "anchorData", "extra", "$updatedAt", "$createdAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byOwner", "properties": [{ "$ownerId": "asc" }] }
    ]
  }
}
```

### `requiresIdentityEncryptionBoundedKey` / `requiresIdentityDecryptionBoundedKey`

These are real, currently-supported Dash Platform data-contract schema
keywords (confirmed directly against the pinned SDK rev's source, not just
documentation) — and they are not optional decoration. Platform's consensus
validation (`validate_identity_public_key_contract_bounds`) rejects any
attempt to register an identity key with
`ContractBounds::SingleContractDocumentType` pointing at a document type that
doesn't declare the matching `requiresIdentity{Encryption,Decryption}BoundedKey`
field — with `DataContractBoundsNotPresentError`. Without this, the
contract-bounded ENCRYPTION/DECRYPTION keys `default_orchardpay_key_specs`
(`src/backend_task/orchardpay/keys.rs`) asks new identities to register would
simply be rejected by Platform the moment the contract went live.

The value `2` maps to `StorageKeyRequirements::MultipleReferenceToLatest`
(`0` = `Unique`, one such key ever; `1` = `Multiple`, many with no special
resolution; `2` = `MultipleReferenceToLatest`). This allows an identity to
hold more than one ENCRYPTION/DECRYPTION key bound to this contract over time
(e.g. across rotations) without a uniqueness conflict, and Platform's own key
lookup (`KeyKindRequestType::CurrentKeyOfKindRequest`, used by
`IdentitiesContractKeysQuery`) resolves to the current/latest one by default.
This solves the key-rotation concern the v0 draft left as an unsolved UX
problem: rotating to a new bounded key just works going forward, with no
special handling needed in OrchardPay's own code. The one caveat that still
holds: an anchor encrypted against an *old* key becomes permanently
undecryptable if that old key is later fully disabled (not just superseded by
a new one) — the "Manage Identity Keys" UI should warn about this specific
case.

**Hardening note (unchanged from the v0 draft):** Platform does not
consensus-enforce `contract_bounds` *content* — the `requiresIdentity*BoundedKey`
check above only gates *whether a key with this purpose+contract-bounds
combination can be registered at all*, not which specific key a piece of
client code chooses to trust when resolving a counterparty's key for ECDH.
Any code doing that resolution must still explicitly verify the returned
key's `contract_bounds()` matches this contract + `contactAnchor` — the
existing DashPay `contact_requests.rs` code does not do this today, and
OrchardPay's equivalent must not repeat that gap.

### Two anchors per relationship, not one

The v0 draft assumed a single anchor (created by the initiator, read once by
the recipient) carried both parties' ReferenceIDs from the start. The actual
design is symmetric and bidirectional — **each party publishes their own
`contactAnchor`**:

1. Alice generates her own ReferenceID, creates her `contactAnchor` (`data` =
   encrypted payload containing at least her ReferenceID — see payload shape
   below), and sends a shielded transaction to Bob's `shieldedAddress` with
   her anchor's DocumentID in the memo.
2. Bob detects the transaction, fetches Alice's anchor **directly by ID**
   (never discoverable by query — this is the core privacy property),
   decrypts `data`, learns it's from Alice (via `$ownerId`, not anything
   inside the ciphertext) and learns her ReferenceID. **This is a read-once
   operation** — Bob never needs to re-fetch Alice's anchor again.
3. If Bob accepts: since Bob already knows Alice's ReferenceID at this point,
   he creates his **own** `contactAnchor` in one shot — `data` contains his
   own ReferenceID, `anchorData` already contains Alice's (no later update
   needed on Bob's side). He sends a return shielded transaction to Alice's
   `shieldedAddress` with his anchor's DocumentID in the memo.
4. Alice detects the return transaction, fetches Bob's anchor, decrypts it,
   learns Bob's ReferenceID — then **updates her own anchor** (this is what
   `documentsMutable: true` is for) to write Bob's ReferenceID into her
   `anchorData` field, completing her side.
5. From this point on, **neither party ever needs the other's document
   again** — each party's own anchor, once complete, is a fully
   self-sufficient personal record (their own ReferenceID in `data`, the
   counterparty's in `anchorData`) usable for recovery via the `byOwner`
   index if they lose local state or move to a new wallet. The mutability
   that makes this possible is safe because Platform's document-ownership
   model means only Alice's own keys can ever sign an update to her own
   anchor — no third party (including Bob) can tamper with it.

**Two distinct ECDH shared secrets, not one.** Alice's anchor is encrypted
using the shared secret from her ENCRYPTION key + Bob's DECRYPTION key; Bob's
return anchor is encrypted using the mirror pairing — his ENCRYPTION key +
Alice's DECRYPTION key. These are cryptographically different values (not a
bug — each document is encrypted for its intended reader using the
appropriate key pairing), so Milestone D's implementation needs to compute
both directions' secrets, not assume one shared secret covers the whole
relationship.

### Payload shape (`data` field, decrypted)

`data` is required and non-empty (`minItems: 32`, matching a bare 32-byte
ReferenceID as the floor); `anchorData` and `extra` are required-but-may-be-
empty (`minItems: 0`) so a document can be created with a placeholder value
and later updated in place without changing its shape. Decrypted, `data`
contains:

```rust
pub struct ContactAnchorPayload {
    /// The only mandatory field.
    pub reference_id: [u8; 32],
    /// Optional: an extended pubkey for L1 Dash Core payments between the
    /// two parties, encrypted the same way DashPay's legacy contact-key
    /// exchange already does it — see `encrypt_extended_public_key` in
    /// `src/backend_task/dashpay/encryption.rs`. Reuse that pattern rather
    /// than inventing a new one.
    pub core_payment_xpub: Option<Vec<u8>>,
    /// Optional, design-only for now (not implemented until a later
    /// milestone): a shielded address dedicated to this specific
    /// relationship, distinct from the identity's one globally-published
    /// `shieldedAddress`. Since shielded transactions don't reveal
    /// sender/recipient on-chain, receiving on a per-contact address would
    /// let an incoming payment be attributed to a specific contact by which
    /// address it landed on, independent of the memo. Needs the wallet's
    /// Orchard implementation to support generating more than one receiving
    /// address per spending key (e.g. diversified addresses) before this is
    /// buildable — not confirmed yet.
    pub dedicated_shielded_address: Option<Vec<u8>>,
    /// Optional: lets the very first message ride along with the contact
    /// request itself, instead of requiring a separate `encryptedMessage`
    /// document as a follow-up.
    pub initial_message: Option<Vec<u8>>,
}
```

`anchorData` (once written) decrypts to the counterparty's own `data`
contents as learned by this document's owner — i.e. the same shape,
containing at minimum the counterparty's ReferenceID. `extra` is reserved for
future use; no defined content yet.

## 3. `encryptedMessage` — polymorphic payload, indistinguishable across use-cases

`documentsMutable: false`. `refId` is the **one** plaintext field beyond the
platform-mandatory `$ownerId`/`$createdAt` — it's a shared secret established
via the anchor's decrypted payload, so indexing it in the clear is safe: an
outside observer can enumerate documents matching a given `refId`, but cannot
derive or guess that value without already being one of the two parties. This
is what makes the channel extensible to any future message type without
protocol changes — new message kinds are just new variants inside `msgData`,
no contract migration needed.

```json
{
  "encryptedMessage": {
    "type": "object",
    "documentsMutable": false,
    "properties": {
      "refId": {
        "type": "array",
        "byteArray": true,
        "minItems": 32,
        "maxItems": 32,
        "position": 0
      },
      "msgData": {
        "type": "array",
        "byteArray": true,
        "minItems": 1,
        "maxItems": 5120,
        "position": 1
      },
      "extra": {
        "type": "array",
        "byteArray": true,
        "minItems": 0,
        "maxItems": 5120,
        "position": 2
      }
    },
    "required": ["refId", "msgData", "$updatedAt", "$createdAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byReferenceIdAndCreated", "properties": [{ "refId": "asc" }, { "$createdAt": "asc" }] },
      { "name": "byOwnerIdAndCreated", "properties": [{ "$ownerId": "asc" }, { "$createdAt": "asc" }] }
    ]
  }
}
```

`byOwnerIdAndCreated` supports a "list messages I've sent" recovery view,
mirroring `contactAnchor`'s own `byOwner` recovery index. Neither index
carries a client-facing sort guarantee beyond what's declared — a "list my
anchors/messages" recovery UI is expected to be small enough to sort
client-side rather than needing the index itself to carry the ordering.

To preserve the "anonymity of usecases" goal, `messageType` (payment / memo /
payment-request / purchase-order / receipt / general-message) is deliberately
**inside** the encrypted payload, not a plaintext top-level field — otherwise
usage-pattern statistics would leak even without identity linkage.
`maxItems: 5120` is Dash Platform's real `max_field_value_size` system limit
(confirmed against the pinned SDK rev's `SYSTEM_LIMITS_V2`). 5 KiB per message
(before AES-GCM/AEAD overhead) is a real constraint on `PurchaseOrder`-style
payloads with many line items; large payloads may need to split across
multiple linked `encryptedMessage` documents (via `reply_to_document_id`) if
this becomes a practical limitation — not addressed in this increment.

```rust
pub struct EncryptedMessageDocument {
    pub reference_id: [u8; 32],
    /// AES-256-GCM ciphertext of `EncryptedMessagePayload`.
    pub msg_data: Vec<u8>,
}

pub enum MessageKind {
    Payment,
    Memo,
    PaymentRequest,
    PurchaseOrder,
    Receipt,
    GeneralMessage,
}

/// Decrypted contents — the actual polymorphic payload.
pub struct EncryptedMessagePayload {
    pub kind: MessageKind,
    pub body: Vec<u8>, // kind-specific serialized fields
    pub reply_to_document_id: Option<[u8; 32]>,
}
```

## Dropped: `protocolVersion`

The v0 draft carried a plaintext `protocolVersion` field on all three
document types for future format/encryption-scheme versioning. Dropped
entirely — if a protocol change is ever needed, a new data contract gets
built rather than versioning within this one. This also keeps every
document's on-chain footprint (and therefore its cost) as low as possible,
which matters given documents are billed by size.

## Contact establishment flow

See "Two anchors per relationship, not one" under `contactAnchor` above for
the full step-by-step flow. In short: Alice creates her anchor and signals
Bob via a shielded-transaction memo; Bob reads it once, and if accepting,
creates his own anchor (already complete, since he knows Alice's ReferenceID
by then) and signals back the same way; Alice reads Bob's anchor once and
updates her own to record his ReferenceID, completing her side. After that,
both parties exchange `encryptedMessage` documents tagged with the agreed
`refId`, for any purpose (payment, memo, request, order, receipt) —
structurally identical regardless of purpose.

## Resolved design decisions

1. **AES-256 key-derivation source for the Contact Anchor**: identity-bound
   `Purpose::ENCRYPTION`/`Purpose::DECRYPTION` keys, contract-bounded to this
   contract's `contactAnchor` document type via `requiresIdentity*BoundedKey`,
   via ECDH — not an HD-path index. Two distinct shared secrets per
   relationship (one per anchor direction), not one.
2. **One or two ReferenceIDs per relationship?** Two — but carried as two
   separate `contactAnchor` documents (one per party), not one document
   holding both from the start.
3. **Exact byte length/encoding of the Orchard shielded address**: 43 bytes
   today, but the schema reserves `40..250` as headroom for a future
   encoding change.
4. **Real Dash Platform per-document byte-size ceiling**: `max_field_value_size
   = 5120` bytes (5 KiB), Platform's actual per-field-value system limit.
5. **`contactAnchor.data` content**: only the ReferenceID is mandatory;
   an L1 payment xpub, a dedicated per-contact shielded address (design-only,
   not yet implemented), and an initial message are all optional additions
   to the same encrypted payload.
6. **`shieldedAddress` deletability**: `canBeDeleted: true` — full opt-out is
   possible, not just leaving the address stale. `contactAnchor` stays
   `canBeDeleted: false` — it's meant to be a permanent recovery record.

## Payment semantics (resolved)

Sending a `Payment`-kind `encryptedMessage` performs a **real** shielded
value transfer, not just a message about a payment: it wraps an actual
shielded transfer (memo-tagged to correlate it with the message thread) plus
the `encryptedMessage` document carrying the amount/note. `Memo` /
`GeneralMessage` / etc. kinds remain pure Platform documents with no value
movement — sending "just a message" stays possible and cheap, distinct from
sending a payment.

## Status of implementation (Milestone tracker — see the OrchardPay plan)

- **Done**: contract schema (this document, `src/backend_task/orchardpay/
  contract_schema.json`), `default_orchardpay_key_specs`
  (`src/backend_task/orchardpay/keys.rs`), identity registration wired to
  request these keys automatically (`combined_default_key_specs` in
  `src/backend_task/identity/mod.rs`, used by both the canonical registration
  builder and the identity-creation UI).
- **Not yet done**: the contract is not registered on any network (a
  one-time per-network operational step, tracked as a hard prerequisite in
  `docs/ORCHARDPAY_MIGRATION.md`); no AES-256-GCM encryption module; no
  contact-establishment flow (search, initiate, detect, accept, the two-anchor
  handshake described above); no messaging send/receive; no local persistence
  layer.
