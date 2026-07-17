# OrchardPay Protocol Design

Status: **schema finalized, identity-key wiring landed** (Milestone B). All 4
open design questions below are resolved. Not yet done: the contract itself
is not registered on any network yet (a one-time per-network operational
step — see `docs/ORCHARDPAY_MIGRATION.md`), and no encryption module or
contact-establishment flow is implemented (Milestones C-E). See
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

## Document conventions used

Following Dash Platform's actual data-contract schema conventions (see
`src/ui/contracts_documents/register_contract_screen.rs`,
`contracts_documents_screen.rs`): each document type is a JSON-Schema object
with `properties` (byte-array fields as `"type":"array","byteArray":true` with
`minItems`/`maxItems`), a `required` array, `additionalProperties:false`, an
`indices` array (`{"name":..., "properties":[{"field":"asc|desc"}], "unique": bool}`),
and an optional `documentsMutable` flag.

---

## 1. `shieldedAddress` — publicly queryable

The dapp fetches this document to know where to send the initial ZK/shielded
transaction. `documentsMutable: true` so an identity rotates its address by
updating the same document in place, avoiding "which is the latest" query
logic. Unique index on `$ownerId` means one active shielded address per
identity in v1.

```json
{
  "shieldedAddress": {
    "type": "object",
    "documentsMutable": true,
    "properties": {
      "shieldedAddress": {
        "type": "array",
        "byteArray": true,
        "minItems": 43,
        "maxItems": 43,
        "position": 0
      },
      "protocolVersion": { "type": "integer", "minimum": 1, "position": 1 }
    },
    "required": ["shieldedAddress", "protocolVersion", "$createdAt", "$updatedAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byOwner", "properties": [{ "$ownerId": "asc" }], "unique": true }
    ]
  }
}
```

```rust
// Design sketch — not yet backed by real create/query task code (Milestone C).
pub struct ShieldedAddressDocument {
    /// Raw Orchard payment address bytes. Confirmed 43 bytes (raw address
    /// per ZIP-316), matching `SHIELDED_ADDRESS_RAW_LEN` in
    /// `src/model/address.rs`, backed by the SDK's own `OrchardAddress` type.
    pub shielded_address: Vec<u8>,
    pub protocol_version: u32,
}
```

## 2. `contactAnchor` — encrypted, publishes no plaintext link to the counterparty

`documentsMutable: false`. No field or index exposes the counterparty's
identity. The recipient learns this document's ID out-of-band, via the ZK
transaction memo (the sender's Contact Anchor DocumentID travels in the
shielded memo field), then does a direct `getDocument(documentId)` lookup —
they never discover it by querying. The `byOwnerAndCreated` index only serves
the *creator's own* bookkeeping/recovery UI (list of anchors I've published).

```json
{
  "contactAnchor": {
    "type": "object",
    "documentsMutable": false,
    "properties": {
      "encryptedPayload": {
        "type": "array",
        "byteArray": true,
        "minItems": 32,
        "maxItems": 512,
        "position": 0
      },
      "protocolVersion": { "type": "integer", "minimum": 1, "position": 1 }
    },
    "required": ["encryptedPayload", "protocolVersion", "$createdAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byOwnerAndCreated", "properties": [{ "$ownerId": "asc" }, { "$createdAt": "asc" }] }
    ]
  }
}
```

**Key derivation (resolved, replaces the earlier `keyDerivationHint` HD-index
draft):** the AES-256 key comes from an ECDH shared secret between two
identity-bound Platform keys, not a wallet HD index — so no hint field is
needed at all. Every identity gets one `Purpose::ENCRYPTION`/
`Purpose::DECRYPTION` key pair (added at identity-creation time — see
`default_orchardpay_key_specs` in `src/backend_task/orchardpay/keys.rs`),
contract-bounded via `ContractBounds::SingleContractDocumentType` to this
contract's `contactAnchor` document type. To establish a `contactAnchor`,
Alice fetches Bob's contract-bounded DECRYPTION key (via Platform's
`IdentitiesContractKeysQuery`, filtered by contract + document type +
purpose) and derives the ECDH shared secret against her own ENCRYPTION key,
using the same DIP-15-style algorithm as the existing (legacy) DashPay
contact-key exchange in `src/backend_task/dashpay/encryption.rs`'s
`generate_ecdh_shared_key` (called directly, not forked). This is why one key
pair per identity is enough for the whole relationship: the derived shared
secret is cached and reused for every subsequent `encryptedMessage`, not
re-derived per message, so no separate key is needed for that document type.
Key rotation/recovery: Platform identity keys are individually addressable by
`key_id`, and rotation is identity-native (an identity-update transition) —
disabling an ENCRYPTION/DECRYPTION key bounded to this contract makes past
anchors/messages encrypted against it permanently undecryptable, so the
"Manage Identity Keys" UI must warn about this before disabling such a key.
**Hardening note:** Platform does not consensus-enforce `contract_bounds` for
ENCRYPTION/DECRYPTION purposes — it's a client-side convention only (unlike
AUTHENTICATION signing keys). Any code resolving a counterparty's key for
ECDH must explicitly verify the returned key's `contract_bounds()` matches
this contract + `contactAnchor` before using it — the existing DashPay
`contact_requests.rs` code does not do this today, and OrchardPay's
equivalent must not repeat that gap.

```rust
pub struct ContactAnchorDocument {
    /// AES-256-GCM ciphertext of `ContactAnchorPayload` (see below).
    pub encrypted_payload: Vec<u8>,
    pub protocol_version: u32,
}

/// Decrypted contents of `encryptedPayload`. Never appears on-chain in
/// plaintext.
pub struct ContactAnchorPayload {
    pub counterparty_identity_id: [u8; 32],
    /// ReferenceID this anchor's creator will use when tagging future
    /// Encrypted Message/Data Documents sent TO the counterparty.
    pub reference_id_outbound: [u8; 32],
    /// ReferenceID this anchor's creator should watch for on incoming
    /// Encrypted Message/Data Documents FROM the counterparty.
    pub reference_id_inbound: [u8; 32],
    pub created_at: u64,
}
```

## 3. `encryptedMessage` — polymorphic payload, indistinguishable across use-cases

`documentsMutable: false`. `referenceId` is the **one** plaintext field beyond
the platform-mandatory `$ownerId`/`$createdAt` — it's a shared secret
established via the anchor's decrypted payload, so indexing it in the clear is
safe: an outside observer can enumerate documents matching a given
`referenceId`, but cannot derive or guess that value without already being one
of the two parties. This is what makes the channel extensible to any future
message type without protocol changes — new message kinds are just new
variants inside `encryptedPayload`, no contract migration needed.

```json
{
  "encryptedMessage": {
    "type": "object",
    "documentsMutable": false,
    "properties": {
      "referenceId": {
        "type": "array",
        "byteArray": true,
        "minItems": 32,
        "maxItems": 32,
        "position": 0
      },
      "encryptedPayload": {
        "type": "array",
        "byteArray": true,
        "minItems": 32,
        "maxItems": 5120,
        "position": 1
      },
      "protocolVersion": { "type": "integer", "minimum": 1, "position": 2 }
    },
    "required": ["referenceId", "encryptedPayload", "protocolVersion", "$createdAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byReferenceIdAndCreated", "properties": [{ "referenceId": "asc" }, { "$createdAt": "asc" }] }
    ]
  }
}
```

To preserve the "anonymity of usecases" goal, `messageType` (payment / memo /
payment-request / purchase-order / receipt / general-message) is deliberately
**inside** the encrypted payload, not a plaintext top-level field — otherwise
usage-pattern statistics would leak even without identity linkage.
`maxItems: 5120` is Dash Platform's real `max_field_value_size` system limit
(confirmed against the pinned SDK rev's `SYSTEM_LIMITS_V2`), not a
placeholder — the earlier 16384 draft value was too high and would have been
rejected at contract registration. 5 KiB per message (before AES-GCM/AEAD
overhead) is a real constraint on `PurchaseOrder`-style payloads with many
line items; large payloads may need to split across multiple linked
`encryptedMessage` documents (via `reply_to_document_id`) if this becomes a
practical limitation — not addressed in this increment.

```rust
pub struct EncryptedMessageDocument {
    pub reference_id: [u8; 32],
    /// AES-256-GCM ciphertext of `EncryptedMessagePayload`.
    pub encrypted_payload: Vec<u8>,
    pub protocol_version: u32,
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

## Contact establishment flow (informal)

1. Alice publishes/updates her `shieldedAddress` document (or reads Bob's).
2. Alice sends a shielded/ZK transaction to Bob's shielded address; the ZK
   memo field carries Alice's `contactAnchor` DocumentID.
3. Alice also publishes her own `contactAnchor` document (encrypted payload
   contains Bob's identity + the two ReferenceIDs).
4. Bob detects the incoming shielded transaction, reads the memo, fetches
   Alice's `contactAnchor` document directly by ID, and (via information only
   Bob has — see open question 1) decrypts it to learn the ReferenceIDs.
5. Both parties now exchange `encryptedMessage` documents tagged with the
   agreed `referenceId`, for any purpose (payment, memo, request, order,
   receipt) — structurally identical regardless of purpose.

## Resolved design decisions

1. **AES-256 key-derivation source for the Contact Anchor**: identity-bound
   `Purpose::ENCRYPTION`/`Purpose::DECRYPTION` keys, contract-bounded to this
   contract's `contactAnchor` document type, via ECDH — not an HD-path index.
   See the `contactAnchor` section above for the full rationale. This is the
   protocol-idiomatic path: Platform ships a dedicated purpose/contract-bounds
   system and a first-class query (`IdentitiesContractKeysQuery`) for exactly
   this, and it's the cheapest to implement given the existing (legacy)
   DashPay ECDH code this reuses.
2. **One or two ReferenceIDs per relationship?** Two —
   `reference_id_outbound` / `reference_id_inbound`, as originally drafted.
3. **Exact byte length/encoding of the Orchard shielded address**: 43 bytes,
   confirmed against `SHIELDED_ADDRESS_RAW_LEN` in `src/model/address.rs`.
4. **Real Dash Platform per-document byte-size ceiling**: `max_field_value_size
   = 5120` bytes (5 KiB), Platform's actual per-field-value system limit —
   see the `encryptedMessage` section above.

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
  contact-establishment flow (search, initiate, detect, accept); no
  messaging send/receive; no local persistence layer.
