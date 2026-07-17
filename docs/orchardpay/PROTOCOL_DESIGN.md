# OrchardPay Protocol Design (v0 draft)

Status: **design doc only** — no contract registered, no SDK/task wiring, no
crypto implemented. See `docs/ORCHARDPAY_MIGRATION.md` for how this relates to
DashPay, and `docs/GLOSSARY.md` for the "Orchard" vs "OrchardPay" naming note.

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
// Design sketch only — not compiled in this increment.
pub struct ShieldedAddressDocument {
    /// Raw Orchard payment address bytes.
    /// TODO(confirm): exact length/encoding against dash_sdk's
    /// `grovedb_commitment_tree::PaymentAddress` serialization
    /// (see src/model/wallet/shielded.rs). Sketch assumes 43 bytes
    /// (raw Orchard address per ZIP-316) — verify before finalizing.
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
      "keyDerivationHint": { "type": "integer", "minimum": 0, "position": 1 },
      "protocolVersion": { "type": "integer", "minimum": 1, "position": 2 }
    },
    "required": ["encryptedPayload", "keyDerivationHint", "protocolVersion", "$createdAt"],
    "additionalProperties": false,
    "indices": [
      { "name": "byOwnerAndCreated", "properties": [{ "$ownerId": "asc" }, { "$createdAt": "asc" }] }
    ]
  }
}
```

`keyDerivationHint` is a small public integer (an HD child-key index), **not
the key itself** — it lets the anchor's *creator* deterministically recompute
the same AES-256 key later from their own wallet seed even if all other local
state (or ZK transaction history) is lost, satisfying the pruning-resilience/
recovery design goal for the creator's side. The recipient still needs the key
delivered confidentially via the ZK memo channel, since they don't share the
sender's seed.

```rust
pub struct ContactAnchorDocument {
    /// AES-256-GCM ciphertext of `ContactAnchorPayload` (see below).
    pub encrypted_payload: Vec<u8>,
    /// HD child-key index used to derive the AES-256 key from the creator's
    /// own contact-key seed chain. Mirrors the DIP-14-style derivation
    /// pattern already used by src/backend_task/dashpay/hd_derivation.rs,
    /// but on a separate, OrchardPay-specific derivation path — this
    /// separation is what implements the "encryption independence" design
    /// goal (ZK-layer encryption and platform-document encryption can be
    /// upgraded independently).
    pub key_derivation_hint: u32,
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
        "maxItems": 16384,
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
`maxItems: 16384` is a placeholder; confirm the actual Dash Platform
per-document byte-size limit before finalizing.

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

## Open design questions (not resolved in this increment)

1. **AES-256 key-derivation source for the Contact Anchor.** This draft
   assumes an HD-path index (`keyDerivationHint`) on the sender's own
   contact-key chain, mirroring `src/backend_task/dashpay/hd_derivation.rs`'s
   DIP-14 pattern but on an OrchardPay-specific path. Need to confirm this
   matches the intended design versus, e.g., deriving from a value embedded
   in the ZK viewing key (which would let the recipient derive the key
   without needing anything delivered via the memo beyond the DocumentID).
2. **One or two ReferenceIDs per relationship?** This draft assumes two
   (`reference_id_outbound` / `reference_id_inbound`), matching the articles'
   plural "both parties' ReferenceIDs" — confirm versus a single shared value
   used by both directions.
3. **Exact byte length/encoding of the Orchard shielded address** — 43 bytes
   assumed (raw address per ZIP-316); verify against `dash_sdk`'s actual
   `PaymentAddress` serialization in `src/model/wallet/shielded.rs`.
4. **Real Dash Platform per-document byte-size ceiling** — needed to set a
   real (not placeholder) `maxItems` on the `encryptedPayload` fields.

## Non-goals for this increment

No working ZK contact-establishment flow, no AES-256 encrypt/decrypt
implementation, no contract registration on any network, no new `src/`
modules or `RootScreenType` variant. This document is the input to that next
increment, once reviewed.
