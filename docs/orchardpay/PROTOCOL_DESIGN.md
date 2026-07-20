# OrchardPay Protocol Design

Status: **schema finalized** (Milestone B). Identity-key wiring, shielded
address publish/discover (Milestone C), and the full contact-establishment
handshake plus DPNS search (Milestone D) have all landed and are registered
on Testnet — see "Status of implementation" below for exact file pointers.
Not yet done: messaging send/receive and payments-with-memos (Milestone E),
recovery UI (Milestone F), Mainnet/Devnet contract registration. See
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
   `documentsMutable: true` is for) to write Bob's ReferenceID (plus the
   rest of what she now knows about him) into her `anchorData` field,
   completing her side.
5. From this point on, **neither party ever needs the other's document
   again** — each party's own anchor, once complete, is a fully
   self-sufficient personal record usable for recovery via the `byOwner`
   index if they lose local state or move to a new wallet. The mutability
   that makes this possible is safe because Platform's document-ownership
   model means only Alice's own keys can ever sign an update to her own
   anchor — no third party (including Bob) can tamper with it.

`anchorData` is not purely something written once, at step 4 — Alice already
knows Bob's identity ID and DPNS name at step 1 (she looked him up to find
his `shieldedAddress` before ever contacting him), so she writes a *partial*
`anchorData` at creation time (counterparty identity + name, her own
ReferenceID, `their_reference_id: None`) and only the `ReplaceDocument` at
step 4 fills in the piece she was actually missing. Even a still-pending
outbound request is locally recoverable, not just a completed relationship —
see "`anchorData`: a wallet-local recovery record" below for the full
content model and why it no longer shares `data`'s encryption scheme.

**Memo delivery caveat (see `docs/ai-design/2026-07-18-orchardpay-memo-detection/`
for the full writeup):** step 2 above ("Bob detects the transaction") assumes
incoming shielded-transfer memo bytes are observable by application code.
They aren't, by default — the wallet's own sync coordinator trial-decrypts
incoming notes with a compact decryption path that structurally cannot
recover the memo. Milestone D works around this with a DET-side duplicate
scan (OrchardPay re-derives the wallet's incoming viewing key and calls the
SDK's memo-preserving decryption primitive itself, redundantly re-scanning
notes the coordinator has already scanned once). This is a deliberate,
documented interim choice, not an oversight — see the linked doc for why, and
for what it'd take to eliminate the duplicate work later.

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
    /// address it landed on, independent of the memo. **Confirmed
    /// buildable** (this was an open question, now resolved): the wallet's
    /// `OrchardKeySet::address_at(index)` (`rs-platform-wallet/src/wallet/
    /// shielded/keys.rs`) already derives a fresh diversified address at any
    /// index off the same FVK — only index 0 is used anywhere in the app
    /// today, but the underlying capability exists. See "Future: account
    /// separation" below for a related idea to capture alongside this.
    pub dedicated_shielded_address: Option<Vec<u8>>,
    /// Optional: lets the very first message ride along with the contact
    /// request itself, instead of requiring a separate `encryptedMessage`
    /// document as a follow-up.
    pub initial_message: Option<Vec<u8>>,
}
```

`extra` is reserved for future use; no defined content yet. `anchorData` has
its own, different content model and encryption scheme — see the next
section; it no longer just mirrors the counterparty's `data`.

### `anchorData`: a wallet-local recovery record (decided 2026-07-19, not yet implemented)

`data` and `anchorData` look symmetric in the schema (both `byteArray`,
both on the same document) but serve fundamentally different readers.
`data` has to be decryptable by *two* parties — the owner and the
counterparty — so it has to stay ECDH-based. `anchorData` is read by
exactly one party, ever: the document's own owner. Encrypting a
self-only field with two-party key agreement was a consistency shortcut
in the original design, not a real requirement, and it inherited ECDH's
real cost for no benefit: decrypting your own notes required a live
`IdentitiesContractKeysQuery` for the counterparty's *current* key, and
broke permanently if either side's key ever got disabled.

**Key source: one fixed AES-256 key per wallet, HD-derived, not ECDH.**

```
m / 420' / 5' / 1'
```

- `420'` — a new, unclaimed top-level BIP43 `purpose'` value, claimed here
  as a forward-looking bet on a future DIP reservation for this scheme (no
  such DIP exists yet). This is a deliberate, accepted risk, not an
  oversight: top-level `purpose'` numbers are a namespace shared across
  wallets, and every other feature in this wallet's tree instead lives as a
  sub-branch under the existing DIP-9 `9'` umbrella (DashPay `9'/coin'/15'`,
  CoinJoin `9'/coin'/4'`, masternode keys `9'/coin'/3'`, etc. — see
  `key-wallet/src/dip9.rs`). If a real, conflicting DIP-420 is ever
  standardized, this derivation would need to migrate. Chosen anyway,
  eyes open.
- `5'` — Dash's coin type (mainnet; `1'` on testnet, matching every other
  path in this wallet).
- `1'` — fixed leaf; there is exactly one key for this feature. No
  `account'` or `identity_index'` component: **one key for the whole
  wallet**, shared across every identity that wallet manages, not one key
  per identity. Sharing the key across identities under one wallet is
  harmless (they already trace to the same seed/owner) and keeps recovery
  down to a single re-derivation regardless of how many identities the
  wallet holds.

Derived once via the existing secret chokepoint
(`SecretAccess::with_secret_session` / `SecretScope::HdSeed`, the same
pattern `derive_contact_info_encryption_keys` in
`src/wallet_backend/dashpay.rs` already uses for a DIP-15 sub-branch),
using the wallet's generic `Wallet::derive_private_key(&self, path:
&DerivationPath)` — no new secret-handling plumbing needed. This is the
first purely local, non-identity, non-payment symmetric secret derived in
this codebase; there was no existing precedent to follow, so this section
*is* the precedent going forward. If a future feature wants its own local
secret, it should get its own leaf under a documented path, not reuse this
one — this key's scope is deliberately narrow (see the nonce-reuse note
below).

**AES-256-GCM under a reused key — checked, not assumed.** The rule that
matters for GCM isn't "don't reuse the key" (reusing a key across many
messages is GCM's normal, intended usage — it's how TLS 1.3 uses one
session key across every record in a connection); it's "never repeat a
(key, nonce) pair under that key." `src/backend_task/orchardpay/
encryption.rs` already draws a fresh 96-bit nonce from `OsRng` (a real
CSPRNG) per encryption — that doesn't change. NIST SP 800-38D gives an
explicit ceiling for randomly-chosen 96-bit GCM nonces under one key:
stay under 2³² invocations to keep collision probability below ~2⁻³².
This key's realistic lifetime volume — one `anchorData` write per contact
at creation plus occasional replaces — is nowhere close: even 10,000
contacts each edited 10 times is 100,000 encryptions ever, ~43,000×
below the NIST ceiling, with actual collision probability around 10⁻²⁰.
No nonce-counter scheme needed at this scale; random nonces are the
correct, simpler choice here.

**Content model.** Decrypted, `anchorData` contains:

```rust
pub struct AnchorDataRecord {
    /// The counterparty's identity — safe to store here because this whole
    /// field is encrypted; nothing about the privacy constraint at the top
    /// of this document changes.
    pub counterparty_identity_id: [u8; 32],
    /// DPNS name snapshot at the time contact was established. Not
    /// live-updated if the counterparty later renames — re-resolving on
    /// every read would reintroduce the network dependency this whole
    /// redesign removes. A stale snapshot is an acceptable, deliberate
    /// tradeoff for a record whose job is "who was this," not "who is
    /// this right now."
    pub counterparty_name_snapshot: Option<String>,
    /// Duplicated from this document's own `data` field — the whole point
    /// of this redesign is that `anchorData` survives independently of
    /// whether `data` is still decryptable.
    pub my_reference_id: [u8; 32],
    /// `None` until the counterparty's return signal is decrypted; filled
    /// in by the `ReplaceDocument` at step 4 of the handshake above.
    pub their_reference_id: Option<[u8; 32]>,
    /// Mirrors of `data`'s own optional fields — same rationale as
    /// `my_reference_id`: everything given to this contact should survive
    /// independently of the fragile ECDH path, not just the ReferenceID.
    pub my_initial_message: Option<Vec<u8>>,
    pub my_core_payment_xpub: Option<Vec<u8>>,
    pub my_dedicated_shielded_address: Option<Vec<u8>>,
    /// Cached ECDH inputs, not cached secrets — see below.
    pub counterparty_encryption_pubkey: Option<Vec<u8>>,
    pub counterparty_decryption_pubkey: Option<Vec<u8>>,
}
```

**Caching the counterparty's public keys, not the derived secrets.** The
motivating problem: reading a contact's messages (or their `data`) needs
`ECDH(my private key, their current public key)`, and fetching "their
current public key" is a live `IdentitiesContractKeysQuery` every time —
paid once at anchor-establishment, then again on every message poll once
Milestone E exists. The fix is to cache the counterparty's **public** key
bytes in `anchorData` (fetched once, already paid for) rather than the
**derived shared secret** itself. Decrypting later still computes
`ECDH(my own private key [always local, free], their cached public key
[from anchorData, free])` — identical elimination of the repeated network
call, at the cost of one cheap scalar multiplication per decrypt instead
of a direct lookup.

This was a deliberate choice over caching the raw secret directly: if
`anchorData`'s *decrypted* content were ever exposed by some means short of
a full wallet-seed compromise (a bug that logs decrypted state, a
memory-scraping attack against the running app — a meaningfully lower bar
than "the seed leaked, everything is already lost"), a cached raw secret
hands over live message-decryption capability for every contact
immediately. A cached public key only hands over "who their key was" —
still useless without separately obtaining the reader's own private key
too. Same performance, smaller exposure for a cheaper class of compromise.

Both directions get cached (`counterparty_encryption_pubkey` for reading
what they send — the ENCRYPTION key they used, paired with my DECRYPTION
key; `counterparty_decryption_pubkey` for encrypting what I send them),
since Milestone E's messaging uses both repeatedly, not just the read
direction. A cached key going stale (the counterparty rotated) just means
decryption/encryption under it quietly fails — the caller should re-fetch
and retry once, not treat a cache miss as permanent.

**Recovery consequence.** This closes most, not all, of the relaunch gap
recorded in `docs/ai-design/2026-07-19-orchardpay-query-workflow-reference/`:
`byOwner` → fetch every anchor → decrypt every `anchorData` with one
re-derived wallet-local key → full contact list, names, both ReferenceIDs,
initial messages, and exchanged keys/addresses recovered, no network
dependency beyond the initial fetch, even if the identity's ENCRYPTION/
DECRYPTION keys are lost entirely. What's still lost in that scenario:
`data` itself and anything actually encrypted under the old per-relationship
ECDH secrets (old messages, the counterparty's own view of the anchor) —
those still need the ENCRYPTION private key, which remains
randomly-generated (`KeyType::random_public_and_private_key_data`), not
seed-derived. Making those keys HD-derived too is the natural companion fix
for the *other* half of that gap — a related but separate decision, not
bundled into this one.

**No migration needed.** No `contactAnchor` documents have been created on
any network yet (Milestone D shipped the contract and the code path, but
no real handshake has run), so this is a clean redesign, not a breaking
change against live data.

### Future: account separation (captured 2026-07-20, not implemented)

Every Orchard key in this wallet derives from `m / 32' / coin_type' /
account'` (ZIP-32), and today **every shielded operation across the whole
app hardcodes `account = 0`** — confirmed at the actual call sites:
`src/context/wallet_lifecycle/bootstrap.rs`'s `shielded_default_address(seed_hash,
0)` (the address `shieldedAddress` documents currently publish) and
`shielded_transfer(.., 0, ..)` (the only account the spend path can spend
from). The code's own comment is explicit: *"the only account DET binds."*

Idea to revisit once the dedicated per-contact shielded address feature
above is actually being built: **move the `shieldedAddress` document's
address off account 0 onto account 1**, reserving account 0 for
onboarding/general wallet shielding and giving OrchardPay's own
discoverable address (and, later, per-contact diversified addresses derived
from it) a clean separation from a user's general shielded-balance activity.
Rationale: account 0 is where a user's first shield/unshield/general
shielded-send activity naturally happens during onboarding; keeping
OrchardPay's contact-discovery address on a distinct account avoids mixing
"this is how people reach me for OrchardPay" with "this is my general
shielded spending," even though both ultimately derive from the same wallet
seed and are only as private from each other as account-level separation
provides (not a strong privacy boundary — Orchard's own shielding is what
actually hides transaction contents, not which account issued them from the
same seed).

**Not free to build**: this isn't just changing a constant. The wallet's
shielded coordinator currently only binds/syncs account 0 (per the "only
account DET binds" comment) — using account 1 would need the coordinator to
additionally bind and sync that second account, which is `platform-wallet`
(upstream) territory, not just an OrchardPay-side change. Scope this as its
own investigation when the dedicated-per-contact-address feature is
actually being built, not assumed to be a small tweak. Milestone C proceeds
on account 0 as-is for now — this is a deliberate deferral, not an
oversight.

## 3. `encryptedMessage` — polymorphic payload, indistinguishable across use-cases

`documentsMutable: true`, `canBeDeleted: true`, `documentsKeepHistory: false`
— sent messages can be edited or deleted, a deliberate chat-app-style UX
feature (Signal/WhatsApp/Slack-style message editing), not an oversight. See
"Editing and deleting messages" below for how this is reconciled with
`Payment`-kind messages documenting a real value transfer. `refId` is the
**one** plaintext field beyond the platform-mandatory `$ownerId`/`$createdAt`
— it's a shared secret established via the anchor's decrypted payload, so
indexing it in the clear is safe: an outside observer can enumerate documents
matching a given `refId`, but cannot derive or guess that value without
already being one of the two parties. This is what makes the channel
extensible to any future message type without protocol changes — new message
kinds are just new variants inside `msgData`, no contract migration needed.

```json
{
  "encryptedMessage": {
    "type": "object",
    "documentsKeepHistory": false,
    "documentsMutable": true,
    "canBeDeleted": true,
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

### Editing and deleting messages

`documentsMutable`/`canBeDeleted` default to `true` on Dash Platform when a
document type doesn't override them (confirmed against
`DEFAULT_CONTRACT_DOCUMENT_MUTABILITY`/`DEFAULT_CONTRACT_DOCUMENTS_CAN_BE_DELETED`
in the pinned SDK rev) — so `encryptedMessage` documents were always
deletable by their owner even under the v1 schema above, which only
overrode `documentsMutable` to `false`. Both flags are now set explicitly
here for clarity, and `documentsMutable` is flipped to match the platform
default rather than override it: a sender can edit or delete a message they
sent (Platform's document-ownership model means only they ever could,
regardless of this flag — no third party, including the recipient, can
mutate or delete someone else's message).

This creates a real tension with `Payment`-kind messages, which document a
value transfer that already happened on-chain (see "Payment semantics"
below): if the message is editable, a sender could later change what it
claims about that payment — amount, note, even `kind` — with no
`documentsKeepHistory` to show what it originally said. The resolution isn't
to prevent edits (there's no schema mechanism to make mutability conditional
on the *decrypted* `kind`, since Platform only sees the document type, not
its ciphertext contents) but to make them **detectable**: `$createdAt` and
`$updatedAt` are both required fields on every `encryptedMessage`, so a
recipient can always tell a message was edited after the fact by comparing
the two, even without knowing what changed. The real, authoritative record
of *how much value moved* is always the on-chain shielded transfer itself,
never the message — the message is supplementary. Milestone E's UI should
surface an "edited" indicator whenever `$updatedAt != $createdAt`, and
should gracefully handle a `reply_to_document_id` that no longer resolves
(the referenced message was deleted) rather than treating it as an error.

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

1. **AES-256 key-derivation source for the Contact Anchor**: `data` stays
   identity-bound `Purpose::ENCRYPTION`/`Purpose::DECRYPTION` keys,
   contract-bounded to this contract's `contactAnchor` document type via
   `requiresIdentity*BoundedKey`, via ECDH — two distinct shared secrets per
   relationship (one per anchor direction), not one. `anchorData` does
   **not** — it's self-only (never read by the counterparty), so it uses a
   single fixed HD-derived AES-256 key instead (`m/420'/5'/1'`, one per
   wallet) — see "`anchorData`: a wallet-local recovery record" above for
   the full reasoning.
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
7. **`encryptedMessage` mutability**: `documentsMutable: true`,
   `canBeDeleted: true` (matching Platform's own defaults, now made
   explicit) — sent messages can be edited/deleted as a deliberate UX
   feature. Reconciled with `Payment`-kind messages documenting a real value
   transfer by making edits *detectable* (`$createdAt` vs `$updatedAt`)
   rather than preventing them — see "Editing and deleting messages" above.

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
  builder and the identity-creation UI). **Contract registered on Testnet**
  as `Hk5Tajxf4FNUjh3S9Sqq7ZFYm3p3b8dPpDEWszJp5Juw` (2026-07-20) — see
  `docs/ORCHARDPAY_MIGRATION.md` for the per-network registration status.
- **Done (Milestone C, 2026-07-18)**: `shieldedAddress` publish/lookup
  (`src/backend_task/orchardpay/shielded_address.rs`), `ShieldedAddressSetupScreen`,
  wired into the onboarding chain and a 4-step progress stepper.
- **Done (Milestone D, 2026-07-18)**: AES-256-GCM encryption
  (`src/backend_task/orchardpay/encryption.rs`), the bounds-verified
  counterparty key lookup (`keys::fetch_bounds_verified_counterparty_key`),
  the full two-anchor handshake (`contact_anchor.rs` — initiate, accept,
  and the memo-triggered complete-outbound step), local contact state as a
  k/v sidecar (`src/wallet_backend/orchardpay.rs`, not SQLite — see that
  file's module doc for why), DPNS-based contact search
  (`contact_search.rs`), and the DET-side duplicate incoming-memo scan with
  automatic triggering off every shielded sync pass (`memo_scan.rs` +
  `docs/ai-design/2026-07-18-orchardpay-memo-detection/`). UI:
  `OrchardPayScreen` (Contacts/Search subscreens), reachable from the left
  nav as "Private Contacts".
- **Decided, not yet implemented (2026-07-19)**: the `anchorData`
  redesign — wallet-local HD key (`m/420'/5'/1'`), the
  `AnchorDataRecord` content model, and public-key caching for both ECDH
  directions. See "`anchorData`: a wallet-local recovery record" above for
  the full design. Should land before Milestone E, since messaging's poll
  path is the main beneficiary of the cached public keys. No migration
  needed — no `contactAnchor` documents exist on any network yet.
- **Not yet done**: Mainnet/Devnet registration (each network needs its own,
  independent of Testnet's); messaging send/receive
  (`encryptedMessage`/`MessageKind`, Milestone E); real payment-with-memo
  transfers riding on messages; recovery UI for a reinstalled/new-device
  user (Milestone F); HD-deriving the ENCRYPTION/DECRYPTION identity keys
  themselves (the companion fix for the other half of the relaunch-from-
  new-wallet recovery gap — not yet decided).
