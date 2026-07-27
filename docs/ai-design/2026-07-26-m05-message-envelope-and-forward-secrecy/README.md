# M-05: No forward secrecy or transcript-bound key schedule

Status: **declined 2026-07-27 (see addendum below) — split into a future
roadmap item for an actual forward-secrecy ratchet.** One of three
independent follow-ups to
`docs/ORCHARDPAY_COMPREHENSIVE_REVIEW_2026-07-25.md` — see
`docs/ai-design/2026-07-26-comprehensive-review-response/README.md` for how
this relates to the other two (M-02, M-08). Can be accepted, modified, or
rejected without affecting the other two. Also folds in H-01's separate ask
for a "versioned envelope with associated authenticated data" — same
underlying change.

## In plain terms (for picking this back up later)

**Nothing here is currently broken or exploitable.** The actual bug from
the review (H-01, forged/replayed messages) was already fixed separately,
by checking document ownership before trusting anything — that fix has
nothing to do with encryption keys and stands on its own. This proposal is
pure defense-in-depth: tightening locks that already work, not fixing ones
that are open.

- **HKDF, simply**: a key splitter. Today, one shared secret (computed
  once per relationship) is used directly as the encryption key for
  everything in that relationship — contact requests and messages alike.
  HKDF takes that one secret plus a label ("this is for anchor requests"
  vs. "this is for messages") and produces a *different* key per label.
  Same original secret in, different keys out — so a key derived for one
  purpose can never be reused, even by accident, for another.
- **AAD ("additional authenticated data"), simply**: a tag glued onto an
  encrypted message. It isn't secret and isn't scrambled itself, but the
  encryption locks it in so it can't be swapped or stripped without
  breaking the whole thing. Here that tag would say things like "this
  belongs to conversation X, between A and B, and it's a message, not an
  anchor." If a ciphertext were ever moved somewhere it doesn't belong — a
  different conversation, a different field — decryption fails outright
  instead of possibly succeeding somewhere it shouldn't.
- **The "envelope"**: just the wrapper around the encrypted bytes. Today
  it's `nonce + encrypted data`. The proposed version is `version number +
  nonce + encrypted data`, with the AAD tag required (but not stored) to
  unlock it. The version number lets a future format change be told apart
  from this one cleanly, instead of a silent break.

**Status**: reviewed and understood, deliberately **not** picked up yet —
revisit when there's appetite for it. A concrete implementation plan
(including the discovery that `generate_ecdh_shared_key` is shared with
DashPay via DIP-15 and must not be touched — all of this work stays
strictly on OrchardPay's own side) exists and can be regenerated or pulled
from session history when this is picked back up.

## The problem, confirmed against current code

- `generate_ecdh_shared_key` (`src/backend_task/dashpay/encryption.rs:17`,
  reused as-is by OrchardPay) derives the AES-256 key as a single
  `SHA256(prefix || x)` over the raw ECDH shared point's x-coordinate. No
  HKDF, no context string, no domain separation between `contactAnchor`'s
  `data`/`anchorData` fields and `encryptedMessage`'s `msgData` — they're
  different call sites but the underlying key derivation is identical.
- `encrypt`/`decrypt` (`src/backend_task/orchardpay/encryption.rs:59-89`)
  call `cipher.encrypt(nonce, plaintext)` — the plain `Aead::encrypt`
  signature, not the `Payload { msg, aad }` variant. **No associated
  authenticated data is bound into the AEAD tag at all.**
- The same directional secret is reused for every message in a
  relationship, indefinitely — there's no rotation, no ratchet, no
  per-message key.
- There is no explicit protocol/envelope version byte anywhere in the
  encrypted blob.

**Important scoping note**: this is *not* what made H-01's forgery possible
— H-01 was purely an application-layer bug (no `$ownerId` check on the
query results), already fixed (`bda6f0e7`) independent of anything here.
Nothing below is required to close H-01. What this *does* provide is
defense-in-depth against a different class of issue: if a ciphertext were
ever moved into the wrong context by some other means (a different
document type, a different relationship, a future contract change reusing
the same key derivation), an AAD-bound envelope would fail to decrypt
instead of silently succeeding. It also gives the protocol room to evolve
without a hard cutover.

## Proposed v2 envelope

1. **Replace the raw single-hash KDF with HKDF.** `HKDF-Extract` using the
   ECDH shared secret as IKM, `HKDF-Expand` with an `info` string binding:
   protocol version, network (mainnet/testnet/devnet), the OrchardPay
   contract ID, and a purpose tag (`"orchardpay-message"` vs.
   `"orchardpay-anchor"` vs. `"orchardpay-anchor-data"`) — so a key derived
   for one purpose can never coincide with a key derived for another, even
   under an identical ECDH point.
2. **Bind associated authenticated data into the AES-GCM call itself**, not
   just as a KDF input — `aes_gcm`'s `Payload` API accepts `aad: &[u8]`
   directly. Proposed AAD: `contract_id || network || owner_id ||
   counterparty_id || refId || message_type_tag || protocol_version`. A
   ciphertext copied into a document with a different `refId`, different
   owner, or different message type fails AEAD verification outright —
   independent of and in addition to the app-level `$ownerId` check.
3. **Add an explicit 1-byte protocol/envelope version prefix** to the
   encrypted blob (`nonce || version || ciphertext-with-tag` or similar),
   so a future format change is detectable and can coexist with this one
   during any transition, rather than a silent hard break.
4. **Migration**: no production/Mainnet data exists yet (Testnet only, no
   public release). A clean version bump with no backward-compatible
   decode path is viable now — this window closes once real users have
   real message history, so this is worth doing before that happens, not
   after.

## Addendum (2026-07-27): declined, split into a future roadmap item

Decision: **HKDF/purpose-splitting and AAD are both declined for now**;
forward secrecy (a real ratchet) is separated out as the one piece with
actual value and tracked as a future roadmap possibility, not active work.
See `docs/ai-design/2026-07-26-comprehensive-review-response/README.md`'s
M-05 entry for the full reasoning. Summary:

- **HKDF/purpose-splitting**: declined — no live cross-context confusion
  risk exists to close (`anchorData` already uses a fully separate key; the
  one real overlap, `contactAnchor.data` vs. `encryptedMessage.msgData`,
  decodes into different structs, so a moved ciphertext would decrypt but
  almost certainly fail to parse). Purely speculative insurance against a
  future schema convergence, not worth doing on its own. Note for whoever
  revisits this: if a real ratchet is ever built, HKDF-style derivation
  comes back anyway as the actual mechanism a ratchet chains through — this
  isn't "HKDF is worthless," just "static purpose-labeling without a ratchet
  behind it isn't worth doing in isolation."
- **AAD**: real but redundant — it's an integrity/authenticity control, not
  a privacy one (it doesn't hide anything; it makes a moved/replayed
  ciphertext fail to decrypt). Its value is as an independent regression
  guard over the already-sufficient H-01 query-side fix. Declined as active
  work now; kept as a future roadmap possibility since it's cheap and could
  be picked up any time without a design phase.
- **Forward secrecy (the actual ratchet)**: this proposal, as originally
  scoped (items 1-3 above), delivers **no forward secrecy at all** — one
  static per-relationship secret split into two labeled static sub-keys
  still means a leaked ECDH secret decrypts the whole relationship's
  history, past and future, either way. The real fix needs the
  Double-Ratchet-style mechanism this doc already flagged as out of scope
  (session state, out-of-order messages, ratchet-state-loss UX on
  reinstall/multi-device) — sized and prioritized as its own, much larger,
  future roadmap item, not bundled with AAD.

## Explicitly out of scope for this pass

- **A full forward-secrecy ratchet** (Double-Ratchet-style per-message key
  evolution, so a compromised long-term key can't decrypt *past* messages).
  This is the review's other ask under M-05 and is a substantially bigger
  lift — session state, out-of-order message handling, and a real UX
  question about what happens when a ratchet state is lost (reinstall,
  multi-device). Recommend deciding this **separately and explicitly**
  once items 1-3 above are settled, not bundled into this pass. Items 1-3
  meaningfully close the domain-separation and cross-context-replay gaps
  without it.
- Rotating `anchorData`'s own wallet-local fixed key (`m/420'/coin_type'/1'`)
  — that key's one-key-per-wallet design is a deliberate, separately
  documented choice (`docs/orchardpay/PROTOCOL_DESIGN.md`'s "`anchorData`: a
  wallet-local recovery record") for a different threat model (self-only
  reader, not a relationship-shared secret) and isn't part of this envelope
  change.

## Verification (if accepted)

- Existing wrong-key/tampered-ciphertext tests in `encryption.rs` should
  still pass under the new envelope (with updated fixtures).
- New tests: same plaintext, same key material, but AAD mismatched on one
  field (wrong `refId`, wrong owner, wrong message type) each fail to
  decrypt.
- New test: HKDF output differs between `"orchardpay-message"` and
  `"orchardpay-anchor"` purpose tags even given the identical ECDH secret.
- `cargo test --all-features orchardpay`, `cargo clippy`, `cargo fmt --all`.
