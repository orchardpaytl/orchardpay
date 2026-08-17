# DashPay → OrchardPay Migration

## Status: feature-complete on Testnet, pending real-world usage before removal

Guided onboarding chain (wallet → identity → DPNS name) landed. OrchardPay's
data contract schema is finalized and identity registration now requests
OrchardPay's contract-bounded ENCRYPTION/DECRYPTION keys automatically — see
`docs/orchardpay/PROTOCOL_DESIGN.md`. Every item in the parity checklist below
is now implemented and registered on Testnet; DashPay is not yet removed
because the removal criteria also require in-practice usage, not just
schema/feature completeness (see "Removal criteria" below).

**Operational prerequisite**: OrchardPay's contract is not an SDK-embedded
system contract like DPNS/DashPay — it must be registered once per network
(via the existing generic "Register Contract" screen) and the resulting
contract ID recorded in that network's config
(`NetworkConfig::orchardpay_contract_id` in `src/config.rs`). Until that
happens on a given network, `AppContext::orchardpay_contract_id()` returns
`None` there and identity registration silently falls back to DashPay's keys
only (see `combined_default_key_specs` in `src/backend_task/identity/mod.rs`)
— OrchardPay's contact/messaging features are simply unavailable on that
network, not broken.

**Testnet: re-registered (2026-07-27).** The contract schema changed
(`shieldedAddress` widened to `40..5120` bytes; `encryptedMessage`'s two
indices merged into one `byReferenceIdbyOwnerIdAndCreated` compound index —
see `docs/orchardpay/PROTOCOL_DESIGN.md`). Because Platform disallows
removing/altering indices via a contract update, this shipped as a
brand-new contract registration rather than an update to the previously
registered one. The updated schema is now registered on Testnet as
`Bu4MNp1gPogr2zSw27Y3e7CE3cKr3kDacUi9tFAYmMFm` (2026-07-27), recorded as
`TESTNET_orchardpay_contract_id` in `.env.example` (update the live `.env`
locally to match). The contract previously registered as
`Hk5Tajxf4FNUjh3S9Sqq7ZFYm3p3b8dPpDEWszJp5Juw` (2026-07-20) is retired,
along with any documents published under it — no migration was performed
(clean slate; see the PROTOCOL_DESIGN.md milestone tracker's 2026-07-27
entry). Mainnet and Devnet still need their own registration before
OrchardPay works there, using this updated schema (not the retired one) —
each network's canonical ID is separate, whoever registers first on a given
network sets it for everyone building against that network.

**Testnet: re-registered (2026-08-17).** `contactAnchor.canBeDeleted` changed
from `false` to `true` — an identity can now permanently delete its own
`contactAnchor` once a contact is `Established`, since (unlike DashPay's
original non-deletable contact-request documents) neither party depends on
the other's `contactAnchor` document continuing to exist once established;
see `docs/orchardpay/PROTOCOL_DESIGN.md`'s "Deletability" subsection under
section 2. Platform disallows changing `canBeDeleted` via a contract update
(the same constraint that drove the 2026-07-27 re-registration above), so
this again required a brand-new contract registration rather than an update.
The updated schema is now registered on Testnet as
`4LEz8JLdFXcJwqmeHeZN5BgwkcGY7AzrNeMi5GBewssi` (2026-08-17), recorded as
`TESTNET_orchardpay_contract_id` in `.env.example` (the live local `.env` was
updated to match). The contract previously registered as
`Bu4MNp1gPogr2zSw27Y3e7CE3cKr3kDacUi9tFAYmMFm` (2026-07-27) is retired, along
with any documents published under it — no migration was performed (clean
slate, same precedent as before). Mainnet and Devnet still have no
OrchardPay contract registered at all, so they simply register this
already-updated schema directly — no retirement step needed there.

DashPay (`src/ui/dashpay/`, `src/backend_task/dashpay/`, `src/database/dashpay.rs`,
`src/database/contacts.rs`) is **legacy** — superseded in intent by OrchardPay's
ZK-based contact model, but still fully functional and **not to be deleted or
feature-gated off** until OrchardPay reaches parity. See `docs/orchardpay/PROTOCOL_DESIGN.md`
for the design replacing it.

## Why DashPay is being superseded

DashPay's contact-request flow publishes public documents that create a
permanent, queryable social graph, and requires both parties to complete a
handshake before either can pay the other. OrchardPay replaces this with
shielded/ZK-based initial contact (no public link between parties) and allows
one-directional sends. See the two source articles this project is based on
for full rationale.

## What needs feature parity before DashPay can be removed

- [x] Shielded-address publishing + discovery (replaces DashPay's public
      contact-request documents) — `src/backend_task/orchardpay/shielded_address.rs`,
      `src/ui/orchardpay/shielded_address_screen.rs`
- [x] Contact Anchor establishment + AES-256 decryption (replaces DashPay's
      DIP-15 ECDH contact key exchange, `src/backend_task/dashpay/encryption.rs`) —
      `src/backend_task/orchardpay/contact_anchor.rs`, `encryption.rs`
- [x] Encrypted message/payment sending using `refId` (replaces
      `src/backend_task/dashpay/payments.rs`, `incoming_payments.rs`) —
      `src/backend_task/orchardpay/messages.rs`, `src/ui/orchardpay/message_thread_screen.rs`
- [x] Profile equivalent (DashPay's `profile.rs` / `ProfileSearchScreen`) —
      the "My Profile" subscreen in `src/ui/orchardpay/orchardpay_screen.rs`
- [x] Contact list / recovery UI equivalent (`contacts.rs`, `contacts_list.rs`) —
      the "Contacts" subscreen plus "Recover from Network" (`recover_own_anchors`)
      in `src/ui/orchardpay/orchardpay_screen.rs`
- [x] Local caching/persistence equivalent (`database/dashpay.rs`, `database/contacts.rs`) —
      the k/v sidecar in `src/wallet_backend/orchardpay.rs`

## Marked locations

Grep for `ORCHARDPAY-TODO(dashpay-legacy)` to find all wiring points flagged
during the rebrand pass (`src/model/settings.rs` — where `RootScreenType`
lives after the platform-wallet rewrite, `src/app.rs`,
`src/ui/components/left_panel.rs`). Module-level `//! LEGACY` doc comments
are on `src/ui/dashpay/mod.rs` and `src/backend_task/dashpay.rs`.

## Removal criteria

Do not remove DashPay code until all boxes above are checked **and** OrchardPay
has been used in practice as a full DashPay replacement (not just schema-complete).
