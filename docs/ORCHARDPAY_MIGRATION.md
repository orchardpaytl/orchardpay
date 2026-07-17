# DashPay → OrchardPay Migration

## Status: in progress

Guided onboarding chain (wallet → identity → DPNS name) landed. OrchardPay's
data contract schema is finalized and identity registration now requests
OrchardPay's contract-bounded ENCRYPTION/DECRYPTION keys automatically — see
`docs/orchardpay/PROTOCOL_DESIGN.md`. None of the parity checklist below is
checked yet; that starts with shielded-address publishing (next up).

**Operational prerequisite, not yet met on any network**: OrchardPay's
contract is not an SDK-embedded system contract like DPNS/DashPay — it must
be registered once per network (via the existing generic "Register Contract"
screen) and the resulting contract ID recorded in that network's config
(`NetworkConfig::orchardpay_contract_id` in `src/config.rs`). Until that
happens on a given network, `AppContext::orchardpay_contract_id()` returns
`None` there and identity registration silently falls back to DashPay's keys
only (see `combined_default_key_specs` in `src/backend_task/identity/mod.rs`)
— OrchardPay's contact/messaging features are simply unavailable on that
network, not broken.

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

- [ ] Shielded-address publishing + discovery (replaces DashPay's public
      contact-request documents)
- [ ] Contact Anchor establishment + AES-256 decryption (replaces DashPay's
      DIP-15 ECDH contact key exchange, `src/backend_task/dashpay/encryption.rs`)
- [ ] Encrypted message/payment sending using `referenceId` (replaces
      `src/backend_task/dashpay/payments.rs`, `incoming_payments.rs`)
- [ ] Profile equivalent (DashPay's `profile.rs` / `ProfileSearchScreen`)
- [ ] Contact list / recovery UI equivalent (`contacts.rs`, `contacts_list.rs`)
- [ ] Local caching/persistence equivalent (`database/dashpay.rs`, `database/contacts.rs`)

## Marked locations

Grep for `ORCHARDPAY-TODO(dashpay-legacy)` to find all wiring points flagged
during the rebrand pass (`src/model/settings.rs` — where `RootScreenType`
lives after the platform-wallet rewrite, `src/app.rs`,
`src/ui/components/left_panel.rs`). Module-level `//! LEGACY` doc comments
are on `src/ui/dashpay/mod.rs` and `src/backend_task/dashpay.rs`.

## Removal criteria

Do not remove DashPay code until all boxes above are checked **and** OrchardPay
has been used in practice as a full DashPay replacement (not just schema-complete).
