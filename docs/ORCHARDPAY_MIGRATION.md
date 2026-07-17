# DashPay → OrchardPay Migration

## Status: not started (design phase)

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
during the rebrand pass (`src/ui/mod.rs`, `src/app.rs`, `src/ui/components/left_panel.rs`).
Module-level `//! LEGACY` doc comments are on `src/ui/dashpay/mod.rs` and
`src/backend_task/dashpay.rs`.

## Removal criteria

Do not remove DashPay code until all boxes above are checked **and** OrchardPay
has been used in practice as a full DashPay replacement (not just schema-complete).
