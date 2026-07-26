# HD Derivation Path Registry

A short index of every BIP32 "purpose" (the first hardened path segment)
this codebase derives keys under, so a new feature can pick an unclaimed one
without grepping the whole tree first. Each feature keeps its own detailed
design doc / code comments as the source of truth — this file only tracks
*which purpose numbers are taken and by what*, not the full derivation logic.

| Purpose | Path shape | Used for | Detail |
|---|---|---|---|
| `44'` | `m/44'/coin'/0'/...` | Standard BIP44 wallet funds (the account a user's normal balance lives on) | `src/wallet_backend/payments.rs`, `src/model/wallet/meta.rs` |
| `9'` | `m/9'/coin'/15'/account'/(sender)/(recipient)` | DashPay (DIP-15) per-relationship contact-payment xpub | `src/wallet_backend/dashpay.rs` (`derive_contact_xpub`, upstream `platform_wallet`); see `docs/ai-design/2026-05-18-platform-wallet-migration/dip14-migration-hardstop.md` |
| `420'` | `m/420'/coin_type'/1'` | OrchardPay's wallet-local, self-only `anchorData` encryption key (one fixed key per wallet, not per-relationship) | `src/wallet_backend/orchardpay.rs` (`derive_anchor_data_key`); see `docs/orchardpay/PROTOCOL_DESIGN.md`'s "`anchorData`: a wallet-local recovery record" |

Before adding a new purpose number, check this table first, then add a row
here alongside the feature's own detailed doc — don't let the detail doc be
the only place a purpose number is recorded.
