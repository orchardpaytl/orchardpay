# Glossary

**Orchard** — Zcash's shielded-pool protocol (ZIP32 key derivation, `FullViewingKey`,
`Note`, `Nullifier`, `PaymentAddress`, etc.), used by this app's shielded wallet
layer (see `src/model/wallet/shielded.rs`, e.g. `OrchardKeySet`,
`derive_orchard_keys()`). This term predates and is unrelated to this project's
name — it comes from upstream `dash-sdk`/Zcash terminology.

**OrchardPay** — this project: a privacy-focused peer-to-peer payment and
messaging system built on Dash Platform, forked from `dash-evo-tool`. It uses
the Orchard shielded-pool protocol (above) as its ZK transaction layer, plus a
data-contract-based document scheme for private contact establishment and
messaging (see `docs/orchardpay/PROTOCOL_DESIGN.md`).

These two terms are related only by coincidence of the word "Orchard." When
writing code or docs near real Orchard-protocol logic, always spell out
"OrchardPay" in full for the product name to keep the two visually distinct.
