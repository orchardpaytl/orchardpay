use thiserror::Error;

/// Domain errors for OrchardPay's private contact/messaging protocol.
#[derive(Error, Debug)]
pub enum OrchardPayError {
    /// OrchardPay's contract isn't configured for the active network, either
    /// because no one has registered it there yet or the resulting ID was
    /// never recorded in network config. See
    /// `docs/ORCHARDPAY_MIGRATION.md` for the per-network registration
    /// status and `AppContext::orchardpay_contract`.
    #[error(
        "OrchardPay's private contact features aren't set up on this network yet. Try switching to a network where they're available, such as Testnet."
    )]
    ContractNotConfigured,

    /// Failed to build a document query (schema / configuration error).
    #[error("Could not prepare the data request. Please retry or update the application.")]
    QueryCreation {
        /// Description of what query was being built (e.g. "shieldedAddress lookup").
        query_target: &'static str,
        #[source]
        source: Box<dash_sdk::Error>,
    },

    /// The counterparty identity has no ENCRYPTION/DECRYPTION key bound to
    /// OrchardPay's `contactAnchor` document type, so a private contact
    /// request can't be encrypted to them yet.
    #[error(
        "This person hasn't set up private contacts on OrchardPay yet, so they can't be reached this way."
    )]
    CounterpartyKeyMissing,

    /// A key was found for the counterparty, but its `contract_bounds()`
    /// don't match OrchardPay's contract + `contactAnchor` document type —
    /// see `keys::fetch_bounds_verified_counterparty_key`'s hardening note.
    /// Never use this key for ECDH; treat it the same as "missing."
    #[error("This person's OrchardPay contact key could not be verified. Please try again later.")]
    CounterpartyKeyNotBound,

    /// Encrypting or decrypting a `contactAnchor` payload failed — either
    /// the AEAD tag didn't verify (wrong key / tampered data) or the
    /// plaintext didn't decode as the expected structure.
    #[error(transparent)]
    Crypto(#[from] super::encryption::OrchardPayCryptoError),

    /// A `contactAnchor` document referenced by ID (e.g. from a memo) could
    /// not be found. It may have been deleted, or the ID may be stale.
    #[error("This private contact request could not be found. It may no longer be available.")]
    AnchorNotFound,

    /// `initiate_contact` found local contact state already recorded for
    /// this counterparty — a request was already sent, already received, or
    /// the relationship is already established. Distinct from
    /// [`Self::AnchorNotFound`], which means the opposite (nothing found).
    #[error(
        "You've already connected with this contact, or a request is already pending. Check your Contacts list."
    )]
    RelationshipAlreadyExists,

    /// The active identity has no ENCRYPTION or DECRYPTION key bound to
    /// OrchardPay's `contactAnchor` document type. Identities created before
    /// OrchardPay's contract was configured for this network won't have
    /// one automatically.
    #[error(
        "This identity isn't set up for OrchardPay's private contacts yet. Add an OrchardPay-bound key from Key Info to enable them."
    )]
    OwnKeyMissing,

    /// The DET-side duplicate incoming-memo scan
    /// (`docs/ai-design/2026-07-18-orchardpay-memo-detection/`) failed to
    /// fetch or decrypt a chunk of shielded notes. Non-fatal from the app's
    /// perspective — the next sync pass retries automatically.
    #[error(
        "Could not check for new private contact requests. This will be retried automatically."
    )]
    MemoScanFailed {
        #[source]
        source: Box<dash_sdk::Error>,
    },

    /// Generating a fresh keypair for an OrchardPay-bound ENCRYPTION/
    /// DECRYPTION key failed. Extremely unlikely in practice (secp256k1
    /// key generation essentially never fails) — surfaced as a typed
    /// variant rather than silently retried.
    #[error("Could not prepare your private OrchardPay keys. Please try again.")]
    KeyGenerationFailed {
        #[source]
        source: Box<dash_sdk::dpp::ProtocolError>,
    },

    /// Attempted to send or load a message for a counterparty with no
    /// `Established` local contact state — either no relationship exists
    /// yet, or the handshake with them hasn't completed. Messaging requires
    /// both parties' ReferenceIDs and cached public keys, which only exist
    /// once `docs/orchardpay/PROTOCOL_DESIGN.md`'s two-anchor handshake is
    /// fully complete.
    #[error(
        "You haven't connected with this contact yet. Send or accept a private contact request first."
    )]
    ContactNotEstablished,

    /// A gap-limit scan of `identity_authentication_path` (see
    /// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "HD-deriving the
    /// ENCRYPTION/DECRYPTION identity keys") could not find a free
    /// `key_index` for a new OrchardPay key, or could not find the
    /// `key_index` matching an already-registered one. In practice this
    /// means the identity has accumulated more purpose-bound keys than the
    /// scan window covers — a shared, non-OrchardPay-specific limit, not a
    /// problem with this identity's own OrchardPay setup.
    #[error("Could not prepare your private OrchardPay keys. Please try again.")]
    OwnKeyNotDerivable,
}
