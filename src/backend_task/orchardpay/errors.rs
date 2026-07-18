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
}
