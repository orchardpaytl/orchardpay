use dash_sdk::dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::platform::Identifier;

/// The document type these keys are bound to. Both the sender's ENCRYPTION
/// key and the recipient's DECRYPTION key involved in establishing a
/// `contactAnchor` are scoped here — see `docs/orchardpay/PROTOCOL_DESIGN.md`.
pub const CONTACT_ANCHOR_DOCUMENT_TYPE: &str = "contactAnchor";

/// Returns the OrchardPay-specific key specifications a new identity should
/// carry, mirroring `default_identity_key_specs` in
/// `backend_task::identity` but bound to OrchardPay's own contract instead
/// of DashPay's.
///
/// A single ENCRYPTION/DECRYPTION key pair, bound via
/// `ContractBounds::SingleContractDocumentType` to OrchardPay's contract +
/// the `contactAnchor` document type, is sufficient for the whole
/// relationship: the ECDH shared secret it produces is derived once when a
/// `contactAnchor` is established and then reused for every subsequent
/// `encryptedMessage` in that relationship, so no separate key is needed for
/// the `encryptedMessage` document type.
pub fn default_orchardpay_key_specs(
    orchardpay_contract_id: Identifier,
) -> Vec<(KeyType, Purpose, SecurityLevel, Option<ContractBounds>)> {
    let bounds = Some(ContractBounds::SingleContractDocumentType {
        id: orchardpay_contract_id,
        document_type_name: CONTACT_ANCHOR_DOCUMENT_TYPE.to_string(),
    });

    vec![
        (
            KeyType::ECDSA_SECP256K1, // ECDH requires secp256k1
            Purpose::ENCRYPTION,
            SecurityLevel::MEDIUM, // Platform enforces MEDIUM for ENCRYPTION
            bounds.clone(),
        ),
        (
            KeyType::ECDSA_SECP256K1, // ECDH requires secp256k1
            Purpose::DECRYPTION,
            SecurityLevel::MEDIUM,
            bounds,
        ),
    ]
}
