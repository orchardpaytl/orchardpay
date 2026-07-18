use crate::backend_task::orchardpay::errors::OrchardPayError;
use dash_sdk::Sdk;
use dash_sdk::dpp::identity::identities_contract_keys::IdentitiesContractKeys;
use dash_sdk::dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dash_sdk::dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::platform::identities_contract_keys_query::IdentitiesContractKeysQuery;
use dash_sdk::platform::{Fetch, Identifier, IdentityPublicKey};

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

/// Fetch `counterparty_identity_id`'s current key of `purpose`, bounded to
/// OrchardPay's `contactAnchor` document type, and explicitly verify its
/// `contract_bounds()` before returning it.
///
/// Platform's `requiresIdentity{Encryption,Decryption}BoundedKey` schema
/// keywords only gate *registration* of a contract-bounded key — they say
/// nothing about which key a piece of client code chooses to trust when
/// resolving a counterparty's key for ECDH. `IdentitiesContractKeysQuery`
/// resolves the *current* key of this purpose that Platform is willing to
/// register bound to this contract+document-type, but a confused or
/// malicious identity could still hold an unrelated, unbounded key of the
/// same purpose that happens to be returned first by some other lookup
/// path. This function is the one call site that must never be bypassed in
/// favor of `get_first_public_key_matching` (which DashPay's
/// `contact_requests.rs` uses today and which has no `contract_bounds`
/// parameter at all) — see `docs/orchardpay/PROTOCOL_DESIGN.md`'s
/// "Hardening note".
pub async fn fetch_bounds_verified_counterparty_key(
    sdk: &Sdk,
    orchardpay_contract_id: Identifier,
    counterparty_identity_id: Identifier,
    purpose: Purpose,
) -> Result<IdentityPublicKey, OrchardPayError> {
    let query = IdentitiesContractKeysQuery::new(
        vec![counterparty_identity_id],
        orchardpay_contract_id,
        Some(CONTACT_ANCHOR_DOCUMENT_TYPE.to_string()),
        vec![purpose],
    )
    .map_err(|e| OrchardPayError::QueryCreation {
        query_target: "counterparty contract-bounded key",
        source: Box::new(e),
    })?;

    let keys_result: Option<IdentitiesContractKeys> = IdentitiesContractKeys::fetch(sdk, query)
        .await
        .map_err(|e| OrchardPayError::QueryCreation {
            query_target: "counterparty contract-bounded key",
            source: Box::new(e),
        })?;

    let key = keys_result
        .and_then(|by_identity| by_identity.get(&counterparty_identity_id).cloned())
        .and_then(|by_purpose| by_purpose.get(&purpose).cloned())
        .flatten()
        .ok_or(OrchardPayError::CounterpartyKeyMissing)?;

    let expected_bounds = ContractBounds::SingleContractDocumentType {
        id: orchardpay_contract_id,
        document_type_name: CONTACT_ANCHOR_DOCUMENT_TYPE.to_string(),
    };
    if key.contract_bounds() != Some(&expected_bounds) {
        return Err(OrchardPayError::CounterpartyKeyNotBound);
    }

    Ok(key)
}
