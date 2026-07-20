use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::contact_anchor::own_bounds_verified_key;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::context::AppContext;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::qualified_identity::qualified_identity_public_key::QualifiedIdentityPublicKey;
use crate::model::wallet::WalletSeedHash;
use crate::wallet_backend::WalletBackend;
use dash_sdk::Sdk;
use dash_sdk::dpp::dashcore::Network;
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::identities_contract_keys::IdentitiesContractKeys;
use dash_sdk::dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dash_sdk::dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dash_sdk::dpp::identity::identity_public_key::v0::IdentityPublicKeyV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::platform::identities_contract_keys_query::IdentitiesContractKeysQuery;
use dash_sdk::platform::{Fetch, Identifier, IdentityPublicKey};
use std::sync::Arc;

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

/// Ensure `qualified_identity` carries OrchardPay-bound ENCRYPTION and
/// DECRYPTION keys, generating and broadcasting whichever is missing in a
/// single Identity Update transition. Returns the identity unchanged (no
/// network call) if both already exist.
///
/// Called from `shielded_address::publish_own_shielded_address` — OrchardPay
/// deliberately does **not** add these keys at identity-creation time (see
/// `backend_task::identity::combined_default_key_specs`'s doc comment).
/// Instead, "publish a shielded address" is the single flow that gets an
/// identity fully set up for OrchardPay, whether it's brand new or years
/// old: no separate "add these keys first" step to forget.
///
/// The generated keys are HD-derived from `seed_hash`'s wallet — see
/// `docs/orchardpay/PROTOCOL_DESIGN.md`'s "HD-deriving the
/// ENCRYPTION/DECRYPTION identity keys" for why (recoverability from the
/// seed alone) and how (reusing DIP-13's generic per-identity key slot,
/// `identity_authentication_path`, exactly as DashPay's own ENCRYPTION/
/// DECRYPTION keys already do — no new derivation scheme). Never shown to
/// or chosen by the user, so there's nothing to back up beyond the
/// recovery phrase itself.
pub async fn ensure_own_orchardpay_keys(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    qualified_identity: QualifiedIdentity,
    orchardpay_contract_id: Identifier,
    seed_hash: WalletSeedHash,
) -> Result<QualifiedIdentity, TaskError> {
    let has_encryption = own_bounds_verified_key(
        &qualified_identity,
        orchardpay_contract_id,
        Purpose::ENCRYPTION,
    )
    .is_some();
    let has_decryption = own_bounds_verified_key(
        &qualified_identity,
        orchardpay_contract_id,
        Purpose::DECRYPTION,
    )
    .is_some();

    if has_encryption && has_decryption {
        return Ok(qualified_identity);
    }

    let identity_index = qualified_identity
        .wallet_index
        .ok_or(OrchardPayError::OwnKeyNotDerivable)?;
    let backend = app_context.wallet_backend()?;
    let network = app_context.network;

    let bounds = ContractBounds::SingleContractDocumentType {
        id: orchardpay_contract_id,
        document_type_name: CONTACT_ANCHOR_DOCUMENT_TYPE.to_string(),
    };

    // key_index must be unique across the WHOLE identity, not just
    // OrchardPay's own keys — seed with every currently-registered key's
    // bytes, then extend it as each new candidate is claimed below, so a
    // second key generated in this same call never collides with the first.
    let mut already_registered: Vec<Vec<u8>> = qualified_identity
        .identity
        .public_keys()
        .values()
        .map(|key| key.data().as_slice().to_vec())
        .collect();

    let mut keys_to_add = Vec::new();
    if !has_encryption {
        keys_to_add.push(
            generate_orchardpay_key(
                &backend,
                &seed_hash,
                network,
                identity_index,
                &mut already_registered,
                Purpose::ENCRYPTION,
                bounds.clone(),
            )
            .await?,
        );
    }
    if !has_decryption {
        keys_to_add.push(
            generate_orchardpay_key(
                &backend,
                &seed_hash,
                network,
                identity_index,
                &mut already_registered,
                Purpose::DECRYPTION,
                bounds.clone(),
            )
            .await?,
        );
    }

    let (updated_identity, _fee_result) = app_context
        .add_keys_to_identity(sdk, qualified_identity, keys_to_add)
        .await?;
    Ok(updated_identity)
}

/// Derive the next free identity-key slot for `purpose`, bounded to
/// OrchardPay's contract + `contactAnchor` document type. `already_registered`
/// is extended with the chosen candidate's public key bytes before
/// returning, so a caller generating more than one key in the same call
/// (ENCRYPTION then DECRYPTION) never picks the same slot twice.
async fn generate_orchardpay_key(
    backend: &WalletBackend,
    seed_hash: &WalletSeedHash,
    network: Network,
    identity_index: u32,
    already_registered: &mut Vec<Vec<u8>>,
    purpose: Purpose,
    bounds: ContractBounds,
) -> Result<(QualifiedIdentityPublicKey, [u8; 32]), TaskError> {
    let (_key_index, public_key_bytes, private_key_bytes) = backend
        .orchardpay_next_free_identity_key_index(
            seed_hash,
            network,
            identity_index,
            already_registered,
        )
        .await?;
    already_registered.push(public_key_bytes.to_vec());

    let identity_public_key = IdentityPublicKeyV0 {
        id: 0,
        key_type: KeyType::ECDSA_SECP256K1,
        purpose,
        security_level: SecurityLevel::MEDIUM,
        data: public_key_bytes.to_vec().into(),
        read_only: false,
        disabled_at: None,
        contract_bounds: Some(bounds),
    };

    Ok((
        QualifiedIdentityPublicKey {
            identity_public_key: identity_public_key.into(),
            in_wallet_at_derivation_path: None,
        },
        *private_key_bytes,
    ))
}
