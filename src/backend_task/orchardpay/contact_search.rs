//! DPNS-based contact search: find identities by username prefix, then
//! check each for a published `shieldedAddress` to mark it contactable via
//! OrchardPay. Mirrors the DPNS query pattern in
//! `src/backend_task/dashpay/profile.rs::search_profiles`, minus the
//! DashPay-profile enrichment step (OrchardPay has no profile document).

use crate::backend_task::error::TaskError;
use crate::backend_task::orchardpay::errors::OrchardPayError;
use crate::backend_task::orchardpay::shielded_address::lookup_shielded_address;
use crate::backend_task::{
    BackendTaskSuccessResult, NETWORK_REQUEST_TIMEOUT, await_network_request_with_timeout,
};
use crate::context::AppContext;
use dash_sdk::Sdk;
use dash_sdk::dpp::document::DocumentV0Getters;
use dash_sdk::dpp::platform_value::{Value, string_encoding::Encoding};
use dash_sdk::drive::query::{OrderClause, WhereClause, WhereOperator};
use dash_sdk::platform::{Document, DocumentQuery, FetchMany, Identifier};
use std::sync::Arc;

/// One DPNS search hit, annotated with whether the identity has published
/// an OrchardPay `shieldedAddress` and so can actually be contacted.
#[derive(Debug, Clone, PartialEq)]
pub struct OrchardPayContactSearchResult {
    pub identity_id: Identifier,
    pub username: String,
    pub contactable: bool,
}

pub async fn search_contacts(
    app_context: &Arc<AppContext>,
    sdk: &Sdk,
    search_query: String,
) -> Result<BackendTaskSuccessResult, TaskError> {
    let query_trimmed = search_query.trim();
    if query_trimmed.is_empty() {
        return Ok(BackendTaskSuccessResult::OrchardPayContactSearchResults(
            Vec::new(),
        ));
    }

    let normalized_query = crate::model::dpns::normalize_dpns_label(query_trimmed);

    let mut dpns_query =
        DocumentQuery::new(app_context.dpns_contract.clone(), "domain").map_err(|e| {
            OrchardPayError::QueryCreation {
                query_target: "DPNS domain search",
                source: Box::new(e),
            }
        })?;
    dpns_query = dpns_query
        .with_where(WhereClause {
            field: "normalizedParentDomainName".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Text("dash".to_string()),
        })
        .with_where(WhereClause {
            field: "normalizedLabel".to_string(),
            operator: WhereOperator::StartsWith,
            value: Value::Text(normalized_query),
        })
        .with_order_by(OrderClause {
            field: "normalizedLabel".to_string(),
            ascending: true,
        }); // Required for StartsWith range query
    dpns_query.limit = 20;

    let dpns_results = await_network_request_with_timeout(
        NETWORK_REQUEST_TIMEOUT,
        Document::fetch_many(sdk, dpns_query),
        |source| TaskError::DocumentFetchTimeout { source },
    )
    .await?
    .map_err(TaskError::from)?;

    let mut identity_usernames: Vec<(Identifier, String)> = Vec::new();
    for (_, doc) in dpns_results {
        let Some(document) = doc else { continue };
        let Some(identity_id) =
            crate::model::dpns::extract_identity_id_from_dpns_document(&document)
        else {
            continue;
        };
        let username = document
            .get("label")
            .and_then(|v| v.as_text())
            .map(|s| format!("{s}.dash"))
            .unwrap_or_else(|| format!("{}.dash", identity_id.to_string(Encoding::Base58)));
        identity_usernames.push((identity_id, username));
    }

    let mut results = Vec::with_capacity(identity_usernames.len());
    for (identity_id, username) in identity_usernames {
        let contactable = lookup_shielded_address(app_context, sdk, identity_id)
            .await?
            .is_some();
        results.push(OrchardPayContactSearchResult {
            identity_id,
            username,
            contactable,
        });
    }

    Ok(BackendTaskSuccessResult::OrchardPayContactSearchResults(
        results,
    ))
}
