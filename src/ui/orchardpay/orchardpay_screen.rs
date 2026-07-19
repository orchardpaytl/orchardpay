//! OrchardPay's consolidated private-contacts root screen (Milestone D):
//! a contacts list plus DPNS-based contact search, mirroring the
//! already-consolidated `DashPayScreen`/`DashPaySubscreen` pattern (one
//! `RootScreenType` with an internal subscreen switch, not one root screen
//! per feature).
//!
//! Gated behind a readiness check: Contacts/Search are only shown once the
//! active identity has a DPNS name and a published `shieldedAddress`
//! document — otherwise the screen guides the user through whichever of
//! those is missing, in order. OrchardPay-bound ENCRYPTION/DECRYPTION keys
//! are generated automatically as part of publishing the shielded address
//! (`backend_task::orchardpay::keys::ensure_own_orchardpay_keys`), not a
//! separate step here — see that function's doc comment.

use crate::app::AppAction;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::contact_search::OrchardPayContactSearchResult;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::orchardpay::OrchardPayContactState;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::MessageBanner;
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::top_panel::add_top_panel;
use crate::ui::components::wallet_unlock_popup::{
    WalletUnlockPopup, try_open_wallet_no_password, wallet_needs_unlock,
};
use crate::ui::identities::get_selected_wallet;
use crate::ui::identities::register_dpns_name_screen::RegisterDpnsNameSource;
use crate::ui::orchardpay::shielded_address_screen::ShieldedAddressSetupScreen;
use crate::ui::theme::DashColors;
use crate::ui::{MessageType, RootScreenType, Screen, ScreenLike, ScreenType};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::{Identifier, IdentityPublicKey};
use egui::{RichText, Ui};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchardPaySubscreen {
    Contacts,
    Search,
}

/// What, if anything, stands between the active identity and being able to
/// use OrchardPay's Contacts/Search screens. Checked in this order because
/// each step depends on the previous one (a DPNS name check is meaningless
/// with no identity; a shielded-address check is meaningless with no
/// OrchardPay contract configured on this network).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalReadiness {
    NoIdentity,
    NoDpnsName,
    ContractNotConfigured,
    ContractConfigured,
}

pub struct OrchardPayScreen {
    pub app_context: Arc<AppContext>,
    pub orchardpay_subscreen: OrchardPaySubscreen,
    identity: Option<QualifiedIdentity>,
    selected_key: Option<IdentityPublicKey>,
    selected_wallet: Option<Arc<RwLock<Wallet>>>,
    wallet_unlock_popup: WalletUnlockPopup,
    wallet_open_attempted: bool,
    search_query: String,
    search_results: Vec<OrchardPayContactSearchResult>,
    searching: bool,
    /// `None` = not checked yet this visit; `Some(_)` = last known publish
    /// status for the active identity. Reset on `refresh()` so returning
    /// from the shielded-address setup screen re-checks rather than
    /// showing a stale "not published" prompt.
    has_shielded_address: Option<bool>,
    shielded_address_check_dispatched: bool,
}

impl OrchardPayScreen {
    pub fn new(app_context: &Arc<AppContext>, orchardpay_subscreen: OrchardPaySubscreen) -> Self {
        let (identity, selected_key, selected_wallet) = Self::resolve_identity_context(app_context);

        Self {
            app_context: app_context.clone(),
            orchardpay_subscreen,
            identity,
            selected_key,
            selected_wallet,
            wallet_unlock_popup: WalletUnlockPopup::new(),
            wallet_open_attempted: false,
            search_query: String::new(),
            search_results: Vec::new(),
            searching: false,
            has_shielded_address: None,
            shielded_address_check_dispatched: false,
        }
    }

    fn resolve_identity_context(
        app_context: &Arc<AppContext>,
    ) -> (
        Option<QualifiedIdentity>,
        Option<IdentityPublicKey>,
        Option<Arc<RwLock<Wallet>>>,
    ) {
        let identity = app_context
            .selected_identity_id()
            .and_then(|id| {
                app_context
                    .load_local_user_identities()
                    .unwrap_or_default()
                    .into_iter()
                    .find(|qi| qi.identity.id() == id)
            })
            .or_else(|| {
                app_context
                    .load_local_user_identities()
                    .unwrap_or_default()
                    .into_iter()
                    .next()
            });

        let selected_key = identity.as_ref().and_then(|identity| {
            identity
                .identity
                .get_first_public_key_matching(
                    Purpose::AUTHENTICATION,
                    [
                        SecurityLevel::CRITICAL,
                        SecurityLevel::HIGH,
                        SecurityLevel::MEDIUM,
                    ]
                    .into(),
                    KeyType::all_key_types().into(),
                    false,
                )
                .cloned()
        });

        let selected_wallet = identity.as_ref().and_then(|identity| {
            get_selected_wallet(identity, Some(app_context), None).unwrap_or(None)
        });

        (identity, selected_key, selected_wallet)
    }

    fn compute_local_readiness(&self) -> LocalReadiness {
        let Some(identity) = &self.identity else {
            return LocalReadiness::NoIdentity;
        };
        if identity.dpns_names.is_empty() {
            return LocalReadiness::NoDpnsName;
        }
        if self.app_context.orchardpay_contract_id().is_none() {
            return LocalReadiness::ContractNotConfigured;
        }

        LocalReadiness::ContractConfigured
    }

    fn render_needs_identity(&self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        ui.label("OrchardPay needs an identity to publish a private address for.");
        ui.add_space(8.0);
        if ui.button("Create an Identity").clicked() {
            action |=
                AppAction::AddScreen(ScreenType::AddNewIdentity.create_screen(&self.app_context));
        }
        action
    }

    fn render_needs_dpns_name(&self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        ui.label(
            "OrchardPay needs a DPNS name for this identity before it can be found by contacts.",
        );
        ui.add_space(8.0);
        if ui.button("Register a Username").clicked() {
            action |= AppAction::AddScreen(
                ScreenType::RegisterDpnsName(RegisterDpnsNameSource::Identities)
                    .create_screen(&self.app_context),
            );
        }
        action
    }

    fn render_contract_not_configured(&self, ui: &mut Ui) {
        ui.label(
            "OrchardPay's private contact features aren't set up on this network yet. Try switching to a network where they're available, such as Testnet.",
        );
    }

    fn render_needs_shielded_address(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        let Some(identity) = self.identity.clone() else {
            return action;
        };

        ui.label(
            "You haven't published a private address yet — this is how contacts find you. Publishing sets up everything OrchardPay needs, including your private encryption keys.",
        );
        ui.add_space(8.0);
        if ui
            .button("Publish a shielded address to access OrchardPay")
            .clicked()
        {
            action |= AppAction::AddScreen(Screen::ShieldedAddressSetupScreen(
                ShieldedAddressSetupScreen::new(identity, &self.app_context),
            ));
        }
        action
    }

    fn render_contacts(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;

        let Some(identity) = self.identity.clone() else {
            ui.label("No identity available. Register or select an identity first.");
            return action;
        };

        let backend = match self.app_context.wallet_backend() {
            Ok(backend) => backend,
            Err(_) => {
                ui.label("Wallet backend is not ready yet.");
                return action;
            }
        };

        let owner_id = identity.identity.id();
        let contacts = backend
            .orchardpay_list_contacts(&owner_id)
            .unwrap_or_default();

        if contacts.is_empty() {
            ui.label(
                RichText::new("No private contacts yet. Use Search to find someone on OrchardPay.")
                    .color(DashColors::text_secondary(dark_mode)),
            );
            return action;
        }

        for counterparty in contacts {
            let Ok(Some(state)) = backend.orchardpay_get_contact_state(&owner_id, &counterparty)
            else {
                continue;
            };

            ui.group(|ui| {
                ui.label(RichText::new(counterparty.to_string(Encoding::Base58)).monospace());
                match state {
                    OrchardPayContactState::PendingOutbound { .. } => {
                        ui.label(
                            RichText::new("Waiting for a response…")
                                .color(DashColors::text_secondary(dark_mode)),
                        );
                    }
                    OrchardPayContactState::PendingInboundUnaccepted { .. } => {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Wants to connect with you")
                                    .color(DashColors::text_secondary(dark_mode)),
                            );
                            if ui.button("Accept").clicked() {
                                action |= self.accept_clicked(counterparty);
                            }
                        });
                    }
                    OrchardPayContactState::Established { .. } => {
                        ui.label(
                            RichText::new("Connected").color(DashColors::success_color(dark_mode)),
                        );
                    }
                }
            });
            ui.add_space(6.0);
        }

        action
    }

    fn render_search(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;

        ui.horizontal(|ui| {
            ui.label("Search by DPNS name:");
            ui.text_edit_singleline(&mut self.search_query);
            if ui.button("Search").clicked() && !self.search_query.trim().is_empty() {
                self.searching = true;
                action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                    OrchardPayTask::SearchContacts {
                        search_query: self.search_query.clone(),
                    },
                )));
            }
        });
        ui.add_space(10.0);

        if self.searching {
            ui.label("Searching…");
        }

        for result in self.search_results.clone() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(&result.username);
                    if result.contactable {
                        if ui.button("Add Contact").clicked() {
                            action |= self.initiate_clicked(result.identity_id);
                        }
                    } else {
                        ui.label(
                            RichText::new("Hasn't set up OrchardPay yet")
                                .color(DashColors::text_secondary(dark_mode)),
                        );
                    }
                });
            });
            ui.add_space(4.0);
        }

        action
    }

    fn accept_clicked(&mut self, counterparty_identity_id: Identifier) -> AppAction {
        let (Some(identity), Some(key), Some(wallet)) = (
            self.identity.clone(),
            self.selected_key.clone(),
            self.selected_wallet.clone(),
        ) else {
            return AppAction::None;
        };
        let Ok(seed_hash) = wallet.read().map(|w| w.seed_hash()) else {
            return AppAction::None;
        };

        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::AcceptContact {
                qualified_identity: identity,
                identity_key: key,
                counterparty_identity_id,
                seed_hash,
            },
        )))
    }

    fn initiate_clicked(&mut self, counterparty_identity_id: Identifier) -> AppAction {
        let (Some(identity), Some(key), Some(wallet)) = (
            self.identity.clone(),
            self.selected_key.clone(),
            self.selected_wallet.clone(),
        ) else {
            return AppAction::None;
        };
        let Ok(seed_hash) = wallet.read().map(|w| w.seed_hash()) else {
            return AppAction::None;
        };

        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::InitiateContact {
                qualified_identity: identity,
                identity_key: key,
                counterparty_identity_id,
                seed_hash,
            },
        )))
    }
}

impl ScreenLike for OrchardPayScreen {
    fn refresh(&mut self) {
        let (identity, selected_key, selected_wallet) =
            Self::resolve_identity_context(&self.app_context);
        self.identity = identity;
        self.selected_key = selected_key;
        self.selected_wallet = selected_wallet;
        self.wallet_open_attempted = false;
        // Force a fresh shielded-address check — the most common reason to
        // refresh is returning from having just published one.
        self.has_shielded_address = None;
        self.shielded_address_check_dispatched = false;
    }

    fn display_message(&mut self, _message: &str, message_type: MessageType) {
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.searching = false;
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        match result {
            BackendTaskSuccessResult::OrchardPayContactSearchResults(results) => {
                self.search_results = results;
                self.searching = false;
            }
            BackendTaskSuccessResult::OrchardPayOwnShieldedAddressStatus {
                identity_id,
                published,
            } => {
                if self.identity.as_ref().map(|i| i.identity.id()) == Some(identity_id) {
                    self.has_shielded_address = Some(published);
                }
            }
            _ => {}
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let breadcrumbs = vec![("OrchardPay", AppAction::None)];
        let mut action = add_top_panel(ui, &self.app_context, breadcrumbs, vec![]);
        action |= add_left_panel(ui, &self.app_context, RootScreenType::RootScreenOrchardPay);

        action |= island_central_panel(ui, |ui| {
            let mut inner_action = AppAction::None;

            if let Some(wallet) = self.selected_wallet.clone() {
                if !self.wallet_open_attempted {
                    if let Err(e) = try_open_wallet_no_password(&self.app_context, &wallet) {
                        MessageBanner::set_global(ui.ctx(), &e, MessageType::Error)
                            .disable_auto_dismiss();
                    }
                    self.wallet_open_attempted = true;
                }
                if wallet_needs_unlock(&wallet) {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 150, 50),
                        "Wallet is locked. Please unlock to continue.",
                    );
                    ui.add_space(8.0);
                    if ui.button("Unlock Wallet").clicked() {
                        self.wallet_unlock_popup.open();
                    }
                    return inner_action;
                }
            }

            match self.compute_local_readiness() {
                LocalReadiness::NoIdentity => {
                    inner_action |= self.render_needs_identity(ui);
                }
                LocalReadiness::NoDpnsName => {
                    inner_action |= self.render_needs_dpns_name(ui);
                }
                LocalReadiness::ContractNotConfigured => {
                    self.render_contract_not_configured(ui);
                }
                LocalReadiness::ContractConfigured => match self.has_shielded_address {
                    None => {
                        if !self.shielded_address_check_dispatched
                            && let Some(identity) = &self.identity
                        {
                            self.shielded_address_check_dispatched = true;
                            inner_action |= AppAction::BackendTask(BackendTask::OrchardPayTask(
                                Box::new(OrchardPayTask::CheckOwnShieldedAddress {
                                    identity_id: identity.identity.id(),
                                }),
                            ));
                        }
                        ui.label("Checking your OrchardPay setup…");
                    }
                    Some(false) => {
                        inner_action |= self.render_needs_shielded_address(ui);
                    }
                    Some(true) => {
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    self.orchardpay_subscreen == OrchardPaySubscreen::Contacts,
                                    "Contacts",
                                )
                                .clicked()
                            {
                                self.orchardpay_subscreen = OrchardPaySubscreen::Contacts;
                            }
                            if ui
                                .selectable_label(
                                    self.orchardpay_subscreen == OrchardPaySubscreen::Search,
                                    "Search",
                                )
                                .clicked()
                            {
                                self.orchardpay_subscreen = OrchardPaySubscreen::Search;
                            }
                        });
                        ui.add_space(10.0);

                        inner_action |= match self.orchardpay_subscreen {
                            OrchardPaySubscreen::Contacts => self.render_contacts(ui),
                            OrchardPaySubscreen::Search => self.render_search(ui),
                        };
                    }
                },
            }

            inner_action
        });

        if self.wallet_unlock_popup.is_open()
            && let Some(wallet) = &self.selected_wallet
        {
            self.wallet_unlock_popup
                .show(ui.ctx(), wallet, &self.app_context);
        }

        action
    }
}
