//! OrchardPay's consolidated private-contacts root screen (Milestone D):
//! a contacts list plus DPNS-based contact search, mirroring the
//! already-consolidated `DashPayScreen`/`DashPaySubscreen` pattern (one
//! `RootScreenType` with an internal subscreen switch, not one root screen
//! per feature).

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
use crate::ui::theme::DashColors;
use crate::ui::{MessageType, RootScreenType, ScreenLike};
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
}

impl OrchardPayScreen {
    pub fn new(app_context: &Arc<AppContext>, orchardpay_subscreen: OrchardPaySubscreen) -> Self {
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
        }
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
    fn display_message(&mut self, _message: &str, message_type: MessageType) {
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.searching = false;
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        if let BackendTaskSuccessResult::OrchardPayContactSearchResults(results) = result {
            self.search_results = results;
            self.searching = false;
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let breadcrumbs = vec![("Private Contacts", AppAction::None)];
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
