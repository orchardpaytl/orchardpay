//! OrchardPay's consolidated private-contacts root screen (Milestone D):
//! visually mirrors `DashPayScreen`/`DashPaySubscreen` — a left-hand
//! subscreen nav with Profile / Contacts / Payments / Send Friend Request —
//! but keeps a single screen instance with a local subscreen toggle rather
//! than DashPay's one-`RootScreenType`-per-subscreen pattern (simpler, and
//! OrchardPay has no need for deep-linkable subscreen URLs yet).
//!
//! The Profile tab reuses DashPay's own `ProfileScreen` widget unmodified —
//! a profile (display name, avatar, bio) isn't protocol-specific, so there's
//! no reason to duplicate it.
//!
//! Gated behind a readiness check: the whole screen (including the
//! subscreen nav) is only shown once the active identity has a DPNS name
//! and OrchardPay's contract is configured for this network — otherwise the
//! screen guides the user through whichever is missing, in order. Within
//! that, Contacts and Send Friend Request each additionally require a
//! published `shieldedAddress` document (Profile and Payments don't).
//! OrchardPay-bound ENCRYPTION/DECRYPTION keys are generated automatically
//! as part of publishing that address
//! (`backend_task::orchardpay::keys::ensure_own_orchardpay_keys`).

use crate::app::AppAction;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::contact_search::OrchardPayContactSearchResult;
use crate::backend_task::orchardpay::messages::RecentContactActivity;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::fee_estimation::format_credits_as_dash;
use crate::model::orchardpay::OrchardPayContactState;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::MessageBanner;
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::subscreen_chooser_panel::{
    SubscreenNavItem, add_subscreen_chooser_panel,
};
use crate::ui::components::top_panel::{
    add_top_panel_with_global_nav_and_label, subdued_everyday_spec,
};
use crate::ui::components::wallet_unlock_popup::{
    WalletUnlockPopup, try_open_wallet_no_password, wallet_needs_unlock,
};
use crate::ui::dashpay::format_relative_time;
use crate::ui::dashpay::profile_screen::ProfileScreen;
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
    Profile,
    Contacts,
    /// Established contacts ordered by their conversation's most recent
    /// activity (newest first), instead of Contacts' unordered list.
    MostRecent,
    Payments,
    /// "Send Friend Request": DPNS search + initiate a new contact.
    AddContact,
    /// Static informational tab: what OrchardPay is, how it differs from
    /// DashPay, and links to the design articles it grew out of.
    About,
    /// Static informational tab: the quantum-computing risk to shielded
    /// addresses and what happens if it materializes.
    QcWarning,
}

const TAB_PROFILE: &str = "orchardpay_tab_profile";
const TAB_CONTACTS: &str = "orchardpay_tab_contacts";
const TAB_MOST_RECENT: &str = "orchardpay_tab_most_recent";
const TAB_PAYMENTS: &str = "orchardpay_tab_payments";
const TAB_ADD_CONTACT: &str = "orchardpay_tab_add_contact";
const TAB_ABOUT: &str = "orchardpay_tab_about";
const TAB_QC_WARNING: &str = "orchardpay_tab_qc_warning";

/// What, if anything, stands between the active identity and being able to
/// use OrchardPay at all. Checked in this order because each step depends
/// on the previous one (a DPNS name check is meaningless with no identity;
/// a contract check is meaningless with no identity to bind keys to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    profile_screen: ProfileScreen,
    search_query: String,
    search_results: Vec<OrchardPayContactSearchResult>,
    searching: bool,
    /// `None` = not checked yet this visit; `Some(_)` = last known publish
    /// status for the active identity. Reset on `refresh()` so returning
    /// from the shielded-address setup screen re-checks rather than
    /// showing a stale "not published" prompt.
    has_shielded_address: Option<bool>,
    shielded_address_check_dispatched: bool,
    /// `None` = not fetched yet this visit (renders "Loading…").
    /// `Some(_)` = last-known ordering. Reset on `refresh()` and by the
    /// "Refresh" button so leaving/re-entering or an explicit refresh
    /// re-fetches rather than showing stale ordering.
    recent_activity: Option<Vec<RecentContactActivity>>,
    recent_activity_dispatched: bool,
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
            profile_screen: ProfileScreen::new(app_context.clone())
                .with_heading("My OrchardPay Profile (reuses DashPay)"),
            search_query: String::new(),
            search_results: Vec::new(),
            searching: false,
            has_shielded_address: None,
            shielded_address_check_dispatched: false,
            recent_activity: None,
            recent_activity_dispatched: false,
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

    /// "Shielded balance: X DASH", rendered on the far right of the shared top
    /// panel so a user composing a Payment can see what they have to work
    /// with without leaving OrchardPay. Reads
    /// `AppContext::shielded_balance_credits` — an in-memory snapshot kept
    /// current by the shielded sync event bridge, no network call or task
    /// dispatch needed. `None` if no wallet is selected yet.
    fn shielded_balance_label(&self) -> Option<String> {
        let wallet = self.selected_wallet.as_ref()?;
        let seed_hash = wallet.read().ok()?.seed_hash();
        let balance = self.app_context.shielded_balance_credits(&seed_hash);
        Some(format!(
            "Shielded balance: {}",
            format_credits_as_dash(balance)
        ))
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

        if self.has_shielded_address != Some(true) {
            return self.render_needs_shielded_address(ui);
        }

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

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Missing a contact after reinstalling?")
                    .color(DashColors::text_secondary(dark_mode)),
            );
            if ui.button("Recover from Network").clicked() {
                action |= self.recover_contacts_clicked();
            }
        });
        ui.add_space(8.0);

        if contacts.is_empty() {
            ui.label(
                RichText::new(
                    "No private contacts yet. Use Send Friend Request to find someone on OrchardPay.",
                )
                .color(DashColors::text_secondary(dark_mode)),
            );
            return action;
        }

        for counterparty in contacts {
            let Ok(Some(state)) = backend.orchardpay_get_contact_state(&owner_id, &counterparty)
            else {
                continue;
            };

            let (name, created_at) = match &state {
                OrchardPayContactState::PendingOutbound {
                    name, created_at, ..
                }
                | OrchardPayContactState::PendingInboundUnaccepted {
                    name, created_at, ..
                }
                | OrchardPayContactState::Established {
                    name, created_at, ..
                } => (name.clone(), *created_at),
            };

            ui.group(|ui| {
                match &name {
                    Some(name) => ui.label(RichText::new(name)),
                    None => {
                        ui.label(RichText::new(counterparty.to_string(Encoding::Base58)).monospace())
                    }
                };
                if let Some(sent_text) = created_at.and_then(format_relative_time) {
                    ui.label(
                        RichText::new(format!("Sent {sent_text}"))
                            .size(11.0)
                            .color(DashColors::text_secondary(dark_mode)),
                    );
                }
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
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Connected")
                                    .color(DashColors::success_color(dark_mode)),
                            );
                            if ui.button("Open Conversation").clicked() {
                                action |= AppAction::AddScreen(Screen::MessageThreadScreen(
                                    crate::ui::orchardpay::message_thread_screen::MessageThreadScreen::new(
                                        identity.clone(),
                                        counterparty,
                                        &self.app_context,
                                    ),
                                ));
                            }
                        });
                    }
                }
            });
            ui.add_space(6.0);
        }

        action
    }

    fn render_most_recent(&mut self, ui: &mut Ui) -> AppAction {
        if self.has_shielded_address != Some(true) {
            return self.render_needs_shielded_address(ui);
        }

        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;

        let Some(identity) = self.identity.clone() else {
            ui.label("No identity available. Register or select an identity first.");
            return action;
        };

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(
                    "Established contacts, ordered by their conversation's most recent activity.",
                )
                .color(DashColors::text_secondary(dark_mode)),
            );
            if ui.button("Refresh").clicked() {
                self.recent_activity = None;
                self.recent_activity_dispatched = false;
            }
        });
        ui.add_space(8.0);

        if !self.recent_activity_dispatched && self.recent_activity.is_none() {
            self.recent_activity_dispatched = true;
            action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                OrchardPayTask::LoadRecentActivity {
                    qualified_identity: identity.clone(),
                },
            )));
        }

        let Some(entries) = self.recent_activity.clone() else {
            ui.label(RichText::new("Loading…").color(DashColors::text_secondary(dark_mode)));
            return action;
        };

        if entries.is_empty() {
            ui.label(
                RichText::new(
                    "No established contacts yet. Use Send Friend Request to find someone on OrchardPay.",
                )
                .color(DashColors::text_secondary(dark_mode)),
            );
            return action;
        }

        let backend = match self.app_context.wallet_backend() {
            Ok(backend) => backend,
            Err(_) => {
                ui.label("Wallet backend is not ready yet.");
                return action;
            }
        };
        let owner_id = identity.identity.id();

        for entry in entries {
            let Ok(Some(OrchardPayContactState::Established { name, .. })) =
                backend.orchardpay_get_contact_state(&owner_id, &entry.identity_id)
            else {
                continue;
            };

            ui.group(|ui| {
                match &name {
                    Some(name) => ui.label(RichText::new(name)),
                    None => ui.label(
                        RichText::new(entry.identity_id.to_string(Encoding::Base58)).monospace(),
                    ),
                };
                let activity_label = match (
                    entry.has_messages,
                    entry.last_activity.and_then(format_relative_time),
                ) {
                    (true, Some(when)) => format!("Last activity {when}"),
                    (false, Some(when)) => format!("No messages yet — connected {when}"),
                    (_, None) => "No messages yet".to_string(),
                };
                ui.label(
                    RichText::new(activity_label)
                        .size(11.0)
                        .color(DashColors::text_secondary(dark_mode)),
                );
                if ui.button("Open Conversation").clicked() {
                    action |= AppAction::AddScreen(Screen::MessageThreadScreen(
                        crate::ui::orchardpay::message_thread_screen::MessageThreadScreen::new(
                            identity.clone(),
                            entry.identity_id,
                            &self.app_context,
                        ),
                    ));
                }
            });
            ui.add_space(6.0);
        }

        action
    }

    fn render_payments(&self, ui: &mut Ui) {
        let dark_mode = ui.style().visuals.dark_mode;
        ui.label(
            RichText::new(
                "Payments are sent from a conversation with a contact — open a contact from the Contacts tab to send or request one.",
            )
            .color(DashColors::text_secondary(dark_mode)),
        );
    }

    fn render_about(&self, ui: &mut Ui) {
        let dark_mode = ui.style().visuals.dark_mode;
        let secondary =
            |text: &str| RichText::new(text).color(DashColors::text_secondary(dark_mode));

        ui.heading("About OrchardPay");
        ui.add_space(6.0);
        ui.label(
            "OrchardPay is a private contact and messaging protocol built on \
             Dash Platform, combining zero-knowledge shielded transactions \
             with Platform data contracts. It grew out of a two-part design \
             series exploring how those two primitives could be combined — \
             the links are below.",
        );

        ui.add_space(16.0);
        ui.heading("How OrchardPay differs from DashPay");
        ui.add_space(6.0);

        ui.label(RichText::new("No public social graph").strong());
        ui.label(secondary(
            "DashPay's contact-request documents are public and queryable — \
             anyone can see who has requested contact with whom. OrchardPay's \
             contactAnchor documents contain no public identifying or \
             connecting data: the only way to find one is to already know \
             its document ID, which is delivered \
             privately through a shielded on-chain transaction memo that only \
             the intended recipient can decrypt.",
        ));
        ui.add_space(10.0);

        ui.label(RichText::new("One channel, unlimited uses").strong());
        ui.label(secondary(
            "DashPay's contact-request documents exist to carry contact info \
             only. OrchardPay's contactAnchor and encryptedMessage documents \
             form a general private-communication channel — messages, \
             payment requests, and other structured content all use the \
             exact same encrypted shape, so Platform (and anyone else \
             watching) can't tell them apart. New message types can be added \
             later without changing the data contract.",
        ));
        ui.add_space(10.0);

        ui.label(RichText::new("Payments carry real meaning").strong());
        ui.label(secondary(
            "Sending a payment through OrchardPay performs an actual \
             shielded value transfer, correlated to its message through an \
             on-chain memo — not just a record that a payment happened.",
        ));

        ui.add_space(16.0);
        ui.heading("Further reading");
        ui.add_space(6.0);
        ui.hyperlink_to(
            "Combining ZK and Data Contracts",
            "https://pocandstablecostdiscoverer.substack.com/p/combining-zk-and-data-contracts",
        );
        ui.hyperlink_to(
            "OrchardPay Part 2: Design Choices",
            "https://pocandstablecostdiscoverer.substack.com/p/orchardpay-part-2-design-choices",
        );
    }

    fn render_qc_warning(&self, ui: &mut Ui) {
        let dark_mode = ui.style().visuals.dark_mode;

        ui.heading(RichText::new("QC Warning").color(DashColors::warning_color(dark_mode)));
        ui.add_space(6.0);
        ui.label(
            "QC, or Quantum Computing, is a threat to this application, as a \
             quantum computer can break the encryption of shielded addresses.",
        );
        ui.add_space(10.0);
        ui.label(
            "If QC does become a reality, shielded addresses will need to be \
             upgraded to new quantum-resistant addresses, and any funds on \
             your public shielded address will need to be moved elsewhere.",
        );
    }

    fn render_add_contact(&mut self, ui: &mut Ui) -> AppAction {
        if self.has_shielded_address != Some(true) {
            return self.render_needs_shielded_address(ui);
        }

        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;

        ui.heading("Send Friend Request");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Search by DPNS name:");
            ui.text_edit_singleline(&mut self.search_query);
            if ui.button("Search").clicked()
                && !self.search_query.trim().is_empty()
                && let Some(identity) = &self.identity
            {
                self.searching = true;
                action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                    OrchardPayTask::SearchContacts {
                        search_query: self.search_query.clone(),
                        owner_identity_id: identity.identity.id(),
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
                    match &result.existing_relationship {
                        Some(OrchardPayContactState::PendingOutbound { .. }) => {
                            ui.label(
                                RichText::new("Request already sent")
                                    .color(DashColors::text_secondary(dark_mode)),
                            );
                        }
                        Some(OrchardPayContactState::PendingInboundUnaccepted { .. }) => {
                            ui.label(
                                RichText::new(
                                    "Wants to connect with you — check Contacts to accept",
                                )
                                .color(DashColors::text_secondary(dark_mode)),
                            );
                        }
                        Some(OrchardPayContactState::Established { .. }) => {
                            ui.label(
                                RichText::new("Already connected")
                                    .color(DashColors::success_color(dark_mode)),
                            );
                        }
                        None if result.contactable => {
                            if ui.button("Add Contact").clicked() {
                                action |= self
                                    .initiate_clicked(result.identity_id, result.username.clone());
                            }
                        }
                        None => {
                            ui.label(
                                RichText::new("Hasn't set up OrchardPay yet")
                                    .color(DashColors::text_secondary(dark_mode)),
                            );
                        }
                    }
                });
            });
            ui.add_space(4.0);
        }

        action
    }

    fn recover_contacts_clicked(&mut self) -> AppAction {
        let (Some(identity), Some(wallet)) = (self.identity.clone(), self.selected_wallet.clone())
        else {
            return AppAction::None;
        };
        let Ok(seed_hash) = wallet.read().map(|w| w.seed_hash()) else {
            return AppAction::None;
        };

        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::RecoverContacts {
                qualified_identity: identity,
                seed_hash,
            },
        )))
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

    fn initiate_clicked(
        &mut self,
        counterparty_identity_id: Identifier,
        counterparty_name: String,
    ) -> AppAction {
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
                counterparty_name,
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
        self.recent_activity = None;
        self.recent_activity_dispatched = false;
        self.profile_screen.refresh();
    }

    fn display_message(&mut self, message: &str, message_type: MessageType) {
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.searching = false;
        }
        if self.orchardpay_subscreen == OrchardPaySubscreen::Profile {
            self.profile_screen.display_message(message, message_type);
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        match &result {
            BackendTaskSuccessResult::OrchardPayContactSearchResults(results) => {
                self.search_results = results.clone();
                self.searching = false;
            }
            BackendTaskSuccessResult::OrchardPayOwnShieldedAddressStatus {
                identity_id,
                published,
            } => {
                if self.identity.as_ref().map(|i| i.identity.id()) == Some(*identity_id) {
                    self.has_shielded_address = Some(*published);
                }
            }
            BackendTaskSuccessResult::OrchardPayRecentActivity(entries) => {
                self.recent_activity = Some(entries.clone());
            }
            _ => {}
        }
        if self.orchardpay_subscreen == OrchardPaySubscreen::Profile {
            self.profile_screen.display_task_result(result);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let readiness = self.compute_local_readiness();

        let mut action = add_top_panel_with_global_nav_and_label(
            ui,
            &self.app_context,
            subdued_everyday_spec("OrchardPay", RootScreenType::RootScreenOrchardPay),
            vec![],
            self.shielded_balance_label(),
        );
        action |= add_left_panel(ui, &self.app_context, RootScreenType::RootScreenOrchardPay);

        if readiness == LocalReadiness::ContractConfigured {
            // Kick off (once) the shielded-address check the Contacts/Send
            // Friend Request tabs need — cheap and harmless to run even
            // while viewing Profile/Payments.
            if self.has_shielded_address.is_none()
                && !self.shielded_address_check_dispatched
                && let Some(identity) = &self.identity
            {
                self.shielded_address_check_dispatched = true;
                action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                    OrchardPayTask::CheckOwnShieldedAddress {
                        identity_id: identity.identity.id(),
                    },
                )));
            }

            let items = vec![
                SubscreenNavItem::new(
                    "My Profile",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Profile,
                    AppAction::Custom(TAB_PROFILE.to_string()),
                ),
                SubscreenNavItem::new(
                    "Contacts",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Contacts,
                    AppAction::Custom(TAB_CONTACTS.to_string()),
                ),
                SubscreenNavItem::new(
                    "Most Recent",
                    self.orchardpay_subscreen == OrchardPaySubscreen::MostRecent,
                    AppAction::Custom(TAB_MOST_RECENT.to_string()),
                ),
                SubscreenNavItem::new(
                    "Payments",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Payments,
                    AppAction::Custom(TAB_PAYMENTS.to_string()),
                ),
                SubscreenNavItem::new(
                    "Send Friend Request",
                    self.orchardpay_subscreen == OrchardPaySubscreen::AddContact,
                    AppAction::Custom(TAB_ADD_CONTACT.to_string()),
                ),
                SubscreenNavItem::new(
                    "About",
                    self.orchardpay_subscreen == OrchardPaySubscreen::About,
                    AppAction::Custom(TAB_ABOUT.to_string()),
                ),
                SubscreenNavItem::new(
                    "QC Warning",
                    self.orchardpay_subscreen == OrchardPaySubscreen::QcWarning,
                    AppAction::Custom(TAB_QC_WARNING.to_string()),
                ),
            ];
            let nav_action = add_subscreen_chooser_panel(
                ui,
                "orchardpay_subscreen_chooser",
                false,
                false,
                items,
            );
            match nav_action {
                AppAction::Custom(ref tag) if tag == TAB_PROFILE => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::Profile;
                }
                AppAction::Custom(ref tag) if tag == TAB_CONTACTS => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::Contacts;
                }
                AppAction::Custom(ref tag) if tag == TAB_MOST_RECENT => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::MostRecent;
                }
                AppAction::Custom(ref tag) if tag == TAB_PAYMENTS => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::Payments;
                }
                AppAction::Custom(ref tag) if tag == TAB_ADD_CONTACT => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::AddContact;
                }
                AppAction::Custom(ref tag) if tag == TAB_ABOUT => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::About;
                }
                AppAction::Custom(ref tag) if tag == TAB_QC_WARNING => {
                    self.orchardpay_subscreen = OrchardPaySubscreen::QcWarning;
                }
                other => action |= other,
            }
        }

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

            match readiness {
                LocalReadiness::NoIdentity => {
                    inner_action |= self.render_needs_identity(ui);
                }
                LocalReadiness::NoDpnsName => {
                    inner_action |= self.render_needs_dpns_name(ui);
                }
                LocalReadiness::ContractNotConfigured => {
                    self.render_contract_not_configured(ui);
                }
                LocalReadiness::ContractConfigured => {
                    inner_action |= match self.orchardpay_subscreen {
                        OrchardPaySubscreen::Profile => self.profile_screen.render(ui),
                        OrchardPaySubscreen::Contacts => self.render_contacts(ui),
                        OrchardPaySubscreen::MostRecent => self.render_most_recent(ui),
                        OrchardPaySubscreen::Payments => {
                            self.render_payments(ui);
                            AppAction::None
                        }
                        OrchardPaySubscreen::AddContact => self.render_add_contact(ui),
                        OrchardPaySubscreen::About => {
                            self.render_about(ui);
                            AppAction::None
                        }
                        OrchardPaySubscreen::QcWarning => {
                            self.render_qc_warning(ui);
                            AppAction::None
                        }
                    };
                }
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
