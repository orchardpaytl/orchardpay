//! OrchardPay's consolidated private-contacts root screen (Milestone D):
//! visually mirrors `DashPayScreen`/`DashPaySubscreen` — a left-hand
//! subscreen nav with Profile / Contacts / Shielded TXs / Send Friend Request —
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
//! published `shieldedAddress` document (Profile and Shielded TXs don't).
//! OrchardPay-bound ENCRYPTION/DECRYPTION keys are generated automatically
//! as part of publishing that address
//! (`backend_task::orchardpay::keys::ensure_own_orchardpay_keys`).

use crate::app::AppAction;
use crate::backend_task::identity::IdentityTask;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::contact_search::OrchardPayContactSearchResult;
use crate::backend_task::orchardpay::messages::RecentContactActivity;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::dpns::strip_dash_suffix;
use crate::model::fee_estimation::{format_credits_as_dash, format_credits_as_dash_significant};
use crate::model::orchardpay::{
    CREDIT_BLOCKED_TOOLTIP, OrchardPayContactState, ShieldedActivityRow, SpentEntry,
    group_shielded_activity, is_credit_balance_blocked, is_credit_balance_low,
};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::confirmation_dialog::{ConfirmationDialog, ConfirmationStatus};
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
use crate::ui::components::{Component, MessageBanner};
use crate::ui::dashpay::format_relative_time;
use crate::ui::dashpay::profile_screen::ProfileScreen;
use crate::ui::identities::get_selected_wallet;
use crate::ui::identities::register_dpns_name_screen::RegisterDpnsNameSource;
use crate::ui::orchardpay::shielded_address_screen::ShieldedAddressSetupScreen;
use crate::ui::theme::{DashColors, ResponseExt};
use crate::ui::{MessageType, RootScreenType, Screen, ScreenLike, ScreenType};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::{Identifier, IdentityPublicKey};
use egui::{RichText, ScrollArea, Ui};
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

/// Render a `Duration` (typically `Instant::elapsed()`) as a short
/// human-readable "X ago" string, matching `WalletsScreen`'s own
/// `format_duration_ago` — not shared cross-module since it's a few lines
/// and each caller's `Duration` comes from a different clock source.
fn format_duration_ago(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// The activity label for one [`RecentContactActivity`] entry — shared by
/// the Most Recent tab's own list and the Contacts tab's `Established`
/// rows, so the wording only ever lives in one place.
fn recent_activity_label(entry: &RecentContactActivity) -> String {
    match (
        entry.has_messages,
        entry.last_activity.and_then(format_relative_time),
    ) {
        (true, Some(when)) => format!("Last activity {when}"),
        (false, Some(when)) => format!("No messages yet — connected {when}"),
        (_, None) => "No messages yet".to_string(),
    }
}

/// Renders one shielded-activity row as a labeled card: the kind/amount
/// header, memo, and confirmation status. Shared between the Unspent Notes
/// list and both sides of a Spent Notes pairing.
fn render_shielded_note_card(ui: &mut Ui, row: &ShieldedActivityRow, dark_mode: bool) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(row.kind.label()).strong());
            ui.label(format_credits_as_dash(row.amount_credits));
        });
        ui.label(
            RichText::new(&row.memo_label)
                .size(11.0)
                .color(DashColors::text_secondary(dark_mode)),
        );
        let status_label = match (row.pending, row.block_height) {
            (true, _) => "Pending".to_string(),
            (false, Some(height)) => format!("Verified as of block {height}"),
            (false, None) => "Verified".to_string(),
        };
        ui.label(
            RichText::new(status_label)
                .size(11.0)
                .color(DashColors::text_secondary(dark_mode)),
        );
    });
}

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
    /// `None` = not yet known (renders a "checking…" state, not the
    /// "publish" prompt — those two must never be conflated). `Some(true)` =
    /// confirmed published, seeded from the local cache
    /// (`wallet_backend::orchardpay_get_has_shielded_address`) when
    /// available so a returning user never waits on a network round-trip.
    /// `Some(false)` = a live `CheckOwnShieldedAddress` confirmed there is
    /// none — this is the only state that shows the "publish" prompt.
    /// Re-seeded from the cache on `refresh()`.
    has_shielded_address: Option<bool>,
    shielded_address_check_dispatched: bool,
    /// `None` = not fetched yet this visit (renders "Loading…").
    /// `Some(_)` = last-known ordering. Reset on `refresh()` and by the
    /// "Refresh" button so leaving/re-entering or an explicit refresh
    /// re-fetches rather than showing stale ordering.
    recent_activity: Option<Vec<RecentContactActivity>>,
    recent_activity_dispatched: bool,
    /// `None` = not fetched yet this visit (renders "Loading…"). Reset on
    /// `refresh()` and by the Shielded TXs tab's "Refresh" button. Diagnostic
    /// view of the wallet's shielded transaction history — see
    /// `wallet_backend::shielded::shielded_activity`.
    shielded_activity: Option<Vec<ShieldedActivityRow>>,
    shielded_activity_dispatched: bool,
    /// Set on construction, on `refresh()` (tab (re)entry), and after a
    /// credit-spending action completes — drained by `ui()` into a
    /// `RefreshIdentity` dispatch. Identity credit balance has no live push
    /// like the shielded balance does, so this is what keeps the top-panel
    /// readout and the low-credit action gates reasonably current.
    pending_identity_refresh: bool,
    /// The one confirmation modal that can be up at a time — shared by
    /// Accept and Add Contact (both build the real `AppAction` up front,
    /// then stash it here instead of dispatching immediately; only
    /// `render_pending_confirmation`'s `Confirmed` arm actually returns it).
    pending_confirmation: Option<PendingConfirmation>,
}

/// A built `AppAction` sitting behind a confirmation dialog — the dialog
/// carries the user-facing "what is about to happen" description; the
/// action itself is only returned to the caller once the user confirms.
struct PendingConfirmation {
    dialog: ConfirmationDialog,
    action: Box<AppAction>,
}

impl OrchardPayScreen {
    pub fn new(app_context: &Arc<AppContext>, orchardpay_subscreen: OrchardPaySubscreen) -> Self {
        let (identity, selected_key, selected_wallet) = Self::resolve_identity_context(app_context);
        let has_shielded_address =
            Self::cached_shielded_address_status(app_context, identity.as_ref());

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
            // If the cache already confirms it, skip the check entirely —
            // no network round-trip, no "checking…"/"publish" flash on open.
            shielded_address_check_dispatched: has_shielded_address == Some(true),
            has_shielded_address,
            recent_activity: None,
            recent_activity_dispatched: false,
            shielded_activity: None,
            shielded_activity_dispatched: false,
            pending_identity_refresh: true,
            pending_confirmation: None,
        }
    }

    /// Read the locally cached "has this identity published a
    /// shieldedAddress" flag (`wallet_backend::orchardpay_get_has_shielded_address`)
    /// — a synchronous, zero-network local read. `Some(true)` if confirmed;
    /// `None` if never confirmed locally yet (including no identity, or the
    /// wallet backend not being wired up yet), in which case the caller
    /// falls back to the existing live `CheckOwnShieldedAddress` task.
    fn cached_shielded_address_status(
        app_context: &Arc<AppContext>,
        identity: Option<&QualifiedIdentity>,
    ) -> Option<bool> {
        let identity = identity?;
        app_context
            .wallet_backend()
            .ok()?
            .orchardpay_get_has_shielded_address(&identity.identity.id())
            .ok()
            .flatten()
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

    /// "Identity Balance: X DASH · Low Credits   Shielded Balance: Y DASH", rendered
    /// on the far right of the shared top panel so a user composing a
    /// Payment can see what they have to work with without leaving
    /// OrchardPay. The credit half reads straight off the resolved
    /// `QualifiedIdentity` (no live push exists for it, unlike shielded
    /// balance — see `pending_identity_refresh`) and is omitted if no
    /// identity is resolved. The shielded half reads
    /// `AppContext::shielded_balance_credits` — an in-memory snapshot kept
    /// current by the shielded sync event bridge, no network call or task
    /// dispatch needed. `None` only if no wallet is selected yet.
    fn balance_summary_label(&self) -> Option<String> {
        let wallet = self.selected_wallet.as_ref()?;
        let seed_hash = wallet.read().ok()?.seed_hash();
        let shielded = self.app_context.shielded_balance_credits(&seed_hash);
        let mut label = String::new();
        if let Some(credits) = self.identity.as_ref().map(|i| i.identity.balance()) {
            label.push_str(&format!(
                "Identity Balance: {}",
                format_credits_as_dash_significant(credits, 4)
            ));
            if is_credit_balance_low(credits) {
                label.push_str("  ·  Low Credits");
            }
            label.push_str("                        ");
        }
        label.push_str(&format!(
            "Shielded Balance: {}",
            format_credits_as_dash_significant(shielded, 4)
        ));
        Some(label)
    }

    fn render_needs_identity(&self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        ui.label("OrchardPay needs an identity to publish a shielded address for.");
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

    /// Shown only while `has_shielded_address` is still `None` — genuinely
    /// unknown, not confirmed absent. Never shows the "publish" call to
    /// action, which would wrongly suggest the user needs to act before
    /// the check has even finished.
    fn render_checking_shielded_address(&self, ui: &mut Ui) -> AppAction {
        ui.label(
            RichText::new("Checking whether you've already published a shielded address…")
                .color(DashColors::text_secondary(ui.style().visuals.dark_mode)),
        );
        AppAction::None
    }

    fn render_needs_shielded_address(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        let Some(identity) = self.identity.clone() else {
            return action;
        };

        ui.label(
            "You haven't published a shielded address yet — this is how contacts find you. Publishing sets up everything OrchardPay needs, including your private encryption keys.",
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

        match self.has_shielded_address {
            Some(true) => {}
            Some(false) => return self.render_needs_shielded_address(ui),
            None => return self.render_checking_shielded_address(ui),
        }

        let dark_mode = ui.style().visuals.dark_mode;

        let Some(identity) = self.identity.clone() else {
            ui.label("No identity available. Register or select an identity first.");
            return action;
        };

        // Same idempotent dispatch-if-not-loaded guard `render_most_recent`
        // uses — shares that tab's `self.recent_activity` cache (gated by
        // `recent_activity_dispatched`, so this only ever fires once) so
        // `Established` rows below can show real last-message activity
        // regardless of which tab the user opens first.
        if !self.recent_activity_dispatched && self.recent_activity.is_none() {
            self.recent_activity_dispatched = true;
            action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                OrchardPayTask::LoadRecentActivity {
                    qualified_identity: identity.clone(),
                },
            )));
        }

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
        let credit_blocked = is_credit_balance_blocked(identity.identity.balance());

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Missing a contact after reinstalling?")
                    .color(DashColors::text_secondary(dark_mode)),
            );
            if ui.button("Recover from Network").clicked() {
                action |= self.recover_contacts_clicked();
            }
        });
        ui.add_space(4.0);

        // Diagnostic: tells a stalled contact-request handshake apart from a
        // wallet that simply hasn't synced recently. Per-note memo detail
        // (including whether contactAnchor/payment memos are being found at
        // all) now lives in the Shielded TXs tab instead of a count here.
        let connection_status = self.app_context.connection_status();
        let last_sync_label = match connection_status.last_shielded_sync_completed_at() {
            Some(at) => format_duration_ago(at.elapsed()),
            None => "not yet this session".to_string(),
        };
        ui.label(
            RichText::new(format!("Last shielded sync: {last_sync_label}"))
                .size(11.0)
                .color(DashColors::text_secondary(dark_mode)),
        );
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

        // Sort alphabetically by resolved name (case-insensitive), falling
        // back to the base58 ID for contacts with no resolved name yet —
        // the same fallback the row itself displays, so sort order and
        // displayed label always agree.
        let mut contacts: Vec<(Identifier, OrchardPayContactState)> = contacts
            .into_iter()
            .filter_map(|counterparty| {
                let state = backend
                    .orchardpay_get_contact_state(&owner_id, &counterparty)
                    .ok()??;
                Some((counterparty, state))
            })
            .collect();
        contacts.sort_by_key(|(counterparty, state)| {
            let name = match state {
                OrchardPayContactState::PendingOutbound { name, .. }
                | OrchardPayContactState::PendingInboundUnaccepted { name, .. }
                | OrchardPayContactState::Established { name, .. } => name.clone(),
            };
            name.unwrap_or_else(|| counterparty.to_string(Encoding::Base58))
                .to_lowercase()
        });

        for (counterparty, state) in contacts {
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
                    Some(name) => ui.label(RichText::new(strip_dash_suffix(name))),
                    None => {
                        ui.label(RichText::new(counterparty.to_string(Encoding::Base58)).monospace())
                    }
                };
                // `Established` rows prefer real message activity (from
                // the same `self.recent_activity` cache `render_most_recent`
                // populates) over the connection date — falls back to
                // "Sent {when}" only while that fetch is still in flight.
                // Pending contacts can't have any `encryptedMessage` yet
                // (`established_state` requires `Established`), so "Sent
                // {when}" from the anchor's own date stays correct for them.
                let activity_label = match &state {
                    OrchardPayContactState::Established { .. } => self
                        .recent_activity
                        .as_ref()
                        .and_then(|entries| {
                            entries.iter().find(|e| e.identity_id == counterparty)
                        })
                        .map(recent_activity_label)
                        .or_else(|| {
                            created_at
                                .and_then(format_relative_time)
                                .map(|when| format!("Sent {when}"))
                        }),
                    _ => created_at
                        .and_then(format_relative_time)
                        .map(|when| format!("Sent {when}")),
                };
                if let Some(activity_label) = activity_label {
                    ui.label(
                        RichText::new(activity_label)
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
                            if ui
                                .add_enabled(!credit_blocked, egui::Button::new("Accept"))
                                .disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
                                .clicked()
                            {
                                let display_name = name
                                    .as_deref()
                                    .map(strip_dash_suffix)
                                    .map(str::to_string)
                                    .unwrap_or_else(|| counterparty.to_string(Encoding::Base58));
                                let confirm_action = self.accept_clicked(counterparty);
                                self.open_confirmation(
                                    "Accept Contact Request",
                                    format!(
                                        "Accept the contact request from {display_name}?"
                                    ),
                                    confirm_action,
                                    false,
                                );
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
        match self.has_shielded_address {
            Some(true) => {}
            Some(false) => return self.render_needs_shielded_address(ui),
            None => return self.render_checking_shielded_address(ui),
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
                    Some(name) => ui.label(RichText::new(strip_dash_suffix(name))),
                    None => ui.label(
                        RichText::new(entry.identity_id.to_string(Encoding::Base58)).monospace(),
                    ),
                };
                ui.label(
                    RichText::new(recent_activity_label(&entry))
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

    fn render_payments(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;

        let Some(wallet) = self.selected_wallet.clone() else {
            ui.label(
                RichText::new("No wallet selected.").color(DashColors::text_secondary(dark_mode)),
            );
            return action;
        };
        let Ok(seed_hash) = wallet.read().map(|w| w.seed_hash()) else {
            return action;
        };

        ui.horizontal(|ui| {
            ui.heading("Shielded Transaction History");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    self.shielded_activity = None;
                    self.shielded_activity_dispatched = false;
                }
            });
        });
        ui.label(
            RichText::new(
                "Every shielded send and receive on this wallet's Orchard address — useful for \
                 confirming a transfer (like a 0.001 DASH contact-request signal) actually \
                 reached the wallet.",
            )
            .size(11.0)
            .color(DashColors::text_secondary(dark_mode)),
        );
        ui.add_space(8.0);

        if self
            .app_context
            .connection_status()
            .last_shielded_sync_completed_at()
            .is_none()
        {
            ui.label(
                RichText::new(
                    "Still syncing shielded activity — the notes and totals below may not \
                     reflect the full picture yet.",
                )
                .size(11.0)
                .color(DashColors::warning_color(dark_mode)),
            );
            ui.add_space(8.0);
        }

        if !self.shielded_activity_dispatched && self.shielded_activity.is_none() {
            self.shielded_activity_dispatched = true;
            action |= AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
                OrchardPayTask::LoadShieldedActivity { seed_hash },
            )));
        }

        let Some(rows) = self.shielded_activity.clone() else {
            ui.label(RichText::new("Loading…").color(DashColors::text_secondary(dark_mode)));
            return action;
        };

        if rows.is_empty() {
            ui.label(
                RichText::new("No shielded transactions found for this wallet yet.")
                    .color(DashColors::text_secondary(dark_mode)),
            );
            return action;
        }

        let view = group_shielded_activity(rows);

        ScrollArea::vertical()
            .id_salt("orchardpay_payments_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Unspent Notes");
                ui.label(
                    RichText::new(format!(
                        "{} note{} · {} total",
                        view.unspent_count,
                        if view.unspent_count == 1 { "" } else { "s" },
                        format_credits_as_dash(view.unspent_total_credits)
                    ))
                    .size(11.0)
                    .color(DashColors::text_secondary(dark_mode)),
                );
                ui.add_space(6.0);
                if view.unspent.is_empty() {
                    ui.label(
                        RichText::new("No unspent notes.")
                            .color(DashColors::text_secondary(dark_mode)),
                    );
                } else {
                    for row in &view.unspent {
                        render_shielded_note_card(ui, row, dark_mode);
                        ui.add_space(6.0);
                    }
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                ui.heading("Spent Notes");
                ui.label(
                    RichText::new(
                        "Where a same-amount send matches a spent note, they're shown side by \
                         side as a best-effort pairing — not a guaranteed link between the two.",
                    )
                    .size(11.0)
                    .color(DashColors::text_secondary(dark_mode)),
                );
                ui.add_space(6.0);
                if view.spent.is_empty() {
                    ui.label(
                        RichText::new("No spent notes yet.")
                            .color(DashColors::text_secondary(dark_mode)),
                    );
                } else {
                    for entry in &view.spent {
                        match entry {
                            SpentEntry::Pair { spent, sent } => {
                                ui.columns(2, |columns| {
                                    render_shielded_note_card(&mut columns[0], spent, dark_mode);
                                    render_shielded_note_card(&mut columns[1], sent, dark_mode);
                                });
                            }
                            SpentEntry::SpentOnly(row) | SpentEntry::SentOnly(row) => {
                                render_shielded_note_card(ui, row, dark_mode);
                            }
                        }
                        ui.add_space(6.0);
                    }
                }
            });

        action
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
        match self.has_shielded_address {
            Some(true) => {}
            Some(false) => return self.render_needs_shielded_address(ui),
            None => return self.render_checking_shielded_address(ui),
        }

        let mut action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;
        let credit_blocked = self
            .identity
            .as_ref()
            .map(|i| is_credit_balance_blocked(i.identity.balance()))
            .unwrap_or(true);

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
                    ui.label(strip_dash_suffix(&result.username));
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
                            if ui
                                .add_enabled(!credit_blocked, egui::Button::new("Add Contact"))
                                .disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
                                .clicked()
                            {
                                let confirm_action = self
                                    .initiate_clicked(result.identity_id, result.username.clone());
                                self.open_confirmation(
                                    "Send Contact Request",
                                    format!("Send a contact request to {}?", result.username),
                                    confirm_action,
                                    false,
                                );
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

    /// Stash `action` behind a confirmation modal instead of dispatching it
    /// immediately — the misclick guard every OrchardPay action that reaches
    /// another party goes through. A no-op if `action` is `AppAction::None`
    /// (the trigger's own precondition, e.g. no identity/key/wallet
    /// resolved, already failed — nothing to confirm).
    fn open_confirmation(
        &mut self,
        title: &str,
        message: String,
        action: AppAction,
        danger_mode: bool,
    ) {
        if matches!(action, AppAction::None) {
            return;
        }
        self.pending_confirmation = Some(PendingConfirmation {
            dialog: ConfirmationDialog::new(title, message)
                .danger_mode(danger_mode)
                .blocks_input(true),
            action: Box::new(action),
        });
    }

    /// Drives the one pending confirmation modal, if any. Returns the real
    /// action only once the user confirms; a cancel (button, Escape, or the
    /// window's close button — see `ConfirmationDialog`) just clears state
    /// and dispatches nothing.
    fn render_pending_confirmation(&mut self, ui: &mut Ui) -> AppAction {
        let response = self
            .pending_confirmation
            .as_mut()
            .and_then(|pending| pending.dialog.show(ui).inner.dialog_response);

        match response {
            Some(ConfirmationStatus::Confirmed) => {
                let Some(pending) = self.pending_confirmation.take() else {
                    return AppAction::None;
                };
                *pending.action
            }
            Some(ConfirmationStatus::Canceled) => {
                self.pending_confirmation = None;
                AppAction::None
            }
            None => AppAction::None,
        }
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
        // Re-read the cache — the most common reason to refresh is
        // returning from having just published a shielded address, which
        // already wrote the cache before this screen is shown again, so
        // this picks it up with no network round-trip. Falls back to a
        // live check only if the cache still doesn't know.
        self.has_shielded_address =
            Self::cached_shielded_address_status(&self.app_context, self.identity.as_ref());
        self.shielded_address_check_dispatched = self.has_shielded_address == Some(true);
        self.recent_activity = None;
        self.recent_activity_dispatched = false;
        self.shielded_activity = None;
        self.shielded_activity_dispatched = false;
        self.pending_identity_refresh = true;
        self.profile_screen.refresh();
    }

    fn display_message(&mut self, message: &str, message_type: MessageType) {
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.searching = false;
            // A failed shielded-address check leaves `has_shielded_address`
            // at `None` — reset the dispatch guard so the "checking…" state
            // isn't permanently stuck; the next frame's `ui()` retries it.
            if self.has_shielded_address.is_none() {
                self.shielded_address_check_dispatched = false;
            }
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
            BackendTaskSuccessResult::OrchardPayShieldedActivity(rows) => {
                self.shielded_activity = Some(rows.clone());
            }
            // A contact request (initiate/accept) publish — both spend
            // identity credits, so the top-panel readout and the
            // low-credit action gates need a fresh balance.
            BackendTaskSuccessResult::BroadcastedDocument(_) => {
                self.pending_identity_refresh = true;
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
            self.balance_summary_label(),
        );
        action |= add_left_panel(ui, &self.app_context, RootScreenType::RootScreenOrchardPay);
        action |= self.render_pending_confirmation(ui);

        if self.pending_identity_refresh
            && let Some(identity) = self.identity.clone()
        {
            self.pending_identity_refresh = false;
            action |= AppAction::BackendTask(BackendTask::IdentityTask(
                IdentityTask::RefreshIdentity(identity),
            ));
        }

        if readiness == LocalReadiness::ContractConfigured {
            // Kick off (once) the shielded-address check the Contacts/Send
            // Friend Request tabs need — cheap and harmless to run even
            // while viewing Profile/Shielded TXs. Already skipped (dispatched
            // guard pre-set) when `new()`/`refresh()` seeded a confirmed
            // `Some(true)` from the local cache.
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
                    "Most Recent",
                    self.orchardpay_subscreen == OrchardPaySubscreen::MostRecent,
                    AppAction::Custom(TAB_MOST_RECENT.to_string()),
                ),
                SubscreenNavItem::new(
                    "Contacts",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Contacts,
                    AppAction::Custom(TAB_CONTACTS.to_string()),
                ),
                SubscreenNavItem::new(
                    "Send Friend Request",
                    self.orchardpay_subscreen == OrchardPaySubscreen::AddContact,
                    AppAction::Custom(TAB_ADD_CONTACT.to_string()),
                ),
                SubscreenNavItem::new(
                    "Shielded TXs",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Payments,
                    AppAction::Custom(TAB_PAYMENTS.to_string()),
                ),
                SubscreenNavItem::new(
                    "Profile",
                    self.orchardpay_subscreen == OrchardPaySubscreen::Profile,
                    AppAction::Custom(TAB_PROFILE.to_string()),
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
                        OrchardPaySubscreen::Payments => self.render_payments(ui),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_task::orchardpay::contact_search::OrchardPayContactSearchResult;
    use crate::context::connection_status::ConnectionStatus;
    use crate::database::test_helpers::create_database_at_path;
    use crate::model::qualified_identity::encrypted_key_storage::KeyStorage;
    use crate::model::qualified_identity::{IdentityStatus, IdentityType};
    use crate::utils::tasks::TaskManager;
    use dash_sdk::dashcore_rpc::dashcore::Network;
    use dash_sdk::dpp::identity::accessors::IdentitySettersV0;
    use dash_sdk::dpp::identity::identity_public_key::accessors::v0::{
        IdentityPublicKeyGettersV0, IdentityPublicKeySettersV0,
    };
    use dash_sdk::dpp::identity::{Identity, KeyID};
    use dash_sdk::dpp::version::PlatformVersion;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// Same offline-`AppContext` recipe as `send_screen.rs`'s own `mod tests`
    /// — no network, no tokio runtime, just enough of `AppContext` for a
    /// screen to construct and render.
    fn offline_ctx() -> (Arc<AppContext>, tempfile::TempDir) {
        use crate::app_dir::ensure_env_file;

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let data_dir = temp_dir.path().to_path_buf();
        ensure_env_file(&data_dir);
        let db = Arc::new(create_database_at_path(&data_dir.join("data.db")).expect("db"));
        let app_kv = AppContext::open_app_kv(&data_dir).expect("app kv");
        let secret_store = AppContext::open_secret_store(&data_dir).expect("secret store");
        let ctx = AppContext::new(
            data_dir,
            Network::Testnet,
            db,
            Arc::new(TaskManager::new()),
            Arc::new(ConnectionStatus::new()),
            egui::Context::default(),
            app_kv,
            secret_store,
            crate::model::user_role::UserRoleCell::default(),
        )
        .expect("offline testnet AppContext::new");
        (ctx, temp_dir)
    }

    /// A `QualifiedIdentity` with one on-chain AUTHENTICATION key and a
    /// credit balance safely above both low-credit thresholds, so
    /// "Add Contact" isn't gated by `is_credit_balance_blocked`.
    fn build_identity(app_context: &Arc<AppContext>) -> QualifiedIdentity {
        let mut auth_key = IdentityPublicKey::random_key(1, Some(1), PlatformVersion::latest());
        auth_key.set_id(1);
        auth_key.set_purpose(Purpose::AUTHENTICATION);
        auth_key.set_security_level(SecurityLevel::CRITICAL);

        let public_keys: BTreeMap<KeyID, IdentityPublicKey> =
            [(auth_key.id(), auth_key)].into_iter().collect();
        let mut identity = Identity::new_with_id_and_keys(
            Identifier::random(),
            public_keys,
            PlatformVersion::latest(),
        )
        .expect("identity");
        identity.set_balance(1_000_000_000_000); // 10 DASH, well above both thresholds

        QualifiedIdentity {
            identity,
            associated_voter_identity: None,
            associated_operator_identity: None,
            associated_owner_key_id: None,
            identity_type: IdentityType::User,
            alias: None,
            private_keys: KeyStorage {
                private_keys: BTreeMap::new(),
            },
            dpns_names: vec![],
            associated_wallets: BTreeMap::new(),
            secret_access: None,
            wallet_index: None,
            top_ups: BTreeMap::new(),
            status: IdentityStatus::Active,
            network: app_context.network(),
        }
    }

    /// Builds an `OrchardPayScreen` with a resolved identity/key/wallet and
    /// one contactable search result — everything `render_add_contact`
    /// needs, without going through the full readiness-gated `ui()` (that
    /// gate isn't the subject of this test; see `render_add_contact`/
    /// `render_pending_confirmation` called directly in `mount_add_contact`).
    fn add_contact_screen() -> (OrchardPayScreen, tempfile::TempDir, Identifier) {
        let (app_context, temp_dir) = offline_ctx();
        let identity = build_identity(&app_context);

        let mut screen = OrchardPayScreen::new(&app_context, OrchardPaySubscreen::AddContact);
        screen.has_shielded_address = Some(true);
        screen.selected_key = Some(
            identity
                .identity
                .get_first_public_key_matching(
                    Purpose::AUTHENTICATION,
                    [SecurityLevel::CRITICAL].into(),
                    KeyType::all_key_types().into(),
                    false,
                )
                .cloned()
                .expect("auth key"),
        );
        screen.identity = Some(identity);

        let wallet = Wallet::new_from_seed(
            [1u8; 64],
            Network::Testnet,
            Some("Test wallet".to_string()),
            None,
        )
        .expect("wallet from seed");
        screen.selected_wallet = Some(Arc::new(RwLock::new(wallet)));

        let counterparty_id = Identifier::random();
        screen.search_results = vec![OrchardPayContactSearchResult {
            identity_id: counterparty_id,
            username: "alice.dash".to_string(),
            contactable: true,
            existing_relationship: None,
        }];

        (screen, temp_dir, counterparty_id)
    }

    /// Simulates a real click (press + release at the widget's center) in a
    /// single frame — needed for the *triggering* click that opens the
    /// confirmation, since `Harness::run()` hasn't settled a frame for
    /// `.click_accesskit()` to target yet. Mirrors `send_screen.rs`'s own
    /// `click_in_one_frame` helper.
    fn click_in_one_frame(harness: &mut Harness<'_, OrchardPayScreen>, label: &str) {
        let pos = harness.get_by_label(label).rect().center();
        harness.input_mut().events.extend([
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]);
        harness.step();
    }

    fn mount_add_contact(
        screen: OrchardPayScreen,
        captured_action: Rc<RefCell<AppAction>>,
    ) -> Harness<'static, OrchardPayScreen> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(700.0, 500.0))
            .build_ui_state(
                move |ui, screen: &mut OrchardPayScreen| {
                    let mut action = screen.render_add_contact(ui);
                    action |= screen.render_pending_confirmation(ui);
                    if !matches!(action, AppAction::None) {
                        *captured_action.borrow_mut() = action;
                    }
                },
                screen,
            );
        harness.run();
        harness
    }

    #[test]
    fn add_contact_click_opens_confirmation_without_dispatching() {
        let (screen, _temp_dir, _counterparty_id) = add_contact_screen();

        let observed_action = Rc::new(RefCell::new(AppAction::None));
        let mut harness = mount_add_contact(screen, observed_action.clone());

        click_in_one_frame(&mut harness, "Add Contact");

        assert!(
            matches!(*observed_action.borrow(), AppAction::None),
            "the original Add Contact click must not dispatch a backend task"
        );
        assert!(
            harness.query_by_label("Send Contact Request").is_some(),
            "confirmation modal must show the action's title"
        );

        harness.get_by_label("Confirm").click_accesskit();
        harness.step();

        assert!(
            harness.state().pending_confirmation.is_none(),
            "the confirmation dialog must close after confirmation"
        );
        assert!(
            matches!(*observed_action.borrow(), AppAction::BackendTask(_)),
            "confirming must dispatch the real backend task"
        );
    }

    #[test]
    fn add_contact_cancel_does_not_dispatch() {
        let (screen, _temp_dir, _counterparty_id) = add_contact_screen();

        let observed_action = Rc::new(RefCell::new(AppAction::None));
        let mut harness = mount_add_contact(screen, observed_action.clone());

        click_in_one_frame(&mut harness, "Add Contact");
        assert!(harness.query_by_label("Send Contact Request").is_some());

        harness.get_by_label("Cancel").click_accesskit();
        harness.step();

        assert!(
            harness.state().pending_confirmation.is_none(),
            "canceling must close the confirmation dialog"
        );
        assert!(
            matches!(*observed_action.borrow(), AppAction::None),
            "canceling must never dispatch a backend task"
        );
    }
}
