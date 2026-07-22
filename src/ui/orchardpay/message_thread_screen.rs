//! Per-contact `encryptedMessage` thread view + composer (Milestone E).
//! Shows the reconstructed two-way history with an established contact —
//! `Message`/`Payment`/`PaymentRequest` entries, chronological — and lets
//! the user send a new one. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
//! "Message content schema for the three in-scope kinds".

use crate::app::AppAction;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::encryption::MessageContent;
use crate::backend_task::orchardpay::messages::ThreadMessage;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::fee_estimation::format_credits_as_dash;
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::subscreen_chooser_panel::{
    SubscreenNavItem, add_subscreen_chooser_panel,
};
use crate::ui::components::top_panel::add_top_panel_with_label;
use crate::ui::components::wallet_unlock_popup::{
    WalletUnlockPopup, try_open_wallet_no_password, wallet_needs_unlock,
};
use crate::ui::components::{BannerHandle, MessageBanner, OptionBannerExt};
use crate::ui::identities::get_selected_wallet;
use crate::ui::orchardpay::orchardpay_screen::OrchardPaySubscreen;
use crate::ui::theme::DashColors;
use crate::ui::{MessageType, RootScreenType, ScreenLike};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::{Identifier, IdentityPublicKey};
use egui::{RichText, Ui};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeKind {
    Message,
    Payment,
    PaymentRequest,
}

pub struct MessageThreadScreen {
    pub app_context: Arc<AppContext>,
    pub identity: QualifiedIdentity,
    pub counterparty_identity_id: Identifier,
    selected_key: Option<IdentityPublicKey>,
    selected_wallet: Option<Arc<RwLock<Wallet>>>,
    wallet_unlock_popup: WalletUnlockPopup,
    wallet_open_attempted: bool,
    messages: Vec<ThreadMessage>,
    load_dispatched: bool,
    loading: bool,
    pending_reload: bool,
    compose_kind: ComposeKind,
    compose_text: String,
    compose_amount: String,
    compose_memo: String,
    sending: bool,
    /// Set when the user clicked "Pay" on a specific incoming
    /// `PaymentRequest` bubble: (that document's own ID, its requested
    /// amount — used only to pre-fill the composer, not to lock it).
    fulfilling_request: Option<(Identifier, u64)>,
    refresh_banner: Option<BannerHandle>,
}

impl MessageThreadScreen {
    pub fn new(
        identity: QualifiedIdentity,
        counterparty_identity_id: Identifier,
        app_context: &Arc<AppContext>,
    ) -> Self {
        let selected_key = identity
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
            .cloned();
        let selected_wallet =
            get_selected_wallet(&identity, Some(app_context), None).unwrap_or(None);

        Self {
            app_context: app_context.clone(),
            identity,
            counterparty_identity_id,
            selected_key,
            selected_wallet,
            wallet_unlock_popup: WalletUnlockPopup::new(),
            wallet_open_attempted: false,
            messages: Vec::new(),
            load_dispatched: false,
            loading: false,
            pending_reload: false,
            compose_kind: ComposeKind::Message,
            compose_text: String::new(),
            compose_amount: String::new(),
            compose_memo: String::new(),
            sending: false,
            fulfilling_request: None,
            refresh_banner: None,
        }
    }

    fn seed_hash(&self) -> Option<crate::model::wallet::WalletSeedHash> {
        self.selected_wallet
            .as_ref()
            .and_then(|w| w.read().ok().map(|w| w.seed_hash()))
    }

    /// "Shielded balance: X DASH", rendered on the far right of the shared
    /// top panel — the balance a `Payment`/`PaymentRequest` composed here
    /// would draw from. Reads `AppContext::shielded_balance_credits`, an
    /// in-memory snapshot the shielded sync event bridge keeps current — no
    /// network call or task dispatch needed. `None` if no wallet is selected.
    fn shielded_balance_label(&self) -> Option<String> {
        let seed_hash = self.seed_hash()?;
        let balance = self.app_context.shielded_balance_credits(&seed_hash);
        Some(format!(
            "Shielded balance: {}",
            format_credits_as_dash(balance)
        ))
    }

    fn dispatch_load(&mut self) -> AppAction {
        let Some(seed_hash) = self.seed_hash() else {
            return AppAction::None;
        };
        self.loading = true;
        self.load_dispatched = true;
        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::LoadThread {
                qualified_identity: self.identity.clone(),
                counterparty_identity_id: self.counterparty_identity_id,
                seed_hash,
            },
        )))
    }

    fn clear_composer(&mut self) {
        self.compose_text.clear();
        self.compose_amount.clear();
        self.compose_memo.clear();
        self.fulfilling_request = None;
    }

    fn reply_to_request_clicked(&mut self, document_id: Identifier, amount: u64) {
        self.compose_kind = ComposeKind::Payment;
        self.fulfilling_request = Some((document_id, amount));
        self.compose_amount = amount.to_string();
    }

    fn send_clicked(&mut self) -> AppAction {
        let Some(identity_key) = self.selected_key.clone() else {
            return AppAction::None;
        };
        let Some(seed_hash) = self.seed_hash() else {
            return AppAction::None;
        };
        let memo = if self.compose_memo.trim().is_empty() {
            None
        } else {
            Some(self.compose_memo.trim().to_string())
        };

        let task = match self.compose_kind {
            ComposeKind::Message => {
                let text = self.compose_text.trim().to_string();
                if text.is_empty() {
                    return AppAction::None;
                }
                OrchardPayTask::SendMessage {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    text,
                    seed_hash,
                }
            }
            ComposeKind::PaymentRequest => {
                let Ok(amount) = self.compose_amount.trim().parse::<u64>() else {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "Enter a whole number of credits to request.",
                        MessageType::Error,
                    );
                    return AppAction::None;
                };
                OrchardPayTask::SendPaymentRequest {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    amount,
                    memo,
                    seed_hash,
                }
            }
            ComposeKind::Payment => {
                let Ok(amount) = self.compose_amount.trim().parse::<u64>() else {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "Enter a whole number of credits to send.",
                        MessageType::Error,
                    );
                    return AppAction::None;
                };
                OrchardPayTask::SendPayment {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    seed_hash,
                    amount,
                    memo,
                    fulfilling_request_document_id: self.fulfilling_request.map(|(id, _)| id),
                }
            }
        };

        self.sending = true;
        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task)))
    }

    /// Renders one message bubble. Returns `Some((document_id, amount))`
    /// when the user clicked "Pay" on an incoming `PaymentRequest` bubble —
    /// the caller applies that to `self.fulfilling_request` outside this
    /// method, since a `ui.group` closure can't hold a `&mut self` borrow.
    fn render_message_bubble(
        &self,
        ui: &mut Ui,
        message: &ThreadMessage,
    ) -> Option<(Identifier, u64)> {
        let dark_mode = ui.style().visuals.dark_mode;
        let sender_label = if message.from_me { "You" } else { "Them" };
        let mut reply_target = None;

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(sender_label).strong());
                if message.updated_at.is_some() && message.updated_at != message.created_at {
                    ui.label(
                        RichText::new("(edited)").color(DashColors::text_secondary(dark_mode)),
                    );
                }
            });

            match &message.content {
                MessageContent::Message { data } => {
                    ui.label(data);
                }
                MessageContent::Payment { amount, memo } => {
                    let display_amount = message.verified_amount.unwrap_or(*amount);
                    ui.label(
                        RichText::new(format!("Payment: {display_amount} credits")).strong(),
                    );
                    if let Some(verified) = message.verified_amount
                        && verified != *amount
                    {
                        ui.label(
                            RichText::new(format!(
                                "This message claims {amount} credits, but the actual transfer was {verified}."
                            ))
                            .color(DashColors::warning_color(dark_mode)),
                        );
                    }
                    if let Some(memo) = memo {
                        ui.label(memo);
                    }
                }
                MessageContent::PaymentRequest { amount, memo } => {
                    ui.label(RichText::new(format!("Payment request: {amount} credits")).strong());
                    if let Some(memo) = memo {
                        ui.label(memo);
                    }
                    if !message.from_me && ui.button("Pay").clicked() {
                        reply_target = Some((message.document_id, *amount));
                    }
                }
            }
        });
        ui.add_space(6.0);
        reply_target
    }

    fn render_composer(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        ui.separator();
        ui.add_space(6.0);

        if let Some((_, requested_amount)) = self.fulfilling_request {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Replying to a request for {requested_amount} credits."
                ));
                if ui.button("Cancel").clicked() {
                    self.fulfilling_request = None;
                    self.compose_amount.clear();
                }
            });
        }

        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.compose_kind, ComposeKind::Message, "Message");
            ui.selectable_value(&mut self.compose_kind, ComposeKind::Payment, "Payment");
            ui.selectable_value(
                &mut self.compose_kind,
                ComposeKind::PaymentRequest,
                "Payment Request",
            );
        });
        ui.add_space(4.0);

        match self.compose_kind {
            ComposeKind::Message => {
                ui.text_edit_multiline(&mut self.compose_text);
            }
            ComposeKind::Payment | ComposeKind::PaymentRequest => {
                ui.horizontal(|ui| {
                    ui.label("Amount (credits):");
                    ui.text_edit_singleline(&mut self.compose_amount);
                });
                ui.horizontal(|ui| {
                    ui.label("Note (optional):");
                    ui.text_edit_singleline(&mut self.compose_memo);
                });
            }
        }
        ui.add_space(6.0);

        if ui
            .add_enabled(!self.sending, egui::Button::new("Send"))
            .clicked()
        {
            action |= self.send_clicked();
        }

        action
    }
}

impl ScreenLike for MessageThreadScreen {
    fn refresh(&mut self) {
        self.load_dispatched = false;
    }

    fn display_message(&mut self, message: &str, message_type: MessageType) {
        let _ = message;
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.sending = false;
            self.loading = false;
            self.refresh_banner.take_and_clear();
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        match result {
            BackendTaskSuccessResult::OrchardPayThreadLoaded {
                counterparty_identity_id,
                messages,
            } if counterparty_identity_id == self.counterparty_identity_id => {
                self.messages = messages;
                self.loading = false;
            }
            BackendTaskSuccessResult::OrchardPayPaymentSent { .. } => {
                self.sending = false;
                self.clear_composer();
                self.pending_reload = true;
            }
            BackendTaskSuccessResult::BroadcastedDocument(_) => {
                self.sending = false;
                self.clear_composer();
                self.pending_reload = true;
            }
            _ => {}
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let breadcrumbs = vec![
            (
                "OrchardPay",
                AppAction::SetMainScreenThenGoToMainScreen(RootScreenType::RootScreenOrchardPay),
            ),
            ("Conversation", AppAction::None),
        ];
        let mut action = add_top_panel_with_label(
            ui,
            &self.app_context,
            breadcrumbs,
            vec![],
            self.shielded_balance_label(),
        );
        action |= add_left_panel(ui, &self.app_context, RootScreenType::RootScreenOrchardPay);

        // Mirrors orchardpay_screen.rs's own subscreen nav so it stays
        // visible while viewing a conversation instead of disappearing.
        // Each item dispatches NavigateToOrchardPaySubscreen directly
        // (rather than orchardpay_screen.rs's Custom-tag-then-match
        // pattern) since this screen doesn't own the OrchardPayScreen
        // instance to mutate locally — the central app.rs dispatcher does
        // it instead. None marked active: this screen doesn't track which
        // tab the conversation was opened from.
        let subscreen_items = vec![
            SubscreenNavItem::new(
                "My Profile",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Profile),
            ),
            SubscreenNavItem::new(
                "Contacts",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Contacts),
            ),
            SubscreenNavItem::new(
                "Most Recent",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::MostRecent),
            ),
            SubscreenNavItem::new(
                "Payments",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Payments),
            ),
            SubscreenNavItem::new(
                "Send Friend Request",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::AddContact),
            ),
            SubscreenNavItem::new(
                "About",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::About),
            ),
            SubscreenNavItem::new(
                "QC Warning",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::QcWarning),
            ),
        ];
        action |= add_subscreen_chooser_panel(
            ui,
            "orchardpay_subscreen_chooser",
            false,
            false,
            subscreen_items,
        );

        if !self.load_dispatched {
            action |= self.dispatch_load();
        } else if self.pending_reload {
            self.pending_reload = false;
            action |= self.dispatch_load();
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

            ui.heading(RichText::new(
                self.counterparty_identity_id.to_string(Encoding::Base58),
            ));
            ui.add_space(8.0);

            if self.loading && self.messages.is_empty() {
                ui.label("Loading conversation…");
            }

            let mut reply_target: Option<(Identifier, u64)> = None;
            egui::ScrollArea::vertical()
                .max_height(ui.available_height() * 0.6)
                .show(ui, |ui| {
                    for message in self.messages.clone() {
                        if let Some(target) = self.render_message_bubble(ui, &message) {
                            reply_target = Some(target);
                        }
                    }
                });

            if let Some((document_id, amount)) = reply_target {
                self.reply_to_request_clicked(document_id, amount);
            }

            inner_action |= self.render_composer(ui);
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
