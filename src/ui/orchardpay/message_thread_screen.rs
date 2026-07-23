//! Per-contact `encryptedMessage` thread view + composer (Milestone E).
//! Shows the reconstructed two-way history with an established contact —
//! `Message`/`Payment`/`PaymentRequest` entries, chronological — and lets
//! the user send a new one. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
//! "Message content schema for the three in-scope kinds".

use crate::app::AppAction;
use crate::backend_task::identity::IdentityTask;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::encryption::MessageContent;
use crate::backend_task::orchardpay::messages::ThreadMessage;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::amount::Amount;
use crate::model::dpns::strip_dash_suffix;
use crate::model::fee_estimation::{
    format_credits_as_dash, format_credits_as_dash_significant, shielded_fee_for_actions,
};
use crate::model::orchardpay::{
    CREDIT_BLOCKED_TOOLTIP, OrchardPayContactState, is_credit_balance_blocked,
    is_credit_balance_low,
};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::amount_input::AmountInput;
use crate::ui::components::confirmation_dialog::{ConfirmationDialog, ConfirmationStatus};
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::subscreen_chooser_panel::{
    SubscreenNavItem, add_subscreen_chooser_panel,
};
use crate::ui::components::top_panel::add_top_panel_with_breadcrumb_and_label;
use crate::ui::components::wallet_unlock_popup::{
    WalletUnlockPopup, try_open_wallet_no_password, wallet_needs_unlock,
};
use crate::ui::components::{
    BannerHandle, Component, ComponentResponse, MessageBanner, OptionBannerExt,
};
use crate::ui::dashpay::format_relative_time;
use crate::ui::identities::get_selected_wallet;
use crate::ui::orchardpay::orchardpay_screen::OrchardPaySubscreen;
use crate::ui::theme::{DashColors, ResponseExt};
use crate::ui::{MessageType, RootScreenType, ScreenLike};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::{Identifier, IdentityPublicKey};
use egui::{RichText, Ui};
use std::sync::{Arc, RwLock};

/// Leading space before one of my own message bubbles, so incoming and
/// outgoing messages read as visually distinct columns.
const MY_MESSAGE_INDENT: f32 = 48.0;

/// Cap on a message bubble's width, so a short message doesn't stretch
/// into a nearly-empty row just to make room for the right-aligned
/// timestamp, and a long one wraps instead of running off the screen.
/// Clamped against the available width so it still fits a narrow window.
///
/// `egui::Sides` (the header row's name/timestamp layout) always extends
/// the timestamp out to whatever width it's given, regardless of how short
/// the actual message is — so this constant is also what determines how
/// far the timestamp sits from the name. Kept narrower than a chat bubble
/// might otherwise want for exactly that reason.
const MESSAGE_BUBBLE_MAX_WIDTH: f32 = 340.0;

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
    /// Amount for the Payment/Payment Request composer, entered in DASH
    /// (the widget converts to/from credits internally via
    /// `Amount::dash_from_credits`/`Amount::value`). `None` while empty or
    /// invalid.
    compose_amount: Option<Amount>,
    compose_amount_input: Option<AmountInput>,
    compose_memo: String,
    sending: bool,
    refresh_banner: Option<BannerHandle>,
    /// The active identity's own primary DPNS name, for the "You" message
    /// label. `None` falls back to "You" — shouldn't normally happen since
    /// OrchardPay requires a DPNS name to use at all.
    my_name: Option<String>,
    /// The counterparty's name, cached on the established contact state
    /// (`OrchardPayContactState::Established.name`) — the same name
    /// Contacts/Most Recent already show, read locally with no network
    /// call. `None` falls back to "Them" / the raw identity ID.
    counterparty_name: Option<String>,
    /// Set on construction and after a credit-spending action completes —
    /// drained by `ui()` into a `RefreshIdentity` dispatch. Identity credit
    /// balance has no live push like the shielded balance does, so this is
    /// what keeps the top-panel readout and the low-credit action gates
    /// reasonably current.
    pending_identity_refresh: bool,
    /// The one confirmation modal that can be up at a time — shared by the
    /// composer's Send (Message/Payment Request/Payment) and a bubble's
    /// direct Pay. Each trigger builds the real `AppAction` up front, then
    /// stashes it here instead of dispatching immediately; only
    /// `render_pending_confirmation`'s `Confirmed` arm actually returns it.
    pending_confirmation: Option<PendingConfirmation>,
}

/// A built `AppAction` sitting behind a confirmation dialog — the dialog
/// carries the user-facing "what is about to happen" description; the
/// action itself is only returned to the caller once the user confirms.
struct PendingConfirmation {
    dialog: ConfirmationDialog,
    action: Box<AppAction>,
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
        let my_name = identity
            .dpns_names
            .first()
            .map(|n| strip_dash_suffix(&n.name).to_string());
        let counterparty_name =
            Self::resolve_counterparty_name(app_context, &identity, counterparty_identity_id);

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
            compose_amount: None,
            compose_amount_input: None,
            compose_memo: String::new(),
            sending: false,
            refresh_banner: None,
            my_name,
            counterparty_name,
            pending_identity_refresh: true,
            pending_confirmation: None,
        }
    }

    /// Read the counterparty's name off the locally cached established
    /// contact state — local KV read, no network call. `None` if the
    /// relationship isn't `Established` (shouldn't happen for a screen only
    /// reachable via an established contact's "Open Conversation" button) or
    /// no name was ever resolved for it.
    fn resolve_counterparty_name(
        app_context: &Arc<AppContext>,
        identity: &QualifiedIdentity,
        counterparty_identity_id: Identifier,
    ) -> Option<String> {
        let backend = app_context.wallet_backend().ok()?;
        let state = backend
            .orchardpay_get_contact_state(&identity.identity.id(), &counterparty_identity_id)
            .ok()??;
        match state {
            OrchardPayContactState::Established { name, .. } => {
                name.map(|n| strip_dash_suffix(&n).to_string())
            }
            _ => None,
        }
    }

    fn seed_hash(&self) -> Option<crate::model::wallet::WalletSeedHash> {
        self.selected_wallet
            .as_ref()
            .and_then(|w| w.read().ok().map(|w| w.seed_hash()))
    }

    /// "Identity Balance: X DASH · Low Credits   Shielded Balance: Y DASH", rendered
    /// on the far right of the shared top panel. The credit half reads
    /// straight off `self.identity` (no live push exists for it, unlike
    /// shielded balance — see `pending_identity_refresh`). The shielded half
    /// is the balance a `Payment`/`PaymentRequest` composed here would draw
    /// from — reads `AppContext::shielded_balance_credits`, an in-memory
    /// snapshot the shielded sync event bridge keeps current, no network
    /// call or task dispatch needed. `None` only if no wallet is selected.
    fn balance_summary_label(&self) -> Option<String> {
        let seed_hash = self.seed_hash()?;
        let shielded = self.app_context.shielded_balance_credits(&seed_hash);
        let credits = self.identity.identity.balance();
        let mut label = format!(
            "Identity Balance: {}",
            format_credits_as_dash_significant(credits, 4)
        );
        if is_credit_balance_low(credits) {
            label.push_str("  ·  Low Credits");
        }
        label.push_str(&format!(
            "                        Shielded Balance: {}",
            format_credits_as_dash_significant(shielded, 4)
        ));
        Some(label)
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
        self.compose_amount = None;
        // Dropped rather than reset in place: a fresh widget starts with an
        // empty field (AmountInput::new's zero-amount special case),
        // matching the prior `String::clear()` behavior.
        self.compose_amount_input = None;
        self.compose_memo.clear();
    }

    /// The counterparty's display name for confirmation-modal copy — same
    /// fallback the conversation heading itself uses.
    fn counterparty_display_name(&self) -> String {
        self.counterparty_name
            .clone()
            .unwrap_or_else(|| self.counterparty_identity_id.to_string(Encoding::Base58))
    }

    /// Stash `action` behind a confirmation modal instead of dispatching it
    /// immediately — the misclick guard every OrchardPay action that reaches
    /// another party goes through. A no-op if `action` is `AppAction::None`
    /// (the trigger's own precondition already failed — nothing to confirm).
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
                self.sending = true;
                *pending.action
            }
            Some(ConfirmationStatus::Canceled) => {
                self.pending_confirmation = None;
                AppAction::None
            }
            None => AppAction::None,
        }
    }

    /// Builds the `SendPayment` action for fulfilling `document_id` (a
    /// specific incoming `PaymentRequest`'s own amount) and opens the
    /// confirmation modal directly — clicking "Pay" on a request bubble
    /// goes straight to a modal, it no longer routes through the composer
    /// at all.
    fn open_pay_confirmation(&mut self, document_id: Identifier, amount: u64) {
        let (Some(identity_key), Some(seed_hash)) = (self.selected_key.clone(), self.seed_hash())
        else {
            return;
        };
        let task = OrchardPayTask::SendPayment {
            qualified_identity: self.identity.clone(),
            identity_key,
            counterparty_identity_id: self.counterparty_identity_id,
            seed_hash,
            amount,
            memo: None,
            fulfilling_request_document_id: Some(document_id),
        };
        let name = self.counterparty_display_name();
        self.open_confirmation(
            "Pay Request?",
            format!(
                "Pay {} to {name} for this payment request?",
                format_credits_as_dash(amount)
            ),
            AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task))),
            true,
        );
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
        let name = self.counterparty_display_name();

        let (task, title, message, danger_mode) = match self.compose_kind {
            ComposeKind::Message => {
                let text = self.compose_text.trim().to_string();
                if text.is_empty() {
                    return AppAction::None;
                }
                let task = OrchardPayTask::SendMessage {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    text: text.clone(),
                    seed_hash,
                };
                (
                    task,
                    "Send Message?",
                    format!("Send this message to {name}?\n\n\"{text}\""),
                    false,
                )
            }
            ComposeKind::PaymentRequest => {
                let Some(amount) = self.compose_amount.as_ref().map(Amount::value) else {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "Enter an amount in DASH to request.",
                        MessageType::Error,
                    );
                    return AppAction::None;
                };
                let task = OrchardPayTask::SendPaymentRequest {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    amount,
                    memo,
                    seed_hash,
                };
                (
                    task,
                    "Send Payment Request?",
                    format!("Request {} from {name}?", format_credits_as_dash(amount)),
                    false,
                )
            }
            ComposeKind::Payment => {
                let Some(amount) = self.compose_amount.as_ref().map(Amount::value) else {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "Enter an amount in DASH to send.",
                        MessageType::Error,
                    );
                    return AppAction::None;
                };
                let task = OrchardPayTask::SendPayment {
                    qualified_identity: self.identity.clone(),
                    identity_key,
                    counterparty_identity_id: self.counterparty_identity_id,
                    seed_hash,
                    amount,
                    memo,
                    fulfilling_request_document_id: None,
                };
                (
                    task,
                    "Send Payment?",
                    format!("Send {} to {name}?", format_credits_as_dash(amount)),
                    true,
                )
            }
        };

        self.open_confirmation(
            title,
            message,
            AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task))),
            danger_mode,
        );
        AppAction::None
    }

    /// Renders one message bubble. Returns `Some((document_id, amount))`
    /// when the user clicked "Pay" on an incoming `PaymentRequest` bubble —
    /// the caller applies that to `self.open_pay_confirmation` outside this
    /// method, since a `ui.group` closure can't hold a `&mut self` borrow.
    fn render_message_bubble(
        &self,
        ui: &mut Ui,
        message: &ThreadMessage,
    ) -> Option<(Identifier, u64)> {
        let dark_mode = ui.style().visuals.dark_mode;
        let sender_label = if message.from_me {
            self.my_name.as_deref().unwrap_or("You")
        } else {
            self.counterparty_name.as_deref().unwrap_or("Them")
        };
        let mut reply_target = None;
        // Whether at least one shielded sync pass has completed this
        // session — `PaymentRequest`'s "paid" check reads the shielded
        // store directly (see `decode_thread_message`), so before this a
        // `None` verified_amount doesn't mean "not paid", just "haven't
        // finished checking yet". Gates both the requester's status label
        // and the payer's "Pay" button, so neither side acts on an
        // incomplete picture — see the payer-side note in `send_payment`'s
        // doc comment on why that matters for double-payment risk.
        let shielded_state_ready = self
            .app_context
            .connection_status()
            .last_shielded_sync_completed_at()
            .is_some();
        let credit_blocked = is_credit_balance_blocked(self.identity.identity.balance());

        ui.horizontal(|ui| {
            if message.from_me {
                // Approximates a 7-character indent at the default body
                // text size, so the back-and-forth is easier to follow at
                // a glance — my own messages read as a visually distinct
                // "column" from the counterparty's.
                ui.add_space(MY_MESSAGE_INDENT);
            }
            ui.group(|ui| {
                // Bounds the bubble's width so it shrink-wraps to its
                // content instead of stretching to fill the row just to
                // make room for the right-aligned timestamp below, and so
                // a long message wraps instead of running off the screen.
                ui.set_max_width(ui.available_width().min(MESSAGE_BUBBLE_MAX_WIDTH));
                // A `Frame`-based container (which `ui.group` is) inherits
                // its parent's layout direction when none is given — and
                // the surrounding indent wrapper above is a `horizontal`,
                // so without this the whole bubble (header row, body,
                // PAID label, buttons — everything) would flow left-to-
                // right instead of stacking, landing to the right of the
                // timestamp instead of below it.
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    egui::Sides::new().show(
                        ui,
                        |ui| {
                            ui.label(RichText::new(sender_label).strong());
                            if message.updated_at.is_some()
                                && message.updated_at != message.created_at
                            {
                                ui.label(
                                    RichText::new("(edited)")
                                        .color(DashColors::text_secondary(dark_mode)),
                                );
                            }
                        },
                        |ui| {
                            if let Some(timestamp) =
                                message.created_at.and_then(format_relative_time)
                            {
                                ui.label(
                                    RichText::new(timestamp)
                                        .size(11.0)
                                        .color(DashColors::text_secondary(dark_mode)),
                                );
                            }
                        },
                    );

                    match &message.content {
                        MessageContent::Message { data } => {
                            ui.label(data);
                        }
                        MessageContent::Payment { amount, memo } => {
                            let display_amount = message.verified_amount.unwrap_or(*amount);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "Payment: {}",
                                        format_credits_as_dash(display_amount)
                                    ))
                                    .strong(),
                                );
                            });
                            if let Some(memo) = memo {
                                ui.label(memo);
                            }
                            match message.verified_amount {
                                Some(verified) if verified == *amount => {
                                    ui.label(
                                        RichText::new(format!(
                                            "Verified — {}",
                                            format_credits_as_dash(verified)
                                        ))
                                        .strong()
                                        .color(DashColors::success_color(dark_mode)),
                                    );
                                }
                                Some(verified) => {
                                    ui.label(
                                        RichText::new(format!(
                                            "Verified — but the amount received was {} (message said {})",
                                            format_credits_as_dash(verified),
                                            format_credits_as_dash(*amount)
                                        ))
                                        .strong()
                                        .color(DashColors::warning_color(dark_mode)),
                                    );
                                }
                                None if !shielded_state_ready => {
                                    ui.label(
                                        RichText::new("Checking payment status…")
                                            .italics()
                                            .color(DashColors::text_secondary(dark_mode)),
                                    );
                                }
                                None => {
                                    ui.label(
                                        RichText::new("Awaiting Shielded Sync Completion")
                                            .italics()
                                            .color(DashColors::text_secondary(dark_mode)),
                                    );
                                }
                            }
                        }
                        MessageContent::PaymentRequest { amount, memo } => {
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "Payment Request: {}",
                                        format_credits_as_dash(*amount)
                                    ))
                                    .strong(),
                                );
                            });
                            if let Some(memo) = memo {
                                ui.label(memo);
                            }
                            match message.verified_amount {
                                Some(paid_amount) if paid_amount == *amount => {
                                    ui.label(
                                        RichText::new(format!(
                                            "PAID — {}",
                                            format_credits_as_dash(paid_amount)
                                        ))
                                        .strong()
                                        .color(DashColors::success_color(dark_mode)),
                                    );
                                }
                                Some(paid_amount) => {
                                    ui.label(
                                        RichText::new(format!(
                                            "PAID — but the amount received was {} (requested {})",
                                            format_credits_as_dash(paid_amount),
                                            format_credits_as_dash(*amount)
                                        ))
                                        .strong()
                                        .color(DashColors::warning_color(dark_mode)),
                                    );
                                }
                                None if !shielded_state_ready => {
                                    ui.label(
                                        RichText::new("Checking payment status…")
                                            .italics()
                                            .color(DashColors::text_secondary(dark_mode)),
                                    );
                                }
                                None if message.from_me => {
                                    ui.label(
                                        RichText::new("Awaiting payment")
                                            .italics()
                                            .color(DashColors::text_secondary(dark_mode)),
                                    );
                                }
                                None => {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .add_enabled(
                                                    !credit_blocked,
                                                    egui::Button::new("Pay"),
                                                )
                                                .disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
                                                .clicked()
                                            {
                                                reply_target =
                                                    Some((message.document_id, *amount));
                                            }
                                        },
                                    );
                                }
                            }
                        }
                    }
                });
            });
        });
        ui.add_space(6.0);
        reply_target
    }

    fn render_composer(&mut self, ui: &mut Ui) -> AppAction {
        let mut action = AppAction::None;
        ui.separator();
        ui.add_space(6.0);

        // Indented and width-capped the same as one of "my" message bubbles
        // (`MY_MESSAGE_INDENT`/`MESSAGE_BUBBLE_MAX_WIDTH`) — composing is
        // always "my" side of the conversation, so the whole block (kind
        // selector, input, Send button) lines up under that same column
        // instead of spreading across the full panel width.
        ui.horizontal(|ui| {
            ui.add_space(MY_MESSAGE_INDENT);
            ui.vertical(|ui| {
                ui.set_max_width(ui.available_width().min(MESSAGE_BUBBLE_MAX_WIDTH));

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
                        // Fills the capped column width above instead of
                        // egui's default fixed `text_edit_width` (280px) —
                        // otherwise the box would render narrower than the
                        // column the Send button below it aligns to.
                        ui.add(
                            egui::TextEdit::multiline(&mut self.compose_text)
                                .desired_width(f32::INFINITY),
                        );
                    }
                    ComposeKind::Payment | ComposeKind::PaymentRequest => {
                        // A `Payment` spends from the shielded balance, so cap
                        // the input at what's actually available after the
                        // shielded transfer's own fee — `PaymentRequest` isn't
                        // a spend (it's just an ask), so it carries no cap.
                        // The widget persists across `compose_kind` switches
                        // within one compose session, so this must run every
                        // frame rather than only at creation, or a cap set
                        // while composing a Payment would wrongly bleed into
                        // a PaymentRequest (or vice versa).
                        let available = (self.compose_kind == ComposeKind::Payment)
                            .then(|| self.seed_hash())
                            .flatten()
                            .map(|seed_hash| {
                                let balance = self.app_context.shielded_balance_credits(&seed_hash);
                                let fee = shielded_fee_for_actions(
                                    2,
                                    self.app_context.platform_version(),
                                )
                                .unwrap_or(0);
                                balance.saturating_sub(fee)
                            });

                        let widget = self.compose_amount_input.get_or_insert_with(|| {
                            AmountInput::new(Amount::new_dash(0.0)).with_label("Amount (DASH):")
                        });
                        match self.compose_kind {
                            ComposeKind::Payment => {
                                widget.set_max_amount(available);
                                widget.set_max_exceeded_hint(Some(
                                    "Insufficient Shielded Funds".to_string(),
                                ));
                            }
                            _ => {
                                widget.set_max_amount(None);
                                widget.set_max_exceeded_hint(None);
                            }
                        }
                        let response = widget.show(ui);
                        response.inner.update(&mut self.compose_amount);
                        ui.horizontal(|ui| {
                            ui.label("Note (optional):");
                            ui.text_edit_singleline(&mut self.compose_memo);
                        });
                    }
                }
                ui.add_space(6.0);

                let credit_blocked = is_credit_balance_blocked(self.identity.identity.balance());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.sending && !credit_blocked, egui::Button::new("Send"))
                        .disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
                        .clicked()
                    {
                        action |= self.send_clicked();
                    }
                });
            });
        });

        action
    }
}

impl ScreenLike for MessageThreadScreen {
    fn refresh(&mut self) {
        self.load_dispatched = false;
        // Re-read in case the name wasn't resolved yet when this screen was
        // constructed (e.g. opened right as the contact became established).
        self.counterparty_name = Self::resolve_counterparty_name(
            &self.app_context,
            &self.identity,
            self.counterparty_identity_id,
        );
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
                self.pending_identity_refresh = true;
            }
            BackendTaskSuccessResult::BroadcastedDocument(_) => {
                self.sending = false;
                self.clear_composer();
                self.pending_reload = true;
                self.pending_identity_refresh = true;
            }
            _ => {}
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        // "OrchardPay > wallet > my name", matching the rest of the app's
        // "root > wallet > name" breadcrumb shape instead of a static
        // "Conversation" label. The *other* party's name is deliberately
        // not repeated here — it's already shown in the "Conversation with
        // <name>" heading below; this breadcrumb's job is to say which of
        // my own identities is having this conversation.
        let wallet_name = self
            .selected_wallet
            .as_ref()
            .and_then(|w| w.read().ok())
            .map(|w| w.alias.clone().unwrap_or_else(|| "Wallet".to_string()))
            .unwrap_or_else(|| "Wallet".to_string());
        let my_label = self.my_name.clone().unwrap_or_else(|| {
            crate::model::address::truncate_address(
                &self.identity.identity.id().to_string(Encoding::Base58),
                8,
                6,
            )
        });
        let breadcrumbs = vec![
            (
                "OrchardPay",
                AppAction::SetMainScreenThenGoToMainScreen(RootScreenType::RootScreenOrchardPay),
            ),
            (wallet_name.as_str(), AppAction::None),
            (my_label.as_str(), AppAction::None),
        ];
        // A custom breadcrumb closure instead of add_top_panel_with_label:
        // that helper's shared add_location_view renders every segment at a
        // fixed 22pt (the app-wide convention for breadcrumb-style detail
        // screens), which reads as oversized next to the plain-default-size
        // page label the OrchardPay tab's own top panel uses. This mirrors
        // add_location_view's structure — clickable segments, "›" separator
        // — just without the font override, so it visually matches the tab
        // panel this screen otherwise mirrors (subscreen nav, etc.).
        let dark_mode = ui.style().visuals.dark_mode;
        let mut action = add_top_panel_with_breadcrumb_and_label(
            ui,
            &self.app_context,
            |ui| {
                let mut breadcrumb_action = AppAction::None;
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.horizontal(|ui| {
                        let len = breadcrumbs.len();
                        for (idx, (text, seg_action)) in breadcrumbs.into_iter().enumerate() {
                            if ui
                                .button(
                                    RichText::new(text).color(DashColors::text_primary(dark_mode)),
                                )
                                .clicked()
                            {
                                breadcrumb_action = seg_action;
                            }
                            if idx < len - 1 {
                                ui.label(
                                    RichText::new("›").color(DashColors::text_secondary(dark_mode)),
                                );
                            }
                        }
                    });
                });
                breadcrumb_action
            },
            vec![],
            self.balance_summary_label(),
        );
        action |= add_left_panel(ui, &self.app_context, RootScreenType::RootScreenOrchardPay);
        action |= self.render_pending_confirmation(ui);

        if self.pending_identity_refresh {
            self.pending_identity_refresh = false;
            action |= AppAction::BackendTask(BackendTask::IdentityTask(
                IdentityTask::RefreshIdentity(self.identity.clone()),
            ));
        }

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
                "Shielded TXs",
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

            let heading = match &self.counterparty_name {
                Some(name) => format!("Conversation with {name}"),
                None => format!(
                    "Conversation with {}",
                    self.counterparty_identity_id.to_string(Encoding::Base58)
                ),
            };
            ui.heading(RichText::new(heading));
            ui.add_space(8.0);

            if self.loading && self.messages.is_empty() {
                ui.label("Loading conversation…");
            }

            let mut reply_target: Option<(Identifier, u64)> = None;
            egui::ScrollArea::vertical()
                .max_height(ui.available_height() * 0.6)
                // Opens on the most recent messages (the bottom, since
                // `self.messages` is chronological oldest-first) and follows
                // new messages/payments/requests as they're appended —
                // unless the user has manually scrolled up to read history,
                // in which case egui's own stuck-to-end tracking backs off
                // and leaves them where they are.
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for message in self.messages.clone() {
                        if let Some(target) = self.render_message_bubble(ui, &message) {
                            reply_target = Some(target);
                        }
                    }
                });

            if let Some((document_id, amount)) = reply_target {
                self.open_pay_confirmation(document_id, amount);
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

#[cfg(test)]
mod tests {
    use super::*;
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

    /// A `QualifiedIdentity` with one on-chain AUTHENTICATION key (so
    /// `MessageThreadScreen::new` resolves a `selected_key`) and a credit
    /// balance safely above both low-credit thresholds, so the composer's
    /// Send button isn't gated by `is_credit_balance_blocked`.
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

    /// Builds a `MessageThreadScreen` ready to compose/send: a resolved
    /// identity/key (well above the credit thresholds) and a directly
    /// assigned test wallet — bypassing `get_selected_wallet`'s real
    /// identity-to-wallet resolution, which isn't the subject of this test.
    fn message_thread_screen() -> (MessageThreadScreen, tempfile::TempDir) {
        let (app_context, temp_dir) = offline_ctx();
        let identity = build_identity(&app_context);
        let mut screen = MessageThreadScreen::new(identity, Identifier::random(), &app_context);

        let wallet = Wallet::new_from_seed(
            [1u8; 64],
            Network::Testnet,
            Some("Test wallet".to_string()),
            None,
        )
        .expect("wallet from seed");
        screen.selected_wallet = Some(Arc::new(RwLock::new(wallet)));

        (screen, temp_dir)
    }

    /// Simulates a real click (press + release at the widget's center) in a
    /// single frame — needed for the *triggering* click that opens the
    /// confirmation, since `Harness::run()` hasn't settled a frame for
    /// `.click_accesskit()` to target yet. Mirrors `send_screen.rs`'s own
    /// `click_in_one_frame` helper.
    fn click_in_one_frame(harness: &mut Harness<'_, MessageThreadScreen>, label: &str) {
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

    fn mount_composer(
        screen: MessageThreadScreen,
        captured_action: Rc<RefCell<AppAction>>,
    ) -> Harness<'static, MessageThreadScreen> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(700.0, 500.0))
            .build_ui_state(
                move |ui, screen: &mut MessageThreadScreen| {
                    let mut action = screen.render_composer(ui);
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
    fn send_message_click_opens_confirmation_without_dispatching() {
        let (mut screen, _temp_dir) = message_thread_screen();
        screen.compose_text = "Hello there".to_string();

        let observed_action = Rc::new(RefCell::new(AppAction::None));
        let mut harness = mount_composer(screen, observed_action.clone());

        click_in_one_frame(&mut harness, "Send");

        assert!(
            matches!(*observed_action.borrow(), AppAction::None),
            "the original Send click must not dispatch a backend task"
        );
        assert!(
            harness.query_by_label("Send Message?").is_some(),
            "confirmation modal must show the action's title"
        );

        harness.get_by_label("Confirm").click_accesskit();
        harness.step();

        assert!(
            harness.state().pending_confirmation.is_none(),
            "the confirmation dialog must close after confirmation"
        );
        assert!(
            harness.state().sending,
            "confirming must mark the screen as sending"
        );
        assert!(
            matches!(*observed_action.borrow(), AppAction::BackendTask(_)),
            "confirming must dispatch the real backend task"
        );
    }

    #[test]
    fn send_message_cancel_does_not_dispatch() {
        let (mut screen, _temp_dir) = message_thread_screen();
        screen.compose_text = "Hello there".to_string();

        let observed_action = Rc::new(RefCell::new(AppAction::None));
        let mut harness = mount_composer(screen, observed_action.clone());

        click_in_one_frame(&mut harness, "Send");
        assert!(harness.query_by_label("Send Message?").is_some());

        harness.get_by_label("Cancel").click_accesskit();
        harness.step();

        assert!(
            harness.state().pending_confirmation.is_none(),
            "canceling must close the confirmation dialog"
        );
        assert!(
            !harness.state().sending,
            "canceling must never mark the screen as sending"
        );
        assert!(
            matches!(*observed_action.borrow(), AppAction::None),
            "canceling must never dispatch a backend task"
        );
    }
}
