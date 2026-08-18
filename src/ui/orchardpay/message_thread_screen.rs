//! Per-contact `encryptedMessage` thread view + composer (Milestone E).
//! Shows the reconstructed two-way history with an established contact —
//! `Message`/`Payment`/`PaymentRequest` entries, chronological — and lets
//! the user send a new one. See `docs/orchardpay/PROTOCOL_DESIGN.md`'s
//! "Message content schema for the three in-scope kinds".

use crate::app::AppAction;
use crate::backend_task::identity::IdentityTask;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::orchardpay::encryption::MessageContent;
use crate::backend_task::orchardpay::messages::{
    HistoryCursor, ReceiptAlert, ReceiptAlertReason, ThreadMessage,
};
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::amount::Amount;
use crate::model::dpns::strip_dash_suffix;
use crate::model::fee_estimation::{
    format_credits_as_dash, format_credits_as_dash_significant, shielded_fee_for_actions,
};
use crate::model::orchardpay::{
    CREDIT_BLOCKED_TOOLTIP, MAX_MESSAGE_CHARS, MAX_PAYMENT_MEMO_CHARS, MIN_SEND_AMOUNT_CREDITS,
    OrchardPayContactState, SilentPaymentRecord, is_credit_balance_blocked, is_credit_balance_low,
    validate_message_text, validate_payment_memo,
};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::validation::strip_unsafe_display_characters_allow_newlines;
use crate::model::wallet::Wallet;
use crate::ui::components::amount_input::AmountInput;
use crate::ui::components::confirmation_dialog::{ConfirmationDialog, ConfirmationStatus};
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::subscreen_chooser_panel::{
    SubscreenNavItem, add_subscreen_chooser_panel,
};
use crate::ui::components::text_edit_dialog::{TextEditDialog, TextEditStatus};
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
use crate::ui::theme::{DashColors, ResponseExt, Shape};
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

/// Fixed width of the "Recent Payments" side table, so it reads as a
/// consistent column regardless of how wide its own content is.
const RECENT_PAYMENTS_PANEL_WIDTH: f32 = 500.0;

/// Cap on how many rows the "Recent Payments" side table shows.
const RECENT_PAYMENTS_MAX_ROWS: usize = 6;

/// Fixed width of the "Sent/Received" column in the "Recent Payments" table.
const RECENT_PAYMENTS_COL1_WIDTH: f32 = 110.0;

/// Fixed width of the "Amount (DASH)" column in the "Recent Payments" table.
const RECENT_PAYMENTS_COL2_WIDTH: f32 = 150.0;

/// Row height (header and data rows alike) in the "Recent Payments" table.
const RECENT_PAYMENTS_ROW_HEIGHT: f32 = 22.0;

/// Gap between the conversation column and the "Recent Payments" column —
/// plain spacing, deliberately not a `ui.separator()` line.
const RECENT_PAYMENTS_COLUMN_GAP: f32 = 24.0;

/// Progress-verb labels shown on a bubble's own button while its action is
/// the one in flight (`pending_bubble_action_label`) — shared constants
/// between the "set" call sites and `render_message_bubble`'s "is this the
/// action that's busy" comparison, so the two can't drift out of sync.
const LABEL_PAYING: &str = "Paying…";
const LABEL_DELETING: &str = "Deleting…";
const LABEL_CANCELLING: &str = "Cancelling…";
const LABEL_SAVING: &str = "Saving…";
const LABEL_SENDING: &str = "Sending…";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeKind {
    Message,
    Payment,
    PaymentRequest,
}

/// One row of the "Recent Payments" side table — a verified real-money
/// movement between the two parties. See
/// [`MessageThreadScreen::recent_verified_payments`].
struct PaymentRow {
    /// `true` if the thread owner received this payment, `false` if they
    /// sent it.
    received: bool,
    credits: u64,
    created_at: Option<u64>,
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
    /// Every locally-resolved `OPP2` silent payment with this counterparty
    /// — never document-backed, so it's merged into the same rendered
    /// timeline as `messages` (by timestamp) at render time, the same way
    /// `receipt_alerts` already is, rather than living inside `messages`
    /// itself. See `messages::LoadedThread::silent_payments`.
    silent_payments: Vec<SilentPaymentRecord>,
    /// Saved `PaymentRequestReceipt`s whose original `PaymentRequest` no
    /// longer matches them — see `messages::load_thread`'s anomaly-
    /// detection pass. Rendered as warning panels, never as bubbles.
    receipt_alerts: Vec<ReceiptAlert>,
    /// Every decoded document held so far (both sides, receipts included) —
    /// not rendered, just carried along and handed back into
    /// `OrchardPayTask::LoadMoreHistory` so the backend can merge in the
    /// next page and re-run receipt-anomaly detection over the complete
    /// accumulated set. See `messages::LoadedThread::all_decoded`.
    all_decoded_thread: Vec<ThreadMessage>,
    /// Whether more history exists beyond `messages`, per side — drives the
    /// "See more conversation history" button. Reset to whatever the latest
    /// `OrchardPayThreadLoaded` result reports, whether that came from a
    /// full reload or a "load more" fetch.
    history_cursor: HistoryCursor,
    /// Whether some documents may not have made it into `all_decoded_thread`
    /// — see `messages::LoadedThread::may_be_incomplete`. Sticky across
    /// "load more" fetches like `history_cursor`; surfaced as a notice at
    /// the top of the thread rather than silently dropped.
    may_be_incomplete: bool,
    /// An `OrchardPayTask::LoadMoreHistory` fetch is in flight — distinct
    /// from `loading` (which gates the initial "Loading conversation…"
    /// state) so the already-loaded thread stays visible while more history
    /// loads above it.
    loading_more: bool,
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
    /// "Send without a message" — only meaningful for `ComposeKind::Payment`.
    /// When checked, `send_clicked` dispatches `SendSilentPayment` (no
    /// document, no message) instead of `SendPayment`; the memo field is
    /// hidden while checked, since a silent payment carries no message at
    /// all. See `silent_payment::send_silent_payment`.
    compose_send_silently: bool,
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
    /// composer's Send (Message/Payment Request/Payment), a bubble's direct
    /// Pay, and a bubble's Cancel Request. Each trigger builds the real
    /// `AppAction` up front, then stashes it here instead of dispatching
    /// immediately; only `render_pending_confirmation`'s `Confirmed` arm
    /// actually returns it.
    pending_confirmation: Option<PendingConfirmation>,
    /// The one edit-in-progress modal, if any — ORP-010's Message/Payment-
    /// memo edit flow. Unlike `pending_confirmation`, saving from here
    /// dispatches directly (no second confirmation), per the design
    /// decision that the modal's own Save button is the confirmation.
    editing: Option<EditingState>,
    /// The document ID of an in-flight `SendPayment`/`EditMessage`/
    /// `EditPaymentMemo`/`CancelPaymentRequest`/`DeleteMessage` task, set
    /// right before dispatch — lets `display_task_result`'s
    /// `ReplacedDocument`/`DeletedDocument` arms confirm a result belongs to
    /// this screen's own dispatch rather than an unrelated document
    /// mutation elsewhere in the app, and lets `render_message_bubble`
    /// identify which bubble's own button to relabel with a progress verb.
    pending_document_mutation_id: Option<Identifier>,
    /// The progress-verb label (one of the `LABEL_*` constants) for
    /// whichever action `pending_document_mutation_id` refers to — set
    /// alongside it at every call site. Only meaningful together with
    /// `pending_document_mutation_id`; disambiguates Delete vs. Edit
    /// Message, which otherwise target the same document ID and would
    /// relabel identically.
    pending_bubble_action_label: Option<&'static str>,
    /// Set right before dispatching a composer send (Message/Payment
    /// Request/direct Payment) — lets `display_task_result`'s
    /// `BroadcastedDocument` arm confirm a broadcast result actually belongs
    /// to *this* screen's own composer dispatch. `BroadcastedDocument` is a
    /// generic, app-wide result type shared by several screens, so without
    /// this an unrelated broadcast landing while this thread happens to be
    /// open would incorrectly clear `sending` and re-enable this thread's
    /// buttons while its own action (if any) is still genuinely in flight.
    composer_send_pending: bool,
}

/// A pending action sitting behind a confirmation dialog — the dialog
/// carries the user-facing "what is about to happen" description; the
/// action itself is only built once the user confirms, from the dialog's
/// final state (in particular its checkbox, for the Pay flow's "Save
/// Receipt" — the only current user of that). `open_confirmation`'s static
/// callers just ignore the `bool` argument.
struct PendingConfirmation {
    dialog: ConfirmationDialog,
    action: Box<dyn FnOnce(bool) -> AppAction>,
}

/// One bubble-triggered signal, returned by `render_message_bubble` since a
/// `ui.group` closure can't hold a `&mut self` borrow — the caller in
/// `ui()` applies the actual state change/dispatch outside the closure.
enum BubbleAction {
    /// Pay this incoming `PaymentRequest`.
    Pay {
        document_id: Identifier,
        amount: u64,
        memo: Option<String>,
        created_at: Option<u64>,
    },
    /// Open the edit modal for a `Message` I sent.
    EditMessage {
        document_id: Identifier,
        current_text: String,
    },
    /// Open the edit modal for a `Payment` I sent (memo only).
    EditPaymentMemo {
        document_id: Identifier,
        current_memo: Option<String>,
    },
    /// Cancel a `PaymentRequest` I created.
    CancelPaymentRequest { document_id: Identifier },
    /// Delete a `Message` I sent.
    DeleteMessage { document_id: Identifier },
}

/// The one edit-in-progress modal's state — which document, and the dialog
/// widget itself (already carries the text being edited).
enum EditingState {
    Message {
        document_id: Identifier,
        dialog: TextEditDialog,
    },
    PaymentMemo {
        document_id: Identifier,
        dialog: TextEditDialog,
    },
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
            silent_payments: Vec::new(),
            receipt_alerts: Vec::new(),
            all_decoded_thread: Vec::new(),
            history_cursor: HistoryCursor::default(),
            may_be_incomplete: false,
            loading_more: false,
            load_dispatched: false,
            loading: false,
            pending_reload: false,
            compose_kind: ComposeKind::Message,
            compose_text: String::new(),
            compose_amount: None,
            compose_amount_input: None,
            compose_memo: String::new(),
            compose_send_silently: false,
            sending: false,
            refresh_banner: None,
            my_name,
            counterparty_name,
            pending_identity_refresh: true,
            pending_confirmation: None,
            editing: None,
            pending_document_mutation_id: None,
            pending_bubble_action_label: None,
            composer_send_pending: false,
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
        let contract_id = app_context.orchardpay_contract_id()?;
        let state = backend
            .orchardpay_get_contact_state(
                &contract_id,
                &identity.identity.id(),
                &counterparty_identity_id,
            )
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
        // See the sibling `balance_summary_label` in `orchardpay_screen.rs`
        // for why this checks staleness rather than always formatting the
        // cached amount.
        let shielded_label = if self
            .app_context
            .connection_status()
            .shielded_balance_possibly_stale()
        {
            "Still Syncing…".to_string()
        } else {
            format_credits_as_dash_significant(shielded, 4)
        };
        label.push_str(&format!(
            "                        Shielded Balance: {shielded_label}"
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

    /// Dispatched by the "See more conversation history" button — fetches
    /// the next older page for whichever side(s) `self.history_cursor`
    /// reports more available on, merged with everything already held in
    /// `self.all_decoded_thread`.
    fn dispatch_load_more(&mut self) -> AppAction {
        let Some(seed_hash) = self.seed_hash() else {
            return AppAction::None;
        };
        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::LoadMoreHistory {
                qualified_identity: self.identity.clone(),
                counterparty_identity_id: self.counterparty_identity_id,
                seed_hash,
                all_decoded: self.all_decoded_thread.clone(),
                history_cursor: self.history_cursor,
                may_be_incomplete: self.may_be_incomplete,
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
        self.compose_send_silently = false;
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
            action: Box::new(move |_checkbox_state| action),
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
                let checkbox_state = pending.dialog.checkbox_checked();
                self.sending = true;
                (pending.action)(checkbox_state)
            }
            Some(ConfirmationStatus::Canceled) => {
                self.pending_confirmation = None;
                // Set ahead of this same dialog by whichever opener needed
                // it (Pay, Cancel Request, Delete Message) — clear it so a
                // canceled confirmation doesn't leave a stale guard value
                // waiting for a result that will never arrive.
                self.pending_document_mutation_id = None;
                self.pending_bubble_action_label = None;
                AppAction::None
            }
            None => AppAction::None,
        }
    }

    /// Builds the `SendPayment` action for fulfilling `document_id` (a
    /// specific incoming `PaymentRequest`'s own amount/memo/created_at) and
    /// opens the confirmation modal directly — clicking "Pay" on a request
    /// bubble goes straight to a modal, it no longer routes through the
    /// composer at all. Includes a "Save Receipt" checkbox (unchecked by
    /// default); since `save_receipt` is only known once the user confirms,
    /// the `SendPayment` task is built lazily from the dialog's final
    /// checkbox state rather than up front.
    fn open_pay_confirmation(
        &mut self,
        document_id: Identifier,
        amount: u64,
        memo: Option<String>,
        created_at: Option<u64>,
    ) {
        let (Some(identity_key), Some(seed_hash)) = (self.selected_key.clone(), self.seed_hash())
        else {
            return;
        };
        let qualified_identity = self.identity.clone();
        let counterparty_identity_id = self.counterparty_identity_id;
        let name = self.counterparty_display_name();
        let message = format!(
            "Pay {} to {name} for this payment request?",
            format_credits_as_dash(amount)
        );

        self.pending_document_mutation_id = Some(document_id);
        self.pending_bubble_action_label = Some(LABEL_PAYING);
        self.pending_confirmation = Some(PendingConfirmation {
            dialog: ConfirmationDialog::new("Pay Request?", message)
                .danger_mode(true)
                .blocks_input(true)
                .with_checkbox("Save Receipt", false),
            action: Box::new(move |save_receipt| {
                let task = OrchardPayTask::SendPayment {
                    qualified_identity,
                    identity_key,
                    counterparty_identity_id,
                    seed_hash,
                    amount,
                    memo: None,
                    fulfilling_request_document_id: Some(document_id),
                    save_receipt,
                    original_request_memo: memo,
                    original_request_created_at: created_at,
                };
                AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task)))
            }),
        });
    }

    /// Builds the `CancelPaymentRequest` action for `document_id` and opens
    /// the confirmation modal — the user explicitly asked for a confirming
    /// modal before a request I created is cancelled.
    fn open_cancel_request_confirmation(&mut self, document_id: Identifier) {
        let (Some(identity_key), Some(seed_hash)) = (self.selected_key.clone(), self.seed_hash())
        else {
            return;
        };
        let task = OrchardPayTask::CancelPaymentRequest {
            qualified_identity: self.identity.clone(),
            identity_key,
            counterparty_identity_id: self.counterparty_identity_id,
            document_id,
            seed_hash,
        };
        self.pending_document_mutation_id = Some(document_id);
        self.pending_bubble_action_label = Some(LABEL_CANCELLING);
        self.open_confirmation(
            "Cancel Request?",
            "The other party will no longer be able to pay this request.".to_string(),
            AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task))),
            true,
        );
    }

    /// Builds the `DeleteMessage` action for `document_id` and opens the
    /// confirmation modal — a true delete (see `messages::delete_message`),
    /// so this is a danger-mode confirmation like Cancel Request.
    fn open_delete_message_confirmation(&mut self, document_id: Identifier) {
        let (Some(identity_key), Some(seed_hash)) = (self.selected_key.clone(), self.seed_hash())
        else {
            return;
        };
        let task = OrchardPayTask::DeleteMessage {
            qualified_identity: self.identity.clone(),
            identity_key,
            counterparty_identity_id: self.counterparty_identity_id,
            document_id,
            seed_hash,
        };
        self.pending_document_mutation_id = Some(document_id);
        self.pending_bubble_action_label = Some(LABEL_DELETING);
        self.open_confirmation(
            "Delete Message?",
            "This message will be permanently removed from the conversation for both of you."
                .to_string(),
            AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task))),
            true,
        );
    }

    /// Drives the one edit-in-progress modal, if any — the counterpart to
    /// `render_pending_confirmation`, but saving here dispatches directly:
    /// no second confirmation, since the modal's own Save button already is
    /// one (per the design decision this differs from `pending_confirmation`).
    fn render_editing_modal(&mut self, ui: &mut Ui) -> AppAction {
        let Some(editing) = self.editing.as_mut() else {
            return AppAction::None;
        };
        let (document_id, dialog, is_message) = match editing {
            EditingState::Message {
                document_id,
                dialog,
            } => (*document_id, dialog, true),
            EditingState::PaymentMemo {
                document_id,
                dialog,
            } => (*document_id, dialog, false),
        };
        let Some(status) = dialog.show(ui).inner.dialog_response else {
            return AppAction::None;
        };

        let text = match status {
            TextEditStatus::Canceled => {
                self.editing = None;
                return AppAction::None;
            }
            TextEditStatus::Saved(text) => text,
        };

        let (Some(identity_key), Some(seed_hash)) = (self.selected_key.clone(), self.seed_hash())
        else {
            self.editing = None;
            return AppAction::None;
        };
        let task = if is_message {
            OrchardPayTask::EditMessage {
                qualified_identity: self.identity.clone(),
                identity_key,
                counterparty_identity_id: self.counterparty_identity_id,
                document_id,
                new_text: text,
                seed_hash,
            }
        } else {
            OrchardPayTask::EditPaymentMemo {
                qualified_identity: self.identity.clone(),
                identity_key,
                counterparty_identity_id: self.counterparty_identity_id,
                document_id,
                new_memo: (!text.is_empty()).then_some(text),
                seed_hash,
            }
        };

        self.editing = None;
        self.sending = true;
        self.pending_document_mutation_id = Some(document_id);
        self.pending_bubble_action_label = Some(LABEL_SAVING);
        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task)))
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
                if let Err(error) = validate_message_text(&text) {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "The message is too long. Use 1000 characters or fewer and try again.",
                        MessageType::Error,
                    )
                    .with_details(error);
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
                if let Some(error) = memo.as_deref().and_then(|m| validate_payment_memo(m).err()) {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "The payment memo is too long. Use 1000 characters or fewer and try again.",
                        MessageType::Error,
                    )
                    .with_details(error);
                    return AppAction::None;
                }
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
            ComposeKind::Payment if self.compose_send_silently => {
                let Some(amount) = self.compose_amount.as_ref().map(Amount::value) else {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "Enter an amount in DASH to send.",
                        MessageType::Error,
                    );
                    return AppAction::None;
                };
                let task = OrchardPayTask::SendSilentPayment {
                    qualified_identity: self.identity.clone(),
                    counterparty_identity_id: self.counterparty_identity_id,
                    seed_hash,
                    amount,
                };
                (
                    task,
                    "Send Payment?",
                    format!(
                        "Send {} to {name} without a message? This won't create a document, \
                         only a private transfer.",
                        format_credits_as_dash(amount)
                    ),
                    true,
                )
            }
            ComposeKind::Payment => {
                if let Some(error) = memo.as_deref().and_then(|m| validate_payment_memo(m).err()) {
                    MessageBanner::set_global(
                        self.app_context.egui_ctx(),
                        "The payment memo is too long. Use 1000 characters or fewer and try again.",
                        MessageType::Error,
                    )
                    .with_details(error);
                    return AppAction::None;
                }
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
                    save_receipt: false,
                    original_request_memo: None,
                    original_request_created_at: None,
                };
                (
                    task,
                    "Send Payment?",
                    format!("Send {} to {name}?", format_credits_as_dash(amount)),
                    true,
                )
            }
        };

        self.composer_send_pending = true;
        self.open_confirmation(
            title,
            message,
            AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(task))),
            danger_mode,
        );
        AppAction::None
    }

    /// Renders one message bubble. Returns `Some(BubbleAction)` when the
    /// user clicked something that needs `&mut self` — Pay, Cancel Request,
    /// an Edit/Delete/Add Memo entry in a message's right-click menu — since
    /// a `ui.group` closure can't hold a `&mut self` borrow. The caller in
    /// `ui()` applies the actual state change/dispatch outside the closure.
    /// Message/memo text is deliberately a plain, non-interactive label —
    /// left-click affordances that reveal new buttons right under the
    /// cursor invite mis-clicks, and previously masked a real bug where an
    /// unrelated document broadcast could clear this screen's busy-action
    /// guard early (see `composer_send_pending`'s doc comment). Edit/Delete
    /// live behind a right-click context menu instead.
    fn render_message_bubble(&self, ui: &mut Ui, message: &ThreadMessage) -> Option<BubbleAction> {
        let dark_mode = ui.style().visuals.dark_mode;
        let sender_label = if message.from_me {
            self.my_name.as_deref().unwrap_or("You")
        } else {
            self.counterparty_name.as_deref().unwrap_or("Them")
        };
        let mut bubble_action: Option<BubbleAction> = None;
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
        // Whether *this* bubble's own action is the one currently in
        // flight — used to relabel just its button to a progress verb.
        // Every other button in the thread stays disabled (via `sending`
        // below) with its original wording, since we don't know which
        // action they'd be restating.
        let busy_here = self.pending_document_mutation_id == Some(message.document_id);
        // Conversation-wide, deliberately: `sending` is one flag for the
        // whole thread, not per-message, so any one action in flight
        // (including sending a new message from the composer) disables
        // every mutating button here until it resolves. Also folds in
        // `loading`/`loading_more` so a manual refresh or "load more" keeps
        // these mutually exclusive with every other conversation action too.
        let action_disabled = self.sending || self.loading || self.loading_more;

        // A `Message`'s text is entirely attacker-controlled — nothing
        // stops someone from typing "Payment: 50 DASH" as plain text to
        // impersonate a real bubble. Text styling (bold, underline) isn't a
        // safe defense against that: Unicode combining characters (e.g.
        // U+0332 COMBINING LOW LINE) can fake an underline within ordinary
        // string content. The bubble's own container fill/border, by
        // contrast, is chrome this rendering code controls directly and no
        // message content can ever reach — so only `Payment`/`PaymentRequest`
        // ever get this tinted frame, and a plain `Message` always keeps the
        // neutral look. `PaymentRequest` gets it unconditionally (it never
        // claims funds moved, so there's nothing to mislabel). An unverified
        // `Payment` (`verified_amount: None`) deliberately keeps the neutral
        // `Message` look instead — a rogue contact's bare claim that money
        // moved shouldn't get the same trusted chrome as a real one; see the
        // 2026-07-27 adversarial audit's finding 1. `verified_amount` is
        // computed server-side from this wallet's own shielded-note lookup,
        // never from message content, so this can't be spoofed the same way.
        //
        // The tint color itself encodes which way Dash is moving relative to
        // the wallet owner: blue for outgoing (I sent a `Payment`, or the
        // counterparty sent a `PaymentRequest` asking me to pay them), green
        // for incoming (I received a `Payment`, or I sent a `PaymentRequest`
        // asking the counterparty to pay me).
        let money_bubble_color = match &message.content {
            MessageContent::PaymentRequest { .. } => Some(if message.from_me {
                DashColors::success_color(dark_mode)
            } else {
                DashColors::info_color(dark_mode)
            }),
            MessageContent::Payment { .. } if message.verified_amount.is_some() => {
                Some(if message.from_me {
                    DashColors::info_color(dark_mode)
                } else {
                    DashColors::success_color(dark_mode)
                })
            }
            _ => None,
        };
        let bubble_frame = match money_bubble_color {
            Some(color) => egui::Frame::group(ui.style())
                .fill(color.gamma_multiply(0.08))
                .stroke(egui::Stroke::new(1.0, color)),
            None => egui::Frame::group(ui.style()),
        };

        ui.horizontal(|ui| {
            if message.from_me {
                // Approximates a 7-character indent at the default body
                // text size, so the back-and-forth is easier to follow at
                // a glance — my own messages read as a visually distinct
                // "column" from the counterparty's.
                ui.add_space(MY_MESSAGE_INDENT);
            }
            bubble_frame.show(ui, |ui| {
                // Bounds the bubble's width so it shrink-wraps to its
                // content instead of stretching to fill the row just to
                // make room for the right-aligned timestamp below, and so
                // a long message wraps instead of running off the screen.
                ui.set_max_width(ui.available_width().min(MESSAGE_BUBBLE_MAX_WIDTH));
                // A `Frame` container inherits its parent's layout direction
                // when none is given — and
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

                    // Suppressed for `PaymentRequest`: its own amount/memo
                    // are never editable through any other path, so an
                    // updatedAt/createdAt mismatch on this kind always
                    // means "cancelled" — the dedicated "Request Cancelled"
                    // status line already communicates that; showing this
                    // tag too would be redundant. Rendered per-kind, right
                    // below that kind's own text, rather than once here —
                    // "the text" is a different element per kind.
                    let is_edited = message.updated_at.is_some()
                        && message.updated_at != message.created_at
                        && !matches!(message.content, MessageContent::PaymentRequest { .. });
                    let show_edited_tag = |ui: &mut Ui| {
                        if is_edited {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new("(edited)")
                                            .strong()
                                            .color(DashColors::success_color(dark_mode)),
                                    );
                                },
                            );
                        }
                    };

                    // Delete/Edit Message/Edit Memo now live behind a
                    // right-click context menu on the text (see
                    // `render_message_bubble`'s doc comment on why plain
                    // text left-click was removed), so there's no longer an
                    // always-visible button to relabel with a progress verb
                    // while the menu is closed. This keeps that feedback
                    // visible independent of the menu's open state.
                    let show_busy_label = |ui: &mut Ui| {
                        if busy_here && let Some(label) = self.pending_bubble_action_label {
                            ui.label(
                                RichText::new(label)
                                    .italics()
                                    .color(DashColors::text_secondary(dark_mode)),
                            );
                        }
                    };

                    match &message.content {
                        MessageContent::Message { data } => {
                            let sanitized_data = strip_unsafe_display_characters_allow_newlines(data);
                            let text_response = ui.label(&sanitized_data);
                            show_edited_tag(ui);
                            show_busy_label(ui);
                            // Never reachable for the synthesized initial-
                            // message entry: its `document_id` is a
                            // `contactAnchor`, not an `encryptedMessage`, and
                            // must never be handed to a document-mutation
                            // task (delete/edit).
                            if message.from_me && !message.synthetic {
                                text_response.context_menu(|ui| {
                                    ui.set_min_width(140.0);
                                    if ui
                                        .add_enabled(!action_disabled, egui::Button::new("Delete"))
                                        .clicked()
                                    {
                                        bubble_action = Some(BubbleAction::DeleteMessage {
                                            document_id: message.document_id,
                                        });
                                        ui.close();
                                    }
                                    if ui
                                        .add_enabled(
                                            !action_disabled,
                                            egui::Button::new("Edit Message"),
                                        )
                                        .clicked()
                                    {
                                        bubble_action = Some(BubbleAction::EditMessage {
                                            document_id: message.document_id,
                                            current_text: data.clone(),
                                        });
                                        ui.close();
                                    }
                                });
                            }
                        }
                        MessageContent::Payment { amount, memo } => {
                            // Unverified (`None`) shows a "Pending…" headline
                            // instead of the sender's claimed amount — see
                            // the comment on `money_bubble_color` above. Once
                            // verified, this always shows the real verified
                            // amount, not the claim, matching a mismatch's
                            // own warning label just below.
                            let headline = match message.verified_amount {
                                Some(verified) => format!(
                                    "Payment: {}",
                                    format_credits_as_dash(verified)
                                ),
                                None => "Payment: Pending…".to_string(),
                            };
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(headline).strong());
                            });
                            match memo {
                                Some(memo_text) => {
                                    let sanitized_memo = strip_unsafe_display_characters_allow_newlines(memo_text);
                                    let memo_response = ui.label(&sanitized_memo);
                                    if message.from_me {
                                        memo_response.context_menu(|ui| {
                                            ui.set_min_width(140.0);
                                            if ui
                                                .add_enabled(
                                                    !action_disabled,
                                                    egui::Button::new("Edit Memo"),
                                                )
                                                .clicked()
                                            {
                                                bubble_action =
                                                    Some(BubbleAction::EditPaymentMemo {
                                                        document_id: message.document_id,
                                                        current_memo: Some(memo_text.clone()),
                                                    });
                                                ui.close();
                                            }
                                        });
                                        show_busy_label(ui);
                                    }
                                }
                                None if message.from_me => {
                                    let label = if busy_here { LABEL_SAVING } else { "Add Memo" };
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .add_enabled(!action_disabled, egui::Button::new(label))
                                                .clicked()
                                            {
                                                bubble_action =
                                                    Some(BubbleAction::EditPaymentMemo {
                                                        document_id: message.document_id,
                                                        current_memo: None,
                                                    });
                                            }
                                        },
                                    );
                                }
                                None => {}
                            }
                            show_edited_tag(ui);
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
                                ui.label(strip_unsafe_display_characters_allow_newlines(memo));
                            }
                            // A `PaymentRequest`'s amount/memo are never
                            // editable through any other path, so this
                            // mismatch unambiguously means "cancelled" —
                            // see `cancel_payment_request`'s doc comment.
                            let is_cancelled = message.updated_at.is_some()
                                && message.updated_at != message.created_at;
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
                                None if is_cancelled => {
                                    ui.label(
                                        RichText::new("Request Cancelled")
                                            .italics()
                                            .color(DashColors::text_secondary(dark_mode)),
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
                                    egui::Sides::new().show(
                                        ui,
                                        |ui| {
                                            ui.label(
                                                RichText::new("Awaiting payment")
                                                    .italics()
                                                    .color(DashColors::text_secondary(dark_mode)),
                                            );
                                        },
                                        |ui| {
                                            let label =
                                                if busy_here { LABEL_CANCELLING } else { "Cancel Request" };
                                            if ui
                                                .add_enabled(!action_disabled, egui::Button::new(label))
                                                .clicked()
                                            {
                                                bubble_action =
                                                    Some(BubbleAction::CancelPaymentRequest {
                                                        document_id: message.document_id,
                                                    });
                                            }
                                        },
                                    );
                                }
                                None => {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            let label = if busy_here { LABEL_PAYING } else { "Pay" };
                                            let response = ui.add_enabled(
                                                !credit_blocked && !action_disabled,
                                                egui::Button::new(label),
                                            );
                                            let response = if credit_blocked {
                                                response.disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
                                            } else {
                                                response
                                            };
                                            if response.clicked() {
                                                bubble_action = Some(BubbleAction::Pay {
                                                    document_id: message.document_id,
                                                    amount: *amount,
                                                    memo: memo.clone(),
                                                    created_at: message.created_at,
                                                });
                                            }
                                        },
                                    );
                                }
                            }
                        }
                        // Unreachable in practice: `load_thread` splits
                        // every `PaymentRequestReceipt` out of `messages`
                        // before this screen ever sees it — see
                        // `TimelineItem`/`render_receipt_alert`. Handled
                        // here only because `MessageContent` is matched
                        // exhaustively.
                        MessageContent::PaymentRequestReceipt { .. } => {}
                    }
                });
            });
        });
        ui.add_space(6.0);
        bubble_action
    }

    /// Renders one `OPP2` silent payment — a real, wallet-verified transfer
    /// with no backing document, so there is nothing to edit, delete, or
    /// reply to; no context menu, no `BubbleAction`. Reuses
    /// `render_message_bubble`'s money-tint color language (blue for
    /// outgoing, green for incoming) and header/timestamp layout so it
    /// reads as part of the same conversation rather than a separate
    /// concept.
    fn render_silent_payment_bubble(&self, ui: &mut Ui, payment: &SilentPaymentRecord) {
        let dark_mode = ui.style().visuals.dark_mode;
        let sender_label = if payment.from_me {
            self.my_name.as_deref().unwrap_or("You")
        } else {
            self.counterparty_name.as_deref().unwrap_or("Them")
        };
        let color = if payment.from_me {
            DashColors::info_color(dark_mode)
        } else {
            DashColors::success_color(dark_mode)
        };
        let bubble_frame = egui::Frame::group(ui.style())
            .fill(color.gamma_multiply(0.08))
            .stroke(egui::Stroke::new(1.0, color));

        ui.horizontal(|ui| {
            if payment.from_me {
                ui.add_space(MY_MESSAGE_INDENT);
            }
            bubble_frame.show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(MESSAGE_BUBBLE_MAX_WIDTH));
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    egui::Sides::new().show(
                        ui,
                        |ui| {
                            ui.label(RichText::new(sender_label).strong());
                        },
                        |ui| {
                            if let Some(timestamp) =
                                format_relative_time(payment.timestamp as u64 * 1000)
                            {
                                ui.label(
                                    RichText::new(timestamp)
                                        .size(11.0)
                                        .color(DashColors::text_secondary(dark_mode)),
                                );
                            }
                        },
                    );
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "Payment: {}",
                                format_credits_as_dash(payment.amount)
                            ))
                            .strong(),
                        );
                    });
                });
            });
        });
        ui.add_space(6.0);
    }

    /// The up-to-6 most recent verified money movements between the two
    /// parties, newest first, for the "Recent Payments" side table, plus
    /// whether the pre-truncation count reached [`RECENT_PAYMENTS_MAX_ROWS`]
    /// (i.e. whether the table's "only the N most recent" hint should show).
    /// Mirrors `render_message_bubble`'s own `verified_amount`-gated match
    /// (only a `Payment`/`PaymentRequest` with a wallet-confirmed amount
    /// counts — never the sender's bare claim) but flattens it into rows
    /// instead of a bubble tint. A paid `PaymentRequest` counts too, with
    /// direction inverted from its own `from_me`: money moves opposite to
    /// who asked for it (`verified_amount.is_some()` on a `PaymentRequest`
    /// means "paid", per `ThreadMessage::verified_amount`'s doc comment).
    fn recent_verified_payments(&self) -> (Vec<PaymentRow>, bool) {
        let mut rows: Vec<PaymentRow> = self
            .messages
            .iter()
            .filter_map(|message| {
                let credits = message.verified_amount?;
                let received = match &message.content {
                    MessageContent::Payment { .. } => !message.from_me,
                    MessageContent::PaymentRequest { .. } => message.from_me,
                    MessageContent::Message { .. }
                    | MessageContent::PaymentRequestReceipt { .. } => {
                        return None;
                    }
                };
                Some(PaymentRow {
                    received,
                    credits,
                    created_at: message.created_at,
                })
            })
            // A silent payment is a real wallet-verified transfer too — same
            // trust category as a document-backed `Payment`, just without a
            // document — so it counts toward this panel the same way.
            .chain(self.silent_payments.iter().map(|payment| PaymentRow {
                received: !payment.from_me,
                credits: payment.amount,
                created_at: Some(payment.timestamp as u64 * 1000),
            }))
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.created_at.unwrap_or(0)));
        let has_six_or_more = rows.len() >= RECENT_PAYMENTS_MAX_ROWS;
        rows.truncate(RECENT_PAYMENTS_MAX_ROWS);
        (rows, has_six_or_more)
    }

    /// Renders the "Recent Payments" side table — up to
    /// [`RECENT_PAYMENTS_MAX_ROWS`] verified payments between the two
    /// parties, newest first. Row tint mirrors `render_message_bubble`'s own
    /// color language (green/`success_color` for money received, blue/
    /// `info_color` for money sent) so the table reads as an extension of
    /// the thread's own bubbles rather than a separately-styled widget.
    fn render_recent_payments_table(&self, ui: &mut Ui) {
        let dark_mode = ui.style().visuals.dark_mode;
        ui.set_width(RECENT_PAYMENTS_PANEL_WIDTH);
        ui.heading(RichText::new("Recent Payments"));
        ui.add_space(8.0);

        let (rows, has_six_or_more) = self.recent_verified_payments();
        if rows.is_empty() {
            ui.label(
                RichText::new("No payments yet.").color(DashColors::text_secondary(dark_mode)),
            );
            return;
        }

        // The rows themselves already spell out sent/received, amount, and
        // date, so a full column-header row is redundant — just a small
        // hint about sort order instead.
        ui.label(
            RichText::new("(Most recent on top)").color(DashColors::text_secondary(dark_mode)),
        );
        if has_six_or_more {
            ui.label(
                RichText::new("Only the 6 most recent payments are displayed")
                    .color(DashColors::text_secondary(dark_mode)),
            );
        }
        ui.add_space(4.0);

        for row in &rows {
            let color = if row.received {
                DashColors::success_color(dark_mode)
            } else {
                DashColors::info_color(dark_mode)
            };
            egui::Frame::new()
                .fill(color.gamma_multiply(0.08))
                .stroke(egui::Stroke::new(1.0, color))
                .corner_radius(Shape::RADIUS_MD)
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(RECENT_PAYMENTS_COL1_WIDTH, RECENT_PAYMENTS_ROW_HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                let label = if row.received { "Received" } else { "Sent" };
                                ui.label(RichText::new(label).strong().color(color));
                            },
                        );
                        ui.allocate_ui_with_layout(
                            egui::vec2(RECENT_PAYMENTS_COL2_WIDTH, RECENT_PAYMENTS_ROW_HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(format_credits_as_dash(row.credits));
                            },
                        );
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), RECENT_PAYMENTS_ROW_HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                if let Some(when) = row.created_at.and_then(format_relative_time) {
                                    ui.label(
                                        RichText::new(when)
                                            .color(DashColors::text_secondary(dark_mode)),
                                    );
                                }
                            },
                        );
                    });
                });
            ui.add_space(6.0);
        }
    }

    /// Renders the conversation column (heading, warnings, message
    /// timeline, composer) — split out of `ScreenLike::ui`'s single
    /// `island_central_panel` closure so it can sit in a fixed-width
    /// `ui.vertical` next to the "Recent Payments" column while still
    /// formatting normally (a closure this large nested many levels deep
    /// defeats rustfmt's own reformatting, so this content needs to be a
    /// real method, not an inline closure).
    fn render_conversation_column(&mut self, ui: &mut Ui, conversation_width: f32) -> AppAction {
        let mut inner_action = AppAction::None;
        let dark_mode = ui.style().visuals.dark_mode;
        ui.set_width(conversation_width);
        let heading = match &self.counterparty_name {
            Some(name) => format!("Conversation with {name}"),
            None => format!(
                "Conversation with {}",
                self.counterparty_identity_id.to_string(Encoding::Base58)
            ),
        };
        // Any one of these already means some conversation action is in
        // flight — a manual refresh, a "load more", or a
        // send/pay/cancel/edit/delete via `sending`. Used to keep the
        // Refresh button and every other conversation action button
        // mutually exclusive, so at most one is ever running at a time.
        let thread_busy = self.loading || self.loading_more || self.sending;
        ui.horizontal(|ui| {
            ui.heading(RichText::new(heading));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let refresh_label = if self.loading {
                    "Refreshing…"
                } else {
                    "Refresh"
                };
                if ui
                    .add_enabled(!thread_busy, egui::Button::new(refresh_label))
                    .clicked()
                {
                    inner_action |= self.dispatch_load();
                }
            });
        });
        ui.add_space(8.0);

        if self.may_be_incomplete {
            let color = DashColors::warning_color(dark_mode);
            egui::Frame::new()
                .fill(color.gamma_multiply(0.1))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .corner_radius(5.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Some messages from this contact may not have loaded.")
                            .color(color),
                    );
                });
            ui.add_space(8.0);
        }

        if self.loading && self.messages.is_empty() {
            ui.label("Loading conversation…");
        }

        // Receipt alerts merge into the same chronological position as
        // everything else (sorted by `original_created_at`, captured at
        // pay-time for exactly this purpose — see
        // `MessageContent::PaymentRequestReceipt`), rather than a
        // separate fixed list, so a surfaced alert reads as "this is
        // where that request used to be."
        enum TimelineItem {
            Message(ThreadMessage),
            ReceiptAlert(ReceiptAlert),
            SilentPayment(SilentPaymentRecord),
        }
        let mut timeline: Vec<TimelineItem> = self
            .messages
            .iter()
            .cloned()
            .map(TimelineItem::Message)
            .chain(
                self.receipt_alerts
                    .iter()
                    .cloned()
                    .map(TimelineItem::ReceiptAlert),
            )
            .chain(
                self.silent_payments
                    .iter()
                    .copied()
                    .map(TimelineItem::SilentPayment),
            )
            .collect();
        timeline.sort_by_key(|item| match item {
            TimelineItem::Message(message) => message.created_at.unwrap_or(0),
            TimelineItem::ReceiptAlert(alert) => alert.original_created_at.unwrap_or(0),
            TimelineItem::SilentPayment(payment) => payment.timestamp as u64 * 1000,
        });

        let mut bubble_action: Option<BubbleAction> = None;
        let has_more_history = self.history_cursor.has_more();
        let loading_more = self.loading_more;
        let mut load_more_clicked = false;
        egui::ScrollArea::vertical()
            .max_height(ui.available_height() * 0.6)
            // Opens on the most recent messages (the bottom, since
            // `timeline` is chronological oldest-first) and follows new
            // messages/payments/requests as they're appended — unless
            // the user has manually scrolled up to read history, in
            // which case egui's own stuck-to-end tracking backs off and
            // leaves them where they are.
            .stick_to_bottom(true)
            .show(ui, |ui| {
                // Sits above the oldest bubble, so it's what a user
                // scrolling all the way up to read history runs into —
                // no scroll-position tracking needed, it's just the
                // first item in the same list.
                if has_more_history {
                    if loading_more {
                        ui.label("Loading more…");
                    } else if ui
                        .add_enabled(
                            !thread_busy,
                            egui::Button::new("See more conversation history"),
                        )
                        .clicked()
                    {
                        load_more_clicked = true;
                    }
                    ui.add_space(6.0);
                }
                for item in timeline {
                    match item {
                        TimelineItem::Message(message) => {
                            if let Some(action) = self.render_message_bubble(ui, &message) {
                                bubble_action = Some(action);
                            }
                        }
                        TimelineItem::ReceiptAlert(alert) => {
                            self.render_receipt_alert(ui, &alert);
                        }
                        TimelineItem::SilentPayment(payment) => {
                            self.render_silent_payment_bubble(ui, &payment);
                        }
                    }
                }
            });

        if load_more_clicked {
            self.loading_more = true;
            inner_action |= self.dispatch_load_more();
        }

        match bubble_action {
            Some(BubbleAction::Pay {
                document_id,
                amount,
                memo,
                created_at,
            }) => {
                self.open_pay_confirmation(document_id, amount, memo, created_at);
            }
            Some(BubbleAction::EditMessage {
                document_id,
                current_text,
            }) => {
                self.editing = Some(EditingState::Message {
                    document_id,
                    dialog: TextEditDialog::new(
                        "Edit Message",
                        current_text,
                        MAX_MESSAGE_CHARS,
                        validate_message_text,
                        "The message is too long. Use 1000 characters or fewer.",
                    ),
                });
            }
            Some(BubbleAction::EditPaymentMemo {
                document_id,
                current_memo,
            }) => {
                self.editing = Some(EditingState::PaymentMemo {
                    document_id,
                    dialog: TextEditDialog::new(
                        "Edit Memo",
                        current_memo.unwrap_or_default(),
                        MAX_PAYMENT_MEMO_CHARS,
                        validate_payment_memo,
                        "The payment memo is too long. Use 1000 characters or fewer.",
                    ),
                });
            }
            Some(BubbleAction::CancelPaymentRequest { document_id }) => {
                self.open_cancel_request_confirmation(document_id);
            }
            Some(BubbleAction::DeleteMessage { document_id }) => {
                self.open_delete_message_confirmation(document_id);
            }
            None => {}
        }

        inner_action |= self.render_composer(ui);

        inner_action
    }

    /// Renders one [`ReceiptAlert`] as a warning-styled panel — never a
    /// normal bubble. A receipt only ever surfaces once its original
    /// `PaymentRequest` no longer checks out (deleted, changed kind, or a
    /// tampered amount/memo); this is a system notice, not a chat message,
    /// so it isn't indented like one of "my" or "their" bubbles.
    fn render_receipt_alert(&self, ui: &mut Ui, alert: &ReceiptAlert) {
        let dark_mode = ui.style().visuals.dark_mode;
        let color = DashColors::warning_color(dark_mode);
        let reason = match alert.reason {
            ReceiptAlertReason::OriginalDeleted => "This payment request has been deleted.",
            ReceiptAlertReason::OriginalChangedKind => {
                "This payment request has changed into a different kind of message."
            }
            ReceiptAlertReason::OriginalAmountOrMemoMismatch => {
                "This payment request's amount or note no longer matches what you paid."
            }
        };

        egui::Frame::new()
            .fill(color.gamma_multiply(0.08))
            .inner_margin(egui::Margin::symmetric(10, 8))
            .stroke(egui::Stroke::new(1.0, color))
            .corner_radius(Shape::RADIUS_MD)
            .show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(MESSAGE_BUBBLE_MAX_WIDTH));
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.label(RichText::new("Saved Receipt").strong().color(color));
                    ui.label(reason);
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("You paid {}", format_credits_as_dash(alert.amount)))
                            .strong(),
                    );
                    if let Some(memo) = &alert.memo {
                        ui.label(strip_unsafe_display_characters_allow_newlines(memo));
                    }
                    if let Some(timestamp) =
                        alert.original_created_at.and_then(format_relative_time)
                    {
                        ui.label(
                            RichText::new(format!("Originally requested {timestamp}"))
                                .size(11.0)
                                .color(DashColors::text_secondary(dark_mode)),
                        );
                    }
                });
            });
        ui.add_space(6.0);
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
                            AmountInput::new(Amount::new_dash(0.0))
                                .with_label("Amount (DASH):")
                                .with_min_amount(Some(MIN_SEND_AMOUNT_CREDITS))
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

                        if self.compose_kind == ComposeKind::Payment {
                            ui.checkbox(&mut self.compose_send_silently, "Send without a message")
                                .clickable_tooltip(
                                    "No document is published for this payment — only a private \
                                     transfer, with no public record that it happened.",
                                );
                        }

                        // Hidden while sending silently — a silent payment
                        // carries no message/memo at all (see
                        // `silent_payment::send_silent_payment`'s doc
                        // comment); showing an input the send path ignores
                        // would be misleading.
                        if !(self.compose_kind == ComposeKind::Payment
                            && self.compose_send_silently)
                        {
                            ui.horizontal(|ui| {
                                ui.label("Note (optional):");
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.compose_memo)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(2),
                                );
                            });
                        }
                    }
                }
                ui.add_space(6.0);

                let credit_blocked = is_credit_balance_blocked(self.identity.identity.balance());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // No document_id to key off for a brand-new message/request/
                    // payment, so the composer's own send is "the busy one"
                    // whenever something is pending and it isn't a bubble-scoped
                    // mutation.
                    let composer_busy = self.sending && self.pending_document_mutation_id.is_none();
                    let send_label = if composer_busy { LABEL_SENDING } else { "Send" };
                    // Mirrors `render_message_bubble`'s `action_disabled`: a
                    // manual refresh or "load more" keeps Send mutually
                    // exclusive with every other conversation action too.
                    let thread_busy = self.sending || self.loading || self.loading_more;
                    if ui
                        .add_enabled(
                            !thread_busy && !credit_blocked,
                            egui::Button::new(send_label),
                        )
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
            self.pending_document_mutation_id = None;
            self.pending_bubble_action_label = None;
            self.composer_send_pending = false;
            self.loading = false;
            self.loading_more = false;
            self.refresh_banner.take_and_clear();
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        match result {
            BackendTaskSuccessResult::OrchardPayThreadLoaded {
                counterparty_identity_id,
                all_decoded,
                messages,
                silent_payments,
                receipt_alerts,
                history_cursor,
                may_be_incomplete,
            } if counterparty_identity_id == self.counterparty_identity_id => {
                self.messages = messages;
                self.silent_payments = silent_payments;
                self.receipt_alerts = receipt_alerts;
                self.all_decoded_thread = all_decoded;
                self.history_cursor = history_cursor;
                self.may_be_incomplete = may_be_incomplete;
                self.loading = false;
                self.loading_more = false;
            }
            BackendTaskSuccessResult::OrchardPayPaymentSent { .. }
            | BackendTaskSuccessResult::OrchardPaySilentPaymentSent { .. } => {
                self.sending = false;
                self.pending_document_mutation_id = None;
                self.pending_bubble_action_label = None;
                self.clear_composer();
                self.pending_reload = true;
                self.pending_identity_refresh = true;
            }
            // `BroadcastedDocument` is a generic, app-wide result type (any
            // document creation, not just this thread's own) — only treat
            // it as "my composer send finished" when this screen actually
            // set `composer_send_pending` before dispatch. Otherwise it
            // belongs to some unrelated broadcast that happened to arrive
            // while this thread is the visible/hidden-routed screen, and
            // must not clear a guard it didn't set (see
            // `composer_send_pending`'s doc comment).
            BackendTaskSuccessResult::BroadcastedDocument(_) if self.composer_send_pending => {
                self.composer_send_pending = false;
                self.sending = false;
                self.pending_document_mutation_id = None;
                self.pending_bubble_action_label = None;
                self.clear_composer();
                self.pending_reload = true;
                self.pending_identity_refresh = true;
            }
            BackendTaskSuccessResult::ReplacedDocument(document_id, _fee)
                if self.pending_document_mutation_id == Some(document_id) =>
            {
                self.pending_document_mutation_id = None;
                self.pending_bubble_action_label = None;
                self.sending = false;
                self.pending_reload = true;
                self.pending_identity_refresh = true;
            }
            BackendTaskSuccessResult::DeletedDocument(document_id, _fee)
                if self.pending_document_mutation_id == Some(document_id) =>
            {
                self.pending_document_mutation_id = None;
                self.pending_bubble_action_label = None;
                self.sending = false;
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
        action |= self.render_editing_modal(ui);

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
                "Most Recent",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::MostRecent),
            ),
            SubscreenNavItem::new(
                "Contacts",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Contacts),
            ),
            SubscreenNavItem::new(
                "Send Friend Request",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::AddContact),
            ),
            SubscreenNavItem::new(
                "Shielded TXs",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Payments),
            ),
            SubscreenNavItem::new(
                "Profile",
                false,
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::Profile),
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

            // A horizontal split within the same island rather than a
            // separate side panel — sharing one surface/border/shadow with
            // the conversation itself, no divider line between the two
            // columns, just spacing. `inner_action` is captured by both
            // closures via `&mut`.
            //
            // `horizontal_top` (not plain `horizontal`, which only
            // pre-allocates a single interactive-widget-sized row and grows
            // from there) — it hands both child columns the island's full
            // remaining height up front, so `render_conversation_column`'s
            // own `ui.available_height()` (used to size the message
            // scroll area) sees the real window height again instead of a
            // sliver, which is also what was making the whole island
            // shrink to fit that sliver.
            ui.horizontal_top(|ui| {
                let conversation_width = (ui.available_width()
                    - RECENT_PAYMENTS_PANEL_WIDTH
                    - RECENT_PAYMENTS_COLUMN_GAP)
                    .max(0.0);
                ui.vertical(|ui| {
                    inner_action |= self.render_conversation_column(ui, conversation_width);
                });
                ui.add_space(RECENT_PAYMENTS_COLUMN_GAP);
                ui.vertical(|ui| {
                    self.render_recent_payments_table(ui);
                });
            });
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
            private_keys: KeyStorage::default(),
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

    /// Full-screen render (`ScreenLike::ui`), not just the composer —
    /// needed to see the conversation column's message bubbles. Any
    /// `AppAction` returned (e.g. a `LoadThread` dispatch on first render)
    /// is discarded, same as every other full-render kittest mount in this
    /// codebase.
    fn mount_full(screen: MessageThreadScreen) -> Harness<'static, MessageThreadScreen> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(900.0, 700.0))
            .build_ui_state(
                move |ui, screen: &mut MessageThreadScreen| {
                    let _ = screen.ui(ui);
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

    /// Right-click (secondary button, press + release) at `label`'s center —
    /// mirrors `click_in_one_frame`'s primary-click recipe, since egui's
    /// `context_menu` opens on a raw secondary pointer event, not an
    /// accesskit action.
    fn right_click_in_one_frame(harness: &mut Harness<'_, MessageThreadScreen>, label: &str) {
        let pos = harness.get_by_label(label).rect().center();
        harness.input_mut().events.extend([
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Secondary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Secondary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]);
        harness.step();
    }

    /// The regression test for the §8 gotcha: a synthesized initial-message
    /// bubble (`ThreadMessage::synthetic == true`) must render as a normal
    /// "From Me" message but must never expose the Delete/Edit Message
    /// context menu, since its `document_id` is a `contactAnchor`, not an
    /// `encryptedMessage` — handing it to `DeleteMessage`/`EditMessage`
    /// would attempt to mutate the wrong document type.
    #[test]
    fn synthetic_initial_message_renders_with_no_delete_or_edit_menu() {
        let (mut screen, _temp_dir) = message_thread_screen();

        screen.display_task_result(BackendTaskSuccessResult::OrchardPayThreadLoaded {
            counterparty_identity_id: screen.counterparty_identity_id,
            all_decoded: vec![ThreadMessage {
                document_id: Identifier::random(),
                from_me: true,
                created_at: Some(1_700_000_000_000),
                updated_at: None,
                content: MessageContent::Message {
                    data: "hey its me Paul".to_string(),
                },
                verified_amount: None,
                synthetic: true,
            }],
            messages: vec![ThreadMessage {
                document_id: Identifier::random(),
                from_me: true,
                created_at: Some(1_700_000_000_000),
                updated_at: None,
                content: MessageContent::Message {
                    data: "hey its me Paul".to_string(),
                },
                verified_amount: None,
                synthetic: true,
            }],
            silent_payments: Vec::new(),
            receipt_alerts: Vec::new(),
            history_cursor: HistoryCursor::default(),
            may_be_incomplete: false,
        });

        let mut harness = mount_full(screen);

        assert!(
            harness.query_by_label_contains("hey its me Paul").is_some(),
            "the synthesized initial message must render as a normal bubble"
        );

        right_click_in_one_frame(&mut harness, "hey its me Paul");

        assert!(
            harness.query_by_label("Delete").is_none(),
            "a synthetic bubble must never expose a Delete action"
        );
        assert!(
            harness.query_by_label("Edit Message").is_none(),
            "a synthetic bubble must never expose an Edit Message action"
        );
    }
}
