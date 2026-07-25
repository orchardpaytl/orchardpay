use crate::app::AppAction;
use crate::backend_task::orchardpay::OrchardPayTask;
use crate::backend_task::{BackendTask, BackendTaskSuccessResult};
use crate::context::AppContext;
use crate::model::orchardpay::{CREDIT_BLOCKED_TOOLTIP, is_credit_balance_blocked};
use crate::model::qualified_identity::QualifiedIdentity;
use crate::model::wallet::Wallet;
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::top_panel::add_top_panel;
use crate::ui::components::wallet_unlock_popup::{
    WalletUnlockPopup, try_open_wallet_no_password, wallet_needs_unlock,
};
use crate::ui::components::{
    BannerHandle, MessageBanner, OptionBannerExt, OptionOverlayExt, OverlayConfig, OverlayHandle,
};
use crate::ui::identities::get_selected_wallet;
use crate::ui::orchardpay::orchardpay_screen::OrchardPaySubscreen;
use crate::ui::theme::{DashColors, ResponseExt};
use crate::ui::{MessageType, ScreenLike};
use dash_sdk::dpp::identity::accessors::IdentityGettersV0;
use dash_sdk::dpp::identity::{KeyType, Purpose, SecurityLevel};
use dash_sdk::platform::IdentityPublicKey;
use egui::{Context, RichText, Ui};
use std::sync::{Arc, RwLock};

#[derive(PartialEq)]
enum PublishStatus {
    NotStarted,
    WaitingForResult,
    Error,
    Complete,
}

pub struct ShieldedAddressSetupScreen {
    pub app_context: Arc<AppContext>,
    pub identity: QualifiedIdentity,
    selected_key: Option<IdentityPublicKey>,
    selected_wallet: Option<Arc<RwLock<Wallet>>>,
    wallet_unlock_popup: WalletUnlockPopup,
    wallet_open_attempted: bool,
    status: PublishStatus,
    op_overlay: Option<OverlayHandle>,
    refresh_banner: Option<BannerHandle>,
}

impl ShieldedAddressSetupScreen {
    pub fn new(identity: QualifiedIdentity, app_context: &Arc<AppContext>) -> Self {
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
            selected_key,
            selected_wallet,
            wallet_unlock_popup: WalletUnlockPopup::new(),
            wallet_open_attempted: false,
            status: PublishStatus::NotStarted,
            op_overlay: None,
            refresh_banner: None,
        }
    }

    fn publish_clicked(&mut self, ctx: &Context) -> AppAction {
        let (Some(key), Some(wallet)) = (self.selected_key.clone(), self.selected_wallet.clone())
        else {
            return AppAction::None;
        };
        let Ok(seed_hash) = wallet.read().map(|w| w.seed_hash()) else {
            return AppAction::None;
        };

        self.status = PublishStatus::WaitingForResult;
        self.op_overlay.raise(
            ctx,
            "Publishing your shielded address to the network.",
            OverlayConfig::default(),
        );

        AppAction::BackendTask(BackendTask::OrchardPayTask(Box::new(
            OrchardPayTask::PublishShieldedAddress {
                qualified_identity: self.identity.clone(),
                identity_key: key,
                seed_hash,
            },
        )))
    }

    fn show_success(&mut self, ui: &mut Ui) -> AppAction {
        crate::ui::helpers::show_success_screen_with_info(
            ui,
            "Shielded Address Published!".to_string(),
            vec![(
                "Go to OrchardPay".to_string(),
                AppAction::NavigateToOrchardPaySubscreen(OrchardPaySubscreen::AddContact),
            )],
            Some((
                "What's next",
                "Contacts can now find your shielded address to reach you through \
                 OrchardPay.",
            )),
        )
    }
}

impl ScreenLike for ShieldedAddressSetupScreen {
    fn display_message(&mut self, _message: &str, message_type: MessageType) {
        if matches!(message_type, MessageType::Error | MessageType::Warning) {
            self.op_overlay.take_and_clear();
            self.refresh_banner.take_and_clear();
            self.status = PublishStatus::Error;
        }
    }

    fn display_task_result(&mut self, result: BackendTaskSuccessResult) {
        if matches!(
            result,
            BackendTaskSuccessResult::BroadcastedDocument(_)
                | BackendTaskSuccessResult::ReplacedDocument(_, _)
        ) {
            self.op_overlay.take_and_clear();
            self.status = PublishStatus::Complete;
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let ctx = ui.ctx().clone();
        let ctx = &ctx;

        let breadcrumbs = vec![
            (
                "Identities",
                AppAction::SetMainScreen(crate::ui::RootScreenType::RootScreenIdentities),
            ),
            ("Setup OrchardPay", AppAction::None),
        ];
        let mut action = add_top_panel(ui, &self.app_context, breadcrumbs, vec![]);
        action |= add_left_panel(
            ui,
            &self.app_context,
            crate::ui::RootScreenType::RootScreenIdentities,
        );

        action |= island_central_panel(ui, |ui| {
            let mut inner_action = AppAction::None;

            if self.status == PublishStatus::Complete {
                inner_action |= self.show_success(ui);
                return inner_action;
            }

            ui.heading("Set Up Keys and Address for OrchardPay");
            ui.add_space(10.0);
            ui.label(
                "Publishing a shielded address lets other people find you and start \
                 a private, encrypted conversation through OrchardPay — without revealing \
                 who you are connecting with.",
            );
            ui.add_space(15.0);

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
            } else {
                ui.colored_label(
                    egui::Color32::DARK_RED,
                    "No wallet found for this identity. A wallet is required to derive your \
                     shielded address.",
                );
                return inner_action;
            }

            let dark_mode = ui.style().visuals.dark_mode;
            let address_preview = self
                .selected_wallet
                .as_ref()
                .and_then(|w| w.read().ok().map(|w| w.seed_hash()))
                .and_then(|seed_hash| self.app_context.shielded_receive_address(&seed_hash));

            ui.label(
                RichText::new("Your shielded address:")
                    .color(DashColors::text_secondary(dark_mode)),
            );
            ui.add_space(4.0);
            match &address_preview {
                Some(address) => {
                    ui.label(RichText::new(address).monospace());
                }
                None => {
                    ui.label(
                        RichText::new(
                            "Not ready yet — your wallet's shielded keys are still syncing.",
                        )
                        .color(DashColors::text_secondary(dark_mode)),
                    );
                }
            }
            ui.add_space(15.0);

            let credit_blocked = is_credit_balance_blocked(self.identity.identity.balance());
            let button_enabled =
                self.selected_key.is_some() && address_preview.is_some() && !credit_blocked;
            let response = ui.add_enabled(button_enabled, egui::Button::new("Publish"));
            let response = if credit_blocked {
                response.disabled_tooltip(CREDIT_BLOCKED_TOOLTIP)
            } else {
                response
            };
            if response.clicked() {
                inner_action |= self.publish_clicked(ctx);
            }

            inner_action
        });

        if self.wallet_unlock_popup.is_open()
            && let Some(wallet) = &self.selected_wallet
        {
            self.wallet_unlock_popup
                .show(ctx, wallet, &self.app_context);
        }

        action
    }
}
