use crate::ui::Screen;
use crate::ui::theme::{DashColors, Shape, Spacing};
use egui::{Color32, RichText, Ui};

/// A step in the guided first-run setup chain (wallet -> identity -> DPNS name).
///
/// Determined from the currently visible [`Screen`] rather than tracked as a
/// separate counter, so it can never drift out of sync with where the user
/// actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingStep {
    Wallet,
    Identity,
    DpnsName,
    PrivateAddress,
}

impl OnboardingStep {
    pub const ALL: [OnboardingStep; 4] = [
        OnboardingStep::Wallet,
        OnboardingStep::Identity,
        OnboardingStep::DpnsName,
        OnboardingStep::PrivateAddress,
    ];

    fn label(&self) -> &'static str {
        match self {
            OnboardingStep::Wallet => "Wallet",
            OnboardingStep::Identity => "Identity",
            OnboardingStep::DpnsName => "Name",
            OnboardingStep::PrivateAddress => "OrchardPay",
        }
    }

    fn index(&self) -> usize {
        Self::ALL.iter().position(|s| s == self).unwrap_or(0)
    }
}

/// Maps the currently visible screen to an onboarding step, if it's one of
/// the screens in the guided setup chain. Returns `None` once the user has
/// navigated away from the chain, which is the signal to stop showing the
/// stepper entirely.
pub fn onboarding_step_for_screen(screen: &Screen) -> Option<OnboardingStep> {
    match screen {
        Screen::AddNewWalletScreen(_) | Screen::ImportMnemonicScreen(_) => {
            Some(OnboardingStep::Wallet)
        }
        Screen::AddNewIdentityScreen(_) => Some(OnboardingStep::Identity),
        Screen::RegisterDpnsNameScreen(_) => Some(OnboardingStep::DpnsName),
        Screen::ShieldedAddressSetupScreen(_) => Some(OnboardingStep::PrivateAddress),
        _ => None,
    }
}

/// Renders a thin, skippable step indicator for the guided setup chain.
pub fn render_onboarding_progress(ui: &mut Ui, dark_mode: bool, current: OnboardingStep) {
    let current_index = current.index();

    egui::Frame::new()
        .fill(DashColors::background(dark_mode))
        .inner_margin(egui::Margin::symmetric(
            Spacing::MD as i8,
            Spacing::SM as i8,
        ))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Guided setup:")
                        .size(12.0)
                        .color(DashColors::text_secondary(dark_mode)),
                );
                ui.add_space(Spacing::SM);

                for (index, step) in OnboardingStep::ALL.iter().enumerate() {
                    if index > 0 {
                        ui.label(
                            RichText::new("\u{2192}")
                                .size(12.0)
                                .color(DashColors::text_secondary(dark_mode)),
                        );
                    }

                    let (text_color, strong) = if index == current_index {
                        (DashColors::text_primary(dark_mode), true)
                    } else if index < current_index {
                        (DashColors::success_color(dark_mode), false)
                    } else {
                        (DashColors::text_secondary(dark_mode), false)
                    };

                    let badge = egui::Frame::new()
                        .fill(if index == current_index {
                            DashColors::border_light(dark_mode)
                        } else {
                            Color32::TRANSPARENT
                        })
                        .corner_radius(Shape::RADIUS_SM)
                        .inner_margin(egui::Margin::symmetric(Spacing::SM as i8, 2));
                    badge.show(ui, |ui| {
                        let mut text = RichText::new(step.label()).size(12.0).color(text_color);
                        if strong {
                            text = text.strong();
                        }
                        ui.label(text);
                    });
                }
            });
        });
}
