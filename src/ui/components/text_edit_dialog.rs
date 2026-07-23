use crate::model::validation::TextLengthError;
use crate::ui::components::component_trait::{Component, ComponentResponse};
use crate::ui::components::modal_chrome::{ModalChromeConfig, modal_chrome};
use crate::ui::helpers::{ModalOpeningGuard, clicked_outside_window_after_open};
use crate::ui::theme::{ComponentStyles, DashColors};
use egui::{InnerResponse, Ui, WidgetText};

/// Response from showing a text-edit dialog.
#[derive(Debug, Clone, PartialEq)]
pub enum TextEditStatus {
    /// The user saved the (already-validated) text.
    Saved(String),
    /// The user clicked cancel, closed the dialog, or clicked outside it.
    Canceled,
}

/// Response struct for the `TextEditDialog` component, following the
/// Component trait pattern (see `ConfirmationDialogComponentResponse`).
#[derive(Debug, Clone)]
pub struct TextEditDialogComponentResponse {
    pub response: egui::Response,
    pub changed: bool,
    pub error_message: Option<String>,
    pub dialog_response: Option<TextEditStatus>,
}

impl ComponentResponse for TextEditDialogComponentResponse {
    type DomainType = TextEditStatus;

    fn has_changed(&self) -> bool {
        self.changed
    }

    fn is_valid(&self) -> bool {
        self.error_message.is_none()
    }

    fn changed_value(&self) -> &Option<Self::DomainType> {
        if self.has_changed() {
            &self.dialog_response
        } else {
            &None
        }
    }

    fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

/// A modal dialog for editing a single block of text against a shared
/// character-length validator (e.g. `model::orchardpay::validate_message_text`),
/// with a live character counter and a Save button that's disabled while the
/// current text fails validation. Built on the same [`modal_chrome`] as
/// [`crate::ui::components::confirmation_dialog::ConfirmationDialog`].
///
/// The validator is always the shared model function, never reimplemented
/// here — this dialog only supplies the friendly wording shown on failure,
/// per this repo's validation-layering rule (UI calls model validators for
/// instant feedback; the model function is the single source of truth).
pub struct TextEditDialog {
    title: WidgetText,
    text: String,
    max_chars: usize,
    validator: fn(&str) -> Result<(), TextLengthError>,
    too_long_message: WidgetText,
    save_text: WidgetText,
    cancel_text: WidgetText,
    blocks_input: bool,
    is_open: bool,
    opening_guard: ModalOpeningGuard,
}

impl Component for TextEditDialog {
    type DomainType = TextEditStatus;
    type Response = TextEditDialogComponentResponse;

    fn show(&mut self, ui: &mut Ui) -> InnerResponse<Self::Response> {
        let inner_response = self.show_dialog(ui);
        let changed = inner_response.inner.is_some();
        let response = inner_response.response;

        InnerResponse::new(
            TextEditDialogComponentResponse {
                response: response.clone(),
                changed,
                error_message: None,
                dialog_response: inner_response.inner,
            },
            response,
        )
    }

    fn current_value(&self) -> Option<Self::DomainType> {
        if self.is_open {
            None
        } else {
            Some(TextEditStatus::Canceled)
        }
    }
}

impl TextEditDialog {
    /// Create a new text-edit dialog pre-filled with `initial_text`.
    /// `max_chars` drives only the live counter display — `validator` is the
    /// actual source of truth for whether Save is enabled, and should be one
    /// of the shared `model` validators (e.g. `validate_message_text`).
    /// `too_long_message` is shown, in place of the validator's own
    /// technical `Display` text, whenever the current text fails validation.
    pub fn new(
        title: impl Into<WidgetText>,
        initial_text: impl Into<String>,
        max_chars: usize,
        validator: fn(&str) -> Result<(), TextLengthError>,
        too_long_message: impl Into<WidgetText>,
    ) -> Self {
        Self {
            title: title.into(),
            text: initial_text.into(),
            max_chars,
            validator,
            too_long_message: too_long_message.into(),
            save_text: "Save".into(),
            cancel_text: "Cancel".into(),
            blocks_input: true,
            is_open: true,
            opening_guard: ModalOpeningGuard::armed(),
        }
    }

    /// Set whether the dialog blocks input to controls behind it. Defaults
    /// to `true`, matching the other blocking modals in this app.
    pub fn blocks_input(mut self, enabled: bool) -> Self {
        self.blocks_input = enabled;
        self
    }

    fn show_dialog(&mut self, ui: &mut Ui) -> InnerResponse<Option<TextEditStatus>> {
        if !self.is_open {
            return InnerResponse::new(
                None,
                ui.allocate_response(egui::Vec2::ZERO, egui::Sense::hover()),
            );
        }

        let mut final_response = None;
        let chrome = modal_chrome(
            ui.ctx(),
            ModalChromeConfig {
                title: self.title.clone(),
                overlay_id: egui::Id::new("text_edit_dialog_overlay"),
                overlay_order: egui::Order::Background,
                window_order: if self.blocks_input {
                    egui::Order::Foreground
                } else {
                    egui::Order::Middle
                },
                resizable: false,
                show_close_button: true,
                blocks_input: self.blocks_input,
                inner_margin: 16,
            },
            |ui| {
                ui.set_min_width(360.0);
                let dark_mode = ui.style().visuals.dark_mode;

                ui.add_space(10.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.text)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4),
                );

                let validation = (self.validator)(self.text.trim());
                let char_count = self.text.chars().count();
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if validation.is_err() {
                        ui.label(
                            egui::RichText::new(self.too_long_message.text())
                                .color(DashColors::warning_color(dark_mode)),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(format!("{char_count} / {}", self.max_chars))
                                .size(11.0)
                                .color(DashColors::text_secondary(dark_mode)),
                        );
                    });
                });
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let save_response = ComponentStyles::add_primary_button_enabled(
                            ui,
                            validation.is_ok(),
                            self.save_text.clone(),
                        );
                        if save_response.clicked() {
                            final_response =
                                Some(TextEditStatus::Saved(self.text.trim().to_string()));
                        }

                        if ComponentStyles::add_secondary_button(
                            ui,
                            self.cancel_text.clone(),
                            dark_mode,
                        )
                        .clicked()
                        {
                            final_response = Some(TextEditStatus::Canceled);
                        }
                        ui.add_space(8.0);
                    });
                });
            },
        );

        if chrome.closed_via_x && final_response.is_none() {
            final_response = Some(TextEditStatus::Canceled);
        }

        if final_response.is_none() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            final_response = Some(TextEditStatus::Canceled);
        }

        if let Some(ref wr) = chrome.window_response
            && final_response.is_none()
            && clicked_outside_window_after_open(ui.ctx(), wr.rect, &mut self.opening_guard)
        {
            final_response = Some(TextEditStatus::Canceled);
        }

        self.is_open = !chrome.closed_via_x;

        if let Some(window_response) = chrome.window_response {
            InnerResponse::new(final_response, window_response)
        } else {
            InnerResponse::new(
                final_response,
                ui.allocate_response(egui::Vec2::ZERO, egui::Sense::hover()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::validation::validate_char_count;

    fn short_text_validator(text: &str) -> Result<(), TextLengthError> {
        validate_char_count(text, 0, 5)
    }

    #[test]
    fn dialog_starts_open_with_initial_text() {
        let dialog = TextEditDialog::new("Edit", "hello", 5, short_text_validator, "Too long.");
        assert!(dialog.is_open);
        assert_eq!(dialog.text, "hello");
    }

    #[test]
    fn save_is_rejected_when_validator_fails() {
        let ctx = egui::Context::default();
        let mut dialog = TextEditDialog::new(
            "Edit",
            "way too long for the limit",
            5,
            short_text_validator,
            "Too long.",
        );
        let mut status = None;

        let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
            status = dialog.show(ui).inner.dialog_response;
        });

        assert_eq!(
            status, None,
            "the Save button must be disabled while validation fails, so no click can register"
        );
    }
}
