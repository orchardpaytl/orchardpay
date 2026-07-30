use crate::app::AppAction;
use crate::context::AppContext;
use crate::ui::components::left_panel::add_left_panel;
use crate::ui::components::styled::island_central_panel;
use crate::ui::components::top_panel::add_top_panel;
use crate::ui::theme::DashColors;
use crate::ui::{RootScreenType, ScreenLike};

use egui::{Direction, Layout, RichText};
use std::sync::Arc;

pub struct OrchardPartyScreen {
    pub app_context: Arc<AppContext>,
}

impl OrchardPartyScreen {
    pub fn new(app_context: &Arc<AppContext>) -> Self {
        Self {
            app_context: app_context.clone(),
        }
    }
}

impl ScreenLike for OrchardPartyScreen {
    fn ui(&mut self, ui: &mut egui::Ui) -> AppAction {
        let dark_mode = ui.ctx().global_style().visuals.dark_mode;

        let mut action = add_top_panel(
            ui,
            &self.app_context,
            vec![("OrchardParty", AppAction::None)],
            vec![],
        );
        action |= add_left_panel(
            ui,
            &self.app_context,
            RootScreenType::RootScreenOrchardParty,
        );
        action |= island_central_panel(ui, |ui| {
            ui.with_layout(Layout::centered_and_justified(Direction::TopDown), |ui| {
                ui.label(
                    RichText::new("OrchardParty - Coming Soon!")
                        .size(20.0)
                        .color(DashColors::text_primary(dark_mode)),
                );
            });
            AppAction::None
        });

        action
    }
}
