use bevy::prelude::*;
use bevy_egui::{egui, EguiContext};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GivenWords(pub String);

pub fn action(mut egui_ctx: ResMut<EguiContext>, mut given_words: ResMut<GivenWords>) {
    egui::CentralPanel::default().show(egui_ctx.ctx_mut(), |ui| {
        egui::warn_if_debug_build(ui);

        ui.heading("Mnemonic words");

        ui.separator();

        ui.add_sized(
            [ui.available_width(), 60.0],
            egui::TextEdit::singleline(&mut given_words.0).layouter(
                &mut |ui: &egui::Ui, text: &str, wrap_width: f32| {
                    let text_format = egui::TextFormat::default();
                    let mut layout_job = egui::text::LayoutJob::default();
                    layout_job.append(text, 0.0, text_format);
                    layout_job.wrap_width = wrap_width;
                    ui.fonts().layout_job(layout_job)
                },
            ),
        );

        ui.separator();

        ui.label(given_words.0.as_str());
    });
}
