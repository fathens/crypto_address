use bevy::prelude::ResMut;
use bevy_egui::{egui, EguiContext};

pub fn ui_example(mut egui_context: ResMut<EguiContext>) {
    egui::Window::new("Hello").show(egui_context.ctx_mut(), |ui| {
        ui.label("world");
    });
}
