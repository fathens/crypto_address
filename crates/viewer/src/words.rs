use bevy::prelude::*;
use bevy_egui::{egui, EguiContext};
use bytes::Bytes;
use getrandom::getrandom;
use mnemonic::calcseed::to_mnemonic;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GivenWords(pub String);

pub fn action(mut egui_ctx: ResMut<EguiContext>, mut given_words: ResMut<GivenWords>) {
    let alert = |msg: &str| {
        bevy::log::error!(msg);
        // let window = egui::Window::new("Alert").vscroll(true);
        // window.show(egui_ctx.ctx_mut(), |ui| {
        //     ui.label(msg);
        // });
    };

    egui::CentralPanel::default().show(egui_ctx.ctx_mut(), |ui| {
        egui::warn_if_debug_build(ui);

        ui.heading("Mnemonic words");

        let generate = |len: usize| match random_bytes(len / 8) {
            Err(err) => {
                alert(err.to_string().as_str());
                "".to_owned()
            }
            Ok(bytes) => match to_mnemonic(bytes) {
                Err(err) => {
                    alert(err.to_string().as_str());
                    "".to_owned()
                }
                Ok(ws) => {
                    bevy::log::info!("words: {ws:?}");
                    ws.join(" ").to_owned()
                }
            },
        };

        if ui.button("128 bits (12 words)").clicked() {
            given_words.0 = generate(128);
        }
        if ui.button("256 bits (24 words)").clicked() {
            given_words.0 = generate(256);
        }
        if ui.button("512 bits (48 words)").clicked() {
            given_words.0 = generate(512);
        }

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

fn random_bytes(len_bytes: usize) -> Result<Bytes, getrandom::Error> {
    let mut buf = vec![0; len_bytes];
    getrandom(&mut buf)?;
    Ok(buf.into())
}
