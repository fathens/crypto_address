use bevy::prelude::*;
use bevy_egui::{egui, EguiContext};
use bytes::Bytes;
use evm_address::address::EvmAddress;
use extend_key::{base58, ecdsa_key::PrvKeyBytes, extkey::ExtKey};
use getrandom::getrandom;
use mnemonic::calcseed::to_mnemonic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGeneration {
    pub words: String,
    pub hdpath: String,
    pub address: String,
}

impl Default for KeyGeneration {
    fn default() -> Self {
        Self {
            words: Default::default(),
            hdpath: "m/44'/60'/0'/0/0".to_owned(),
            address: Default::default(),
        }
    }
}

pub fn action(mut egui_ctx: ResMut<EguiContext>, mut given_words: ResMut<KeyGeneration>) {
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
            given_words.words = generate(128);
        }
        if ui.button("256 bits (24 words)").clicked() {
            given_words.words = generate(256);
        }
        if ui.button("512 bits (48 words)").clicked() {
            given_words.words = generate(512);
        }

        ui.separator();

        ui.add_sized(
            [ui.available_width(), 60.0],
            egui::TextEdit::singleline(&mut given_words.words).layouter(
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

        ui.text_edit_singleline(&mut given_words.hdpath);

        ui.separator();

        if ui.button("Calculate").clicked() {
            let words: Vec<_> = given_words.words.split(" ").collect();
            match mk_key(&words, &given_words.hdpath) {
                Ok(address) => given_words.address = address.to_string(),
                Err(err) => {
                    alert(err.to_string().as_str());
                    given_words.address = "".to_owned();
                }
            }
        }

        ui.label(given_words.address.as_str());
    });
}

#[derive(Debug)]
struct ViwerError(String);

impl core::fmt::Display for ViwerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl From<getrandom::Error> for ViwerError {
    fn from(src: getrandom::Error) -> Self {
        Self(src.to_string())
    }
}

impl From<hdpath::path::HDPathError> for ViwerError {
    fn from(src: hdpath::path::HDPathError) -> Self {
        Self(src.to_string())
    }
}

impl From<extend_key::error::ExtendError> for ViwerError {
    fn from(src: extend_key::error::ExtendError) -> Self {
        Self(src.to_string())
    }
}

impl From<std::io::Error> for ViwerError {
    fn from(src: std::io::Error) -> Self {
        Self(src.to_string())
    }
}

type Result<A> = core::result::Result<A, ViwerError>;
type ExtPrvKey = ExtKey<PrvKeyBytes>;

fn random_bytes(len_bytes: usize) -> Result<Bytes> {
    let mut buf = vec![0; len_bytes];
    getrandom(&mut buf)?;
    Ok(buf.into())
}

fn mk_key(words: &[&str], path: &str) -> Result<EvmAddress> {
    let seed = mnemonic::calcseed::to_seed(words)?;
    let root = ExtPrvKey::from_seed(base58::Prefix::XPRV, seed)?;
    let prvkey = root.derive_child(path.parse()?)?;
    let pubkey = prvkey.get_public()?;
    Ok(pubkey.key.into())
}
