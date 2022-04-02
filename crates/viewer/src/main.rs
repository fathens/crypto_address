mod words;

use bevy::prelude::*;
use bevy_egui::EguiPlugin;

fn main() {
    run();
}

fn run() {
    let mut app = App::new();

    app.add_plugins(DefaultPlugins);
    app.add_plugin(EguiPlugin);

    app.add_startup_system(setup);

    app.add_system(words::ui_example);

    app.run();
}

fn setup(mut commands: Commands, mut windows: ResMut<Windows>) {
    let window = windows.get_primary_mut().unwrap();
    window.set_resolution(800.0, 800.0);
    // light
    commands.spawn_bundle(PointLightBundle {
        transform: Transform::from_translation(Vec3::new(0.0, 0.0, 0.0)),
        ..Default::default()
    });
    commands.spawn_bundle(PointLightBundle {
        transform: Transform::from_translation(Vec3::new(3.0, 4.0, 3.0)),
        ..Default::default()
    });
}
