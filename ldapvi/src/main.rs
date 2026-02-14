mod app;
mod arguments;
#[path = "interactive.rs"]
mod interactive;
mod ldap;

fn main() {
    app::run();
}
