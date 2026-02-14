mod app;
mod arguments;
#[path = "noninteractive.rs"]
mod interactive;
mod ldap;

fn main() {
    app::run();
}
