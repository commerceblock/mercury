extern crate client_lib;
use client_lib::daemon::make_wallet_daemon;

fn main() {
    let _ = make_wallet_daemon();
}
