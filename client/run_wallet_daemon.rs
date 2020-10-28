extern crate client_lib;
use client_lib::daemon::run_wallet_daemon;

fn main() {
    let _ = run_wallet_daemon(false);
}
