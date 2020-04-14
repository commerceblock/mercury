//! # run
//!
//! State entity main daemon entry

#[macro_use]
extern crate log;
extern crate mercury;
extern crate env_logger;

use std::env;
use std::process;

fn main() {
    // Fetch config which is set from default values in config
    // and any values overriden by the corresponding env variable
    match mercury::config::Config::new() {
        Ok(config) => {
            // To see results set RUST_LOG to one of the following:
            // info, warning, debug, error, coordinator(for all)
            env::set_var("RUST_LOG", &config.log_level);
            env::set_var("RUST_BACKTRACE", "1");
            // Init env logger with value set from config
            env_logger::init();

            // begin listener daemon here
            let _ = mercury::state_entity::run(config);
            // if let Err(e) = mercury::state_entity::run(config) {
            //     error!("daemon failure: {}", e);
            // }
        }
        Err(e) => {
            env::set_var("RUST_LOG", "error");
            env_logger::init();
            error!("config failure: {}", e);
        }
    }
    process::exit(1);
}
